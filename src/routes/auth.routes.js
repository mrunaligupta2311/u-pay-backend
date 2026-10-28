import { Router } from "express";
import { z } from "zod";
import { prisma } from "../lib/prisma.js";
import {
  generateOtp,
  hashOtp,
  verifyOtpHash,
} from "../lib/otp.js";
import { sendEmailOtp } from "../services/email.service.js";
import { createSession } from "../lib/session.js";

const router = Router();

const OTP_TTL_MS = 5 * 60 * 1000;
const RESEND_COOLDOWN_MS = 30 * 1000;
const RATE_WINDOW_MS = 24 * 60 * 60 * 1000;
const MAX_SENDS_PER_WINDOW = 4;
const MAX_OTP_ATTEMPTS = 5;

const registerSchema = z.object({
  fullName: z.string().trim().min(2).max(80),
  email: z.string().trim().email().max(254),
  phoneNumber: z.string().trim().min(10).max(20),
});

const verifySchema = registerSchema.extend({
  otp: z.string().regex(/^\d{6}$/),
});

const phoneOtpSchema = z.object({
  email: z.string().trim().email().max(254),
  phoneNumber: z.string().trim().min(10).max(20),
  otp: z.string().regex(/^\d{6}$/),
});

const resendEmailSchema = z.object({
  email: z.string().trim().email().max(254),
});

const resendPhoneSchema = z.object({
  email: z.string().trim().email().max(254),
  phoneNumber: z.string().trim().min(10).max(20),
});

function normalizePhone(input) {
  let phone = input.replace(/[\s()-]/g, "");

  if (/^\d{10}$/.test(phone)) {
    phone = `+91${phone}`;
  } else if (/^91\d{10}$/.test(phone)) {
    phone = `+${phone}`;
  }

  return /^\+[1-9]\d{7,14}$/.test(phone) ? phone : null;
}

function invalidBody(res, details) {
  return res.status(400).json({
    error: {
      code: "VALIDATION_ERROR",
      message: "Please check the submitted details.",
      details,
    },
  });
}

function sendError(res, status, code, message, retryAfterSeconds) {
  return res.status(status).json({
    error: {
      code,
      message,
      ...(retryAfterSeconds !== undefined
        ? { retryAfterSeconds }
        : {}),
    },
  });
}

function secondsUntil(date) {
  return Math.max(1, Math.ceil((date.getTime() - Date.now()) / 1000));
}

async function getSendAllowance(destination, purpose) {
  const now = new Date();
  const since = new Date(now.getTime() - RATE_WINDOW_MS);

  const recent = await prisma.otpVerification.findMany({
    where: {
      destination,
      purpose,
      createdAt: { gte: since },
    },
    orderBy: { createdAt: "desc" },
    select: { createdAt: true },
  });

  if (recent.length >= MAX_SENDS_PER_WINDOW) {
    const oldestAllowedWindowRecord = recent[recent.length - 1];
    const availableAt = new Date(
      oldestAllowedWindowRecord.createdAt.getTime() + RATE_WINDOW_MS,
    );

    return {
      allowed: false,
      code: "OTP_RATE_LIMIT",
      retryAfterSeconds: secondsUntil(availableAt),
    };
  }

  if (recent.length > 0) {
    const cooldownEndsAt = new Date(
      recent[0].createdAt.getTime() + RESEND_COOLDOWN_MS,
    );

    if (now < cooldownEndsAt) {
      return {
        allowed: false,
        code: "OTP_COOLDOWN",
        retryAfterSeconds: secondsUntil(cooldownEndsAt),
      };
    }
  }

  return { allowed: true };
}

async function enforceSendAllowance(destination, purpose) {
  const allowance = await getSendAllowance(destination, purpose);

  if (!allowance.allowed) {
    const error = new Error("OTP request limit reached.");
    error.code = allowance.code;
    error.retryAfterSeconds = allowance.retryAfterSeconds;
    throw error;
  }
}

function handleRateError(error, res) {
  if (error.code === "OTP_RATE_LIMIT") {
    return sendError(
      res,
      429,
      error.code,
      "Daily OTP request limit reached. Please try again when the 24-hour window resets.",
      error.retryAfterSeconds,
    );
  }

  if (error.code === "OTP_COOLDOWN") {
    return sendError(
      res,
      429,
      error.code,
      "Please wait before requesting another OTP.",
      error.retryAfterSeconds,
    );
  }

  return null;
}

async function issueEmailOtp({ email, fullName }) {
  await enforceSendAllowance(email, "SIGNUP");

  const otp = generateOtp();
  const now = new Date();

  await prisma.otpVerification.updateMany({
    where: {
      destination: email,
      purpose: "SIGNUP",
      consumedAt: null,
    },
    data: { consumedAt: now },
  });

  const record = await prisma.otpVerification.create({
    data: {
      destination: email,
      purpose: "SIGNUP",
      codeHash: hashOtp(otp),
      expiresAt: new Date(now.getTime() + OTP_TTL_MS),
    },
  });

  try {
    await sendEmailOtp({ email, otp, fullName });
  } catch (error) {
    await prisma.otpVerification.deleteMany({
      where: { id: record.id, consumedAt: null },
    });

    throw error;
  }
}

function logDevelopmentPhoneOtp(phoneNumber, otp) {
  if (process.env.NODE_ENV !== "production") {
    console.info(
      `[DEV ONLY] U-Pay mobile OTP for ${phoneNumber}: ${otp}`,
    );
  }
}

async function issuePhoneOtp(userId, phoneNumber) {
  await enforceSendAllowance(phoneNumber, "PHONE_VERIFICATION");

  const otp = generateOtp();
  const now = new Date();

  await prisma.otpVerification.updateMany({
    where: {
      destination: phoneNumber,
      purpose: "PHONE_VERIFICATION",
      consumedAt: null,
    },
    data: { consumedAt: now },
  });

  await prisma.otpVerification.create({
    data: {
      userId,
      destination: phoneNumber,
      purpose: "PHONE_VERIFICATION",
      codeHash: hashOtp(otp),
      expiresAt: new Date(now.getTime() + OTP_TTL_MS),
    },
  });

  // No SMS provider is configured. Never return this OTP from the API.
  logDevelopmentPhoneOtp(phoneNumber, otp);
}

async function validateOtpRecord(res, record, otp) {
  if (!record || record.consumedAt) {
    sendError(
      res,
      400,
      "OTP_INVALID",
      "The code is invalid. Request a new verification code.",
    );
    return false;
  }

  if (record.expiresAt <= new Date()) {
    sendError(
      res,
      400,
      "OTP_EXPIRED",
      "The code has expired. Request a new verification code.",
    );
    return false;
  }

  if (record.attempts >= MAX_OTP_ATTEMPTS) {
    await prisma.otpVerification.updateMany({
      where: { id: record.id, consumedAt: null },
      data: { consumedAt: new Date() },
    });

    sendError(
      res,
      429,
      "OTP_ATTEMPTS_EXCEEDED",
      "Too many incorrect attempts. Request a new verification code.",
    );
    return false;
  }

  if (!verifyOtpHash(otp, record.codeHash)) {
    const nextAttempts = record.attempts + 1;

    await prisma.otpVerification.updateMany({
      where: {
        id: record.id,
        consumedAt: null,
        attempts: record.attempts,
      },
      data: {
        attempts: { increment: 1 },
        ...(nextAttempts >= MAX_OTP_ATTEMPTS
          ? { consumedAt: new Date() }
          : {}),
      },
    });

    sendError(
      res,
      nextAttempts >= MAX_OTP_ATTEMPTS ? 429 : 400,
      nextAttempts >= MAX_OTP_ATTEMPTS
        ? "OTP_ATTEMPTS_EXCEEDED"
        : "OTP_INVALID",
      nextAttempts >= MAX_OTP_ATTEMPTS
        ? "Too many incorrect attempts. Request a new verification code."
        : `Incorrect verification code. ${MAX_OTP_ATTEMPTS - nextAttempts} attempt(s) remaining.`,
    );

    return false;
  }

  return true;
}

router.post("/register", async (req, res, next) => {
  try {
    const parsed = registerSchema.safeParse(req.body);

    if (!parsed.success) {
      return invalidBody(
        res,
        parsed.error.issues.map((issue) => ({
          field: issue.path.join("."),
          message: issue.message,
        })),
      );
    }

    const fullName = parsed.data.fullName;
    const email = parsed.data.email.toLowerCase();
    const phoneNumber = normalizePhone(parsed.data.phoneNumber);

    if (!phoneNumber) {
      return invalidBody(res, [{
        field: "phoneNumber",
        message: "Enter a valid 10-digit Indian mobile number.",
      }]);
    }

    const existing = await prisma.user.findFirst({
      where: {
        OR: [{ email }, { phoneNumber }],
      },
      select: { id: true },
    });

    if (existing) {
      return sendError(
        res,
        409,
        "ACCOUNT_ALREADY_EXISTS",
        "An account already exists with this email or mobile number.",
      );
    }

    await issueEmailOtp({ email, fullName });

    return res.status(202).json({
      message: "Verification email sent if delivery is available.",
      email,
      expiresInSeconds: OTP_TTL_MS / 1000,
      resendAfterSeconds: RESEND_COOLDOWN_MS / 1000,
      nextStep: "VERIFY_EMAIL",
    });
  } catch (error) {
    const rateResponse = handleRateError(error, res);
    if (rateResponse) return rateResponse;

    if (error.code === "EMAIL_CONFIG_MISSING") {
      return sendError(
        res,
        503,
        "EMAIL_NOT_CONFIGURED",
        "Email verification is not configured on the server.",
      );
    }

    if (
      error.code === "EMAIL_DELIVERY_FAILED" ||
      error.name === "TimeoutError"
    ) {
      return sendError(
        res,
        502,
        "EMAIL_DELIVERY_FAILED",
        "We could not send the verification email. Please try again.",
      );
    }

    return next(error);
  }
});

router.post("/resend-email-otp", async (req, res, next) => {
  try {
    const parsed = resendEmailSchema.safeParse(req.body);

    if (!parsed.success) {
      return invalidBody(
        res,
        parsed.error.issues.map((issue) => ({
          field: issue.path.join("."),
          message: issue.message,
        })),
      );
    }

    const email = parsed.data.email.toLowerCase();

    const latest = await prisma.otpVerification.findFirst({
      where: {
        destination: email,
        purpose: "SIGNUP",
      },
      orderBy: { createdAt: "desc" },
    });

    if (!latest || latest.consumedAt) {
      return sendError(
        res,
        400,
        "REGISTRATION_NOT_PENDING",
        "Restart registration to request an email verification code.",
      );
    }

    const user = await prisma.user.findUnique({
      where: { email },
      select: { id: true },
    });

    if (user) {
      return sendError(
        res,
        400,
        "REGISTRATION_NOT_PENDING",
        "Email verification has already been completed.",
      );
    }

    await issueEmailOtp({ email, fullName: "there" });

    return res.status(202).json({
      message: "A new email verification code has been requested.",
      expiresInSeconds: OTP_TTL_MS / 1000,
      resendAfterSeconds: RESEND_COOLDOWN_MS / 1000,
    });
  } catch (error) {
    const rateResponse = handleRateError(error, res);
    if (rateResponse) return rateResponse;

    if (error.code === "EMAIL_CONFIG_MISSING") {
      return sendError(
        res,
        503,
        "EMAIL_NOT_CONFIGURED",
        "Email verification is not configured on the server.",
      );
    }

    if (
      error.code === "EMAIL_DELIVERY_FAILED" ||
      error.name === "TimeoutError"
    ) {
      return sendError(
        res,
        502,
        "EMAIL_DELIVERY_FAILED",
        "We could not send the verification email. Please try again.",
      );
    }

    return next(error);
  }
});

router.post("/verify-email", async (req, res, next) => {
  try {
    const parsed = verifySchema.safeParse(req.body);

    if (!parsed.success) {
      return invalidBody(
        res,
        parsed.error.issues.map((issue) => ({
          field: issue.path.join("."),
          message: issue.message,
        })),
      );
    }

    const fullName = parsed.data.fullName;
    const email = parsed.data.email.toLowerCase();
    const phoneNumber = normalizePhone(parsed.data.phoneNumber);
    const { otp } = parsed.data;

    if (!phoneNumber) {
      return invalidBody(res, [{
        field: "phoneNumber",
        message: "Enter a valid phone number.",
      }]);
    }

    const otpRecord = await prisma.otpVerification.findFirst({
      where: {
        destination: email,
        purpose: "SIGNUP",
        consumedAt: null,
      },
      orderBy: { createdAt: "desc" },
    });

    if (!(await validateOtpRecord(res, otpRecord, otp))) return;

    const existing = await prisma.user.findFirst({
      where: {
        OR: [{ email }, { phoneNumber }],
      },
      select: { id: true },
    });

    if (existing) {
      return sendError(
        res,
        409,
        "ACCOUNT_ALREADY_EXISTS",
        "An account already exists with this email or mobile number.",
      );
    }

    // Check mobile limits before consuming the email OTP.
    await enforceSendAllowance(phoneNumber, "PHONE_VERIFICATION");

    const phoneOtp = generateOtp();
    const now = new Date();

    const user = await prisma.$transaction(async (tx) => {
      await tx.otpVerification.update({
        where: { id: otpRecord.id },
        data: { consumedAt: now },
      });

      const createdUser = await tx.user.create({
        data: {
          fullName,
          email,
          phoneNumber,
          emailVerified: true,
          phoneVerified: false,
        },
        select: {
          id: true,
          fullName: true,
          email: true,
          phoneNumber: true,
          emailVerified: true,
          phoneVerified: true,
        },
      });

      await tx.wallet.create({
        data: { userId: createdUser.id },
      });

      await tx.otpVerification.updateMany({
        where: {
          destination: phoneNumber,
          purpose: "PHONE_VERIFICATION",
          consumedAt: null,
        },
        data: { consumedAt: now },
      });

      await tx.otpVerification.create({
        data: {
          userId: createdUser.id,
          destination: phoneNumber,
          purpose: "PHONE_VERIFICATION",
          codeHash: hashOtp(phoneOtp),
          expiresAt: new Date(now.getTime() + OTP_TTL_MS),
        },
      });

      return createdUser;
    });

    logDevelopmentPhoneOtp(phoneNumber, phoneOtp);

    return res.status(200).json({
      message: "Email verified. Verify your mobile number to finish registration.",
      nextStep: "VERIFY_PHONE",
      expiresInSeconds: OTP_TTL_MS / 1000,
      resendAfterSeconds: RESEND_COOLDOWN_MS / 1000,
      verification: {
        emailVerified: true,
        phoneVerified: false,
      },
      // Do not return an authenticated session or OTP at this stage.
      pendingUserId: user.id,
    });
  } catch (error) {
    const rateResponse = handleRateError(error, res);
    if (rateResponse) return rateResponse;

    if (error.code === "ACCOUNT_ALREADY_EXISTS" || error.code === "P2002") {
      return sendError(
        res,
        409,
        "ACCOUNT_ALREADY_EXISTS",
        "An account already exists with this email or mobile number.",
      );
    }

    return next(error);
  }
});

router.post("/resend-phone-otp", async (req, res, next) => {
  try {
    const parsed = resendPhoneSchema.safeParse(req.body);

    if (!parsed.success) {
      return invalidBody(
        res,
        parsed.error.issues.map((issue) => ({
          field: issue.path.join("."),
          message: issue.message,
        })),
      );
    }

    const email = parsed.data.email.toLowerCase();
    const phoneNumber = normalizePhone(parsed.data.phoneNumber);

    if (!phoneNumber) {
      return invalidBody(res, [{
        field: "phoneNumber",
        message: "Enter a valid phone number.",
      }]);
    }

    const user = await prisma.user.findFirst({
      where: {
        email,
        phoneNumber,
        emailVerified: true,
        phoneVerified: false,
      },
      select: { id: true },
    });

    if (!user) {
      return sendError(
        res,
        400,
        "PHONE_VERIFICATION_NOT_PENDING",
        "No pending mobile verification was found.",
      );
    }

    await issuePhoneOtp(user.id, phoneNumber);

    return res.status(202).json({
      message: "A new mobile verification code has been generated.",
      expiresInSeconds: OTP_TTL_MS / 1000,
      resendAfterSeconds: RESEND_COOLDOWN_MS / 1000,
    });
  } catch (error) {
    const rateResponse = handleRateError(error, res);
    if (rateResponse) return rateResponse;
    return next(error);
  }
});

router.post("/verify-phone", async (req, res, next) => {
  try {
    const parsed = phoneOtpSchema.safeParse(req.body);

    if (!parsed.success) {
      return invalidBody(
        res,
        parsed.error.issues.map((issue) => ({
          field: issue.path.join("."),
          message: issue.message,
        })),
      );
    }

    const email = parsed.data.email.toLowerCase();
    const phoneNumber = normalizePhone(parsed.data.phoneNumber);
    const { otp } = parsed.data;

    if (!phoneNumber) {
      return invalidBody(res, [{
        field: "phoneNumber",
        message: "Enter a valid phone number.",
      }]);
    }

    const user = await prisma.user.findFirst({
      where: {
        email,
        phoneNumber,
        emailVerified: true,
        phoneVerified: false,
      },
      select: { id: true },
    });

    if (!user) {
      return sendError(
        res,
        400,
        "PHONE_VERIFICATION_NOT_PENDING",
        "No pending mobile verification was found.",
      );
    }

    const otpRecord = await prisma.otpVerification.findFirst({
      where: {
        userId: user.id,
        destination: phoneNumber,
        purpose: "PHONE_VERIFICATION",
        consumedAt: null,
      },
      orderBy: { createdAt: "desc" },
    });

    if (!(await validateOtpRecord(res, otpRecord, otp))) return;

    const now = new Date();

    const verifiedUser = await prisma.$transaction(async (tx) => {
      const consumed = await tx.otpVerification.updateMany({
        where: {
          id: otpRecord.id,
          consumedAt: null,
          attempts: otpRecord.attempts,
        },
        data: { consumedAt: now },
      });

      if (consumed.count !== 1) {
        const error = new Error("This OTP has already been used.");
        error.code = "OTP_INVALID";
        throw error;
      }

      return tx.user.update({
        where: { id: user.id },
        data: { phoneVerified: true },
        select: {
          id: true,
          fullName: true,
          email: true,
          phoneNumber: true,
          emailVerified: true,
          phoneVerified: true,
        },
      });
    });

    const registrationSession = await createSession(verifiedUser.id, req);

    return res.status(200).json({
      message: "Email and mobile verified. Registration is complete.",
      nextStep: "SETUP_PINS",
      sessionToken: registrationSession.token,
      expiresAt: registrationSession.expiresAt,
      user: {
        id: verifiedUser.id,
        fullName: verifiedUser.fullName,
        email: verifiedUser.email,
        phoneNumber: verifiedUser.phoneNumber,
      },
      verification: {
        emailVerified: verifiedUser.emailVerified,
        phoneVerified: verifiedUser.phoneVerified,
      },
    });
  } catch (error) {
    if (error.code === "OTP_INVALID") {
      return sendError(
        res,
        400,
        "OTP_INVALID",
        "This code is invalid or has already been used.",
      );
    }

    return next(error);
  }
});

export default router;
