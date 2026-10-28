import { Router } from "express";
import { randomBytes, createHash } from "node:crypto";
import bcrypt from "bcryptjs";
import { z } from "zod";

import { prisma } from "../lib/prisma.js";
import {
  generateOtp,
  hashOtp,
  verifyOtpHash,
} from "../lib/otp.js";
import {
  createSession,
  requireSession,
  requireUnlockedSession,
} from "../lib/session.js";
import { sendEmailOtp } from "../services/email.service.js";

const router = Router();

const OTP_TTL_MS = 5 * 60 * 1000;
const RESET_TTL_MS = 10 * 60 * 1000;
const RESEND_COOLDOWN_MS = 30 * 1000;
const RATE_WINDOW_MS = 24 * 60 * 60 * 1000;
const MAX_SENDS = 4;
const MAX_ATTEMPTS = 5;
const PIN_LOCK_MS = 15 * 60 * 1000;

const emailSchema = z.string().trim().email().max(254);
const otpSchema = z.string().regex(/^\d{6}$/);
const pinSchema = z.string().regex(/^\d{4,6}$/);
const pinTypeSchema = z.enum(["ENTRY_PIN", "TRANSACTION_PIN"]);

function fail(res, status, code, message, extra = {}) {
  return res.status(status).json({
    error: { code, message, ...extra },
  });
}

function normalizeEmail(value) {
  return value.trim().toLowerCase();
}

function normalizePhone(value) {
  let phone = String(value).replace(/[\s()-]/g, "");

  if (/^\d{10}$/.test(phone)) phone = `+91${phone}`;
  else if (/^91\d{10}$/.test(phone)) phone = `+${phone}`;

  return /^\+[1-9]\d{7,14}$/.test(phone) ? phone : null;
}

function purposeFor(pinType, channel) {
  const purposeMap = {
    ENTRY_PIN: {
      EMAIL: "ENTRY_PIN_RESET_EMAIL",
      PHONE: "ENTRY_PIN_RESET_PHONE",
    },
    TRANSACTION_PIN: {
      EMAIL: "TRANSACTION_PIN_RESET_EMAIL",
      PHONE: "TRANSACTION_PIN_RESET_PHONE",
    },
  };

  const purpose = purposeMap[pinType]?.[channel];

  if (!purpose) {
    throw new Error("Unsupported PIN reset OTP purpose.");
  }

  return purpose;
}

function challengeHash(value) {
  return createHash("sha256").update(value).digest("hex");
}

function pinModel(pinType) {
  return pinType === "ENTRY_PIN" ? "entryPin" : "paymentPin";
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
    take: MAX_SENDS,
  });

  if (recent.length >= MAX_SENDS) {
    const availableAt = new Date(
      recent[MAX_SENDS - 1].createdAt.getTime() + RATE_WINDOW_MS,
    );

    return {
      allowed: false,
      seconds: Math.max(
        1,
        Math.ceil((availableAt.getTime() - now.getTime()) / 1000),
      ),
    };
  }

  const latest = recent[0];

  if (latest) {
    const availableAt = new Date(
      latest.createdAt.getTime() + RESEND_COOLDOWN_MS,
    );

    if (availableAt > now) {
      return {
        allowed: false,
        seconds: Math.ceil((availableAt.getTime() - now.getTime()) / 1000),
      };
    }
  }

  return { allowed: true };
}

async function issueOtp({ user, destination, purpose, channel }) {
  const allowance = await getSendAllowance(destination, purpose);

  if (!allowance.allowed) {
    const error = new Error("Please wait before requesting another code.");
    error.code = "OTP_RATE_LIMIT";
    error.retryAfterSeconds = allowance.seconds;
    throw error;
  }

  const otp = generateOtp();
  const now = new Date();

  await prisma.$transaction([
    prisma.otpVerification.updateMany({
      where: {
        destination,
        purpose,
        consumedAt: null,
      },
      data: { consumedAt: now },
    }),
    prisma.otpVerification.create({
      data: {
        userId: user.id,
        destination,
        purpose,
        codeHash: hashOtp(otp),
        expiresAt: new Date(now.getTime() + OTP_TTL_MS),
      },
    }),
  ]);

  if (channel === "EMAIL") {
    try {
      await sendEmailOtp({
        email: destination,
        otp,
        fullName: user.fullName,
      });
    } catch (error) {
      await prisma.otpVerification.updateMany({
        where: {
          destination,
          purpose,
          codeHash: hashOtp(otp),
          consumedAt: null,
        },
        data: { consumedAt: new Date() },
      });
      throw error;
    }
  } else if (process.env.NODE_ENV !== "production") {
    console.info(
      `[DEV ONLY] U-Pay phone OTP for ${destination}: ${otp}`,
    );
  }
}

async function consumeOtp({ destination, purpose, otp, userId }) {
  const record = await prisma.otpVerification.findFirst({
    where: {
      destination,
      purpose,
      ...(userId ? { userId } : {}),
      consumedAt: null,
    },
    orderBy: { createdAt: "desc" },
  });

  if (!record) return { ok: false, code: "OTP_INVALID" };

  const now = new Date();

  if (record.expiresAt <= now) {
    await prisma.otpVerification.updateMany({
      where: { id: record.id, consumedAt: null },
      data: { consumedAt: now },
    });
    return { ok: false, code: "OTP_EXPIRED" };
  }

  if (record.attempts >= MAX_ATTEMPTS) {
    return { ok: false, code: "OTP_ATTEMPTS_EXCEEDED" };
  }

  if (!verifyOtpHash(otp, record.codeHash)) {
    await prisma.otpVerification.updateMany({
      where: {
        id: record.id,
        consumedAt: null,
        attempts: record.attempts,
      },
      data: { attempts: { increment: 1 } },
    });

    return { ok: false, code: "OTP_INVALID" };
  }

  const consumed = await prisma.otpVerification.updateMany({
    where: {
      id: record.id,
      consumedAt: null,
      attempts: record.attempts,
    },
    data: { consumedAt: now },
  });

  if (consumed.count !== 1) return { ok: false, code: "OTP_INVALID" };

  return { ok: true, record };
}

function otpError(res, result) {
  if (result.code === "OTP_EXPIRED") {
    fail(res, 400, result.code, "This code has expired. Request a new one.");
  } else if (result.code === "OTP_ATTEMPTS_EXCEEDED") {
    fail(res, 429, result.code, "Too many incorrect codes. Request a new one.");
  } else {
    fail(res, 400, "OTP_INVALID", "The verification code is invalid or expired.");
  }
}

function handleRouteError(error, res, next) {
  if (error.code === "OTP_RATE_LIMIT") {
    return fail(
      res,
      429,
      error.code,
      error.message,
      { retryAfterSeconds: error.retryAfterSeconds },
    );
  }

  if (error.code === "EMAIL_CONFIG_MISSING") {
    return fail(
      res,
      503,
      error.code,
      "Email delivery is not configured on the server.",
    );
  }

  if (
    error.code === "EMAIL_DELIVERY_FAILED" ||
    error.name === "TimeoutError"
  ) {
    return fail(
      res,
      502,
      "EMAIL_DELIVERY_FAILED",
      "We could not send the email. Please try again later.",
    );
  }

  return next(error);
}

async function getVerifiedUserByEmail(email) {
  return prisma.user.findUnique({
    where: { email },
    select: {
      id: true,
      fullName: true,
      email: true,
      phoneNumber: true,
      status: true,
      emailVerified: true,
      phoneVerified: true,
    },
  });
}

async function setPin(userId, pinType, pin) {
  const model = pinModel(pinType);
  const pinHash = await bcrypt.hash(pin, 12);

  try {
    // Initial setup must never overwrite an existing PIN.
    // The unique userId constraint also prevents concurrent setup races.
    await prisma[model].create({
      data: { userId, pinHash },
    });
  } catch (error) {
    if (error?.code === "P2002") {
      const conflict = new Error(
        `${pinType === "ENTRY_PIN" ? "Entry" : "Transaction"} PIN is already set. Use the PIN recovery flow to reset it.`,
      );
      conflict.code = "PIN_ALREADY_SET";
      throw conflict;
    }

    throw error;
  }

  const [entryPin, paymentPin] = await Promise.all([
    prisma.entryPin.findUnique({ where: { userId }, select: { id: true } }),
    prisma.paymentPin.findUnique({ where: { userId }, select: { id: true } }),
  ]);

  return Boolean(entryPin && paymentPin);
}

async function verifyPinRecord(userId, pinType, pin) {
  const model = pinModel(pinType);
  const record = await prisma[model].findUnique({ where: { userId } });

  if (!record) return { ok: false, code: "PIN_NOT_SET" };

  const now = new Date();

  if (record.lockedUntil && record.lockedUntil > now) {
    return {
      ok: false,
      code: "PIN_LOCKED",
      retryAfterSeconds: Math.ceil((record.lockedUntil.getTime() - now.getTime()) / 1000),
    };
  }

  if (record.lockedUntil && record.lockedUntil <= now) {
    await prisma[model].update({
      where: { userId },
      data: { failedAttempts: 0, lockedUntil: null },
    });
  }

  const matches = await bcrypt.compare(pin, record.pinHash);

  if (!matches) {
    const attempts = (record.lockedUntil ? 0 : record.failedAttempts) + 1;
    const lockedUntil = attempts >= MAX_ATTEMPTS
      ? new Date(now.getTime() + PIN_LOCK_MS)
      : null;

    const updated = await prisma[model].updateMany({
      where: {
        userId,
        failedAttempts: record.failedAttempts,
        lockedUntil: record.lockedUntil,
      },
      data: {
        failedAttempts: attempts,
        lockedUntil,
      },
    });

    // A concurrent PIN attempt changed the record first.
    // Do not report a successful lockout-counter update if this write lost the race.
    if (updated.count !== 1) {
      const latest = await prisma[model].findUnique({
        where: { userId },
        select: { failedAttempts: true, lockedUntil: true },
      });

      if (latest?.lockedUntil && latest.lockedUntil > new Date()) {
        return {
          ok: false,
          code: "PIN_LOCKED",
          retryAfterSeconds: Math.ceil(
            (latest.lockedUntil.getTime() - Date.now()) / 1000,
          ),
        };
      }

      return { ok: false, code: "PIN_INVALID" };
    }

    return {
      ok: false,
      code: lockedUntil ? "PIN_LOCKED" : "PIN_INVALID",
      ...(lockedUntil ? { retryAfterSeconds: PIN_LOCK_MS / 1000 } : {}),
    };
  }

  await prisma[model].update({
    where: { userId },
    data: { failedAttempts: 0, lockedUntil: null },
  });

  return { ok: true };
}

/*
 * Login starts with email OTP. The session is not considered unlocked
 * until the Entry PIN is verified.
 */
router.post("/login-email-otp", async (req, res, next) => {
  try {
    const parsed = z.object({ email: emailSchema }).safeParse(req.body);

    if (!parsed.success) {
      return fail(res, 400, "VALIDATION_ERROR", "Enter a valid email address.");
    }

    const email = normalizeEmail(parsed.data.email);
    const user = await getVerifiedUserByEmail(email);

    if (
      !user ||
      user.status !== "ACTIVE" ||
      !user.emailVerified ||
      !user.phoneVerified
    ) {
      return fail(
        res,
        400,
        "LOGIN_NOT_AVAILABLE",
        "No active, verified U-Pay account was found for these details.",
      );
    }

    await issueOtp({
      user,
      destination: email,
      purpose: "LOGIN",
      channel: "EMAIL",
    });

    return res.status(202).json({
      message: "Login verification code sent.",
      expiresInSeconds: OTP_TTL_MS / 1000,
      resendAfterSeconds: RESEND_COOLDOWN_MS / 1000,
      nextStep: "VERIFY_LOGIN_OTP",
    });
  } catch (error) {
    return handleRouteError(error, res, next);
  }
});

router.post("/verify-login-otp", async (req, res, next) => {
  try {
    const parsed = z.object({
      email: emailSchema,
      otp: otpSchema,
    }).safeParse(req.body);

    if (!parsed.success) {
      return fail(res, 400, "VALIDATION_ERROR", "Enter your email and six-digit code.");
    }

    const email = normalizeEmail(parsed.data.email);
    const user = await getVerifiedUserByEmail(email);

    if (
      !user ||
      user.status !== "ACTIVE" ||
      !user.emailVerified ||
      !user.phoneVerified
    ) {
      return fail(res, 400, "LOGIN_NOT_AVAILABLE", "Login could not be completed.");
    }

    const result = await consumeOtp({
      destination: email,
      purpose: "LOGIN",
      otp: parsed.data.otp,
      userId: user.id,
    });

    if (!result.ok) return otpError(res, result);

    const created = await createSession(user.id, req);

    const [entryPin, paymentPin] = await Promise.all([
      prisma.entryPin.findUnique({ where: { userId: user.id }, select: { id: true } }),
      prisma.paymentPin.findUnique({ where: { userId: user.id }, select: { id: true } }),
    ]);

    return res.status(200).json({
      message: "Email verified.",
      sessionToken: created.token,
      expiresAt: created.expiresAt,
      user: {
        id: user.id,
        fullName: user.fullName,
        email: user.email,
        phoneNumber: user.phoneNumber,
      },
      nextStep: entryPin && paymentPin ? "ENTRY_PIN" : "SETUP_PINS",
      pinSetup: {
        entryPinSet: Boolean(entryPin),
        transactionPinSet: Boolean(paymentPin),
      },
    });
  } catch (error) {
    if (error.code === "PIN_ALREADY_SET") {
      return fail(res, 409, error.code, error.message);
    }
    return next(error);
  }
});

/*
 * Initial PIN setup is allowed only with a valid session created by
 * the completed registration flow or email-OTP login.
 */
router.post("/entry-pin", requireSession, async (req, res, next) => {
  try {
    const parsed = z.object({ pin: pinSchema }).safeParse(req.body);

    if (!parsed.success) {
      return fail(res, 400, "VALIDATION_ERROR", "Entry PIN must contain 4–6 digits.");
    }

    const bothSet = await setPin(req.auth.user.id, "ENTRY_PIN", parsed.data.pin);

    if (bothSet) {
      await prisma.session.update({
        where: { id: req.auth.sessionId },
        data: { entryPinVerifiedAt: new Date() },
      });
    }

    return res.status(200).json({
      message: "Entry PIN saved.",
      nextStep: bothSet ? "DASHBOARD" : "SET_TRANSACTION_PIN",
    });
  } catch (error) {
    if (error.code === "PIN_ALREADY_SET") {
      return fail(res, 409, error.code, error.message);
    }
    return next(error);
  }
});

router.post("/entry-pin/verify", requireSession, async (req, res, next) => {
  try {
    const parsed = z.object({ pin: pinSchema }).safeParse(req.body);

    if (!parsed.success) {
      return fail(res, 400, "VALIDATION_ERROR", "Enter a valid Entry PIN.");
    }

    const [entryPin, paymentPin] = await Promise.all([
      prisma.entryPin.findUnique({ where: { userId: req.auth.user.id } }),
      prisma.paymentPin.findUnique({ where: { userId: req.auth.user.id } }),
    ]);

    if (!entryPin || !paymentPin) {
      return fail(
        res,
        409,
        "PIN_SETUP_REQUIRED",
        "Set up both PINs before unlocking U-Pay.",
      );
    }

    const result = await verifyPinRecord(
      req.auth.user.id,
      "ENTRY_PIN",
      parsed.data.pin,
    );

    if (!result.ok) {
      return fail(
        res,
        result.code === "PIN_LOCKED" ? 423 : 401,
        result.code,
        result.code === "PIN_LOCKED"
          ? "Entry PIN is temporarily locked."
          : "Incorrect Entry PIN.",
        result.retryAfterSeconds
          ? { retryAfterSeconds: result.retryAfterSeconds }
          : {},
      );
    }

    await prisma.session.update({
      where: { id: req.auth.sessionId },
      data: { entryPinVerifiedAt: new Date() },
    });

    return res.status(200).json({
      message: "U-Pay unlocked.",
      nextStep: "DASHBOARD",
    });
  } catch (error) {
    return next(error);
  }
});

router.post("/transaction-pin", requireSession, async (req, res, next) => {
  try {
    const parsed = z.object({ pin: pinSchema }).safeParse(req.body);

    if (!parsed.success) {
      return fail(res, 400, "VALIDATION_ERROR", "Transaction PIN must contain 4–6 digits.");
    }

    const bothSet = await setPin(
      req.auth.user.id,
      "TRANSACTION_PIN",
      parsed.data.pin,
    );

    if (bothSet) {
      await prisma.session.update({
        where: { id: req.auth.sessionId },
        data: { entryPinVerifiedAt: new Date() },
      });
    }

    return res.status(200).json({
      message: "Transaction PIN saved.",
      nextStep: bothSet ? "DASHBOARD" : "SET_ENTRY_PIN",
    });
  } catch (error) {
    if (error.code === "PIN_ALREADY_SET") {
      return fail(res, 409, error.code, error.message);
    }
    return next(error);
  }
});

router.post(
  "/transaction-pin/verify",
  requireSession,
  requireUnlockedSession,
  async (req, res, next) => {
    try {
      const parsed = z.object({ pin: pinSchema }).safeParse(req.body);

      if (!parsed.success) {
        return fail(res, 400, "VALIDATION_ERROR", "Enter a valid Transaction PIN.");
      }

      const result = await verifyPinRecord(
        req.auth.user.id,
        "TRANSACTION_PIN",
        parsed.data.pin,
      );

      if (!result.ok) {
        return fail(
          res,
          result.code === "PIN_LOCKED" ? 423 : 401,
          result.code,
          result.code === "PIN_LOCKED"
            ? "Transaction PIN is temporarily locked."
            : "Incorrect Transaction PIN.",
          result.retryAfterSeconds
            ? { retryAfterSeconds: result.retryAfterSeconds }
            : {},
        );
      }

      return res.status(200).json({
        message: "Transaction PIN verified.",
        authorized: true,
      });
    } catch (error) {
      return next(error);
    }
  },
);

/*
 * Recovery: email OTP -> one-time reset challenge -> OTP sent only to
 * the phone already registered to this account.
 */
router.post("/pin-reset/email", async (req, res, next) => {
  try {
    const parsed = z.object({
      email: emailSchema,
      pinType: pinTypeSchema,
    }).safeParse(req.body);

    if (!parsed.success) {
      return fail(res, 400, "VALIDATION_ERROR", "Enter your email and select a PIN type.");
    }

    const email = normalizeEmail(parsed.data.email);
    const user = await getVerifiedUserByEmail(email);

    if (
      !user ||
      user.status !== "ACTIVE" ||
      !user.emailVerified ||
      !user.phoneVerified
    ) {
      return fail(
        res,
        400,
        "EMAIL_NOT_ELIGIBLE",
        "This email does not match an active U-Pay account with verified email and mobile. Check your registered email and try again."
      );
    }

    await issueOtp({
      user,
      destination: email,
      purpose: purposeFor(parsed.data.pinType, "EMAIL"),
      channel: "EMAIL",
    });

    return res.status(200).json({
      message: "If email delivery is configured, a verification code has been requested.",
      expiresInSeconds: OTP_TTL_MS / 1000,
      resendAfterSeconds: RESEND_COOLDOWN_MS / 1000,
      nextStep: "VERIFY_RESET_EMAIL_OTP",
    });
  } catch (error) {
    return handleRouteError(error, res, next);
  }
});

router.post("/pin-reset/email/verify", async (req, res, next) => {
  try {
    const parsed = z.object({
      email: emailSchema,
      pinType: pinTypeSchema,
      otp: otpSchema,
    }).safeParse(req.body);

    if (!parsed.success) {
      return fail(res, 400, "VALIDATION_ERROR", "Enter your email and six-digit code.");
    }

    const email = normalizeEmail(parsed.data.email);
    const user = await getVerifiedUserByEmail(email);

    if (
      !user ||
      user.status !== "ACTIVE" ||
      !user.emailVerified ||
      !user.phoneVerified
    ) {
      return fail(res, 400, "OTP_INVALID", "The verification code is invalid or expired.");
    }

    const result = await consumeOtp({
      destination: email,
      purpose: purposeFor(parsed.data.pinType, "EMAIL"),
      otp: parsed.data.otp,
      userId: user.id,
    });

    if (!result.ok) return otpError(res, result);

    const rawChallenge = randomBytes(32).toString("base64url");
    const challenge = await prisma.pinResetChallenge.create({
      data: {
        userId: user.id,
        pinType: parsed.data.pinType,
        tokenHash: challengeHash(rawChallenge),
        expiresAt: new Date(Date.now() + RESET_TTL_MS),
      },
    });

    try {
      await issueOtp({
        user,
        destination: normalizePhone(user.phoneNumber),
        purpose: purposeFor(parsed.data.pinType, "PHONE"),
        channel: "PHONE",
      });
    } catch (error) {
      await prisma.pinResetChallenge.update({
        where: { id: challenge.id },
        data: { consumedAt: new Date() },
      });
      throw error;
    }

    return res.status(200).json({
      message: "A verification code was sent to your registered mobile number.",
      resetToken: rawChallenge,
      expiresInSeconds: RESET_TTL_MS / 1000,
      nextStep: "VERIFY_RESET_PHONE_OTP",
    });
  } catch (error) {
    return handleRouteError(error, res, next);
  }
});

router.post("/pin-reset/phone/verify", async (req, res, next) => {
  try {
    const parsed = z.object({
      resetToken: z.string().min(32).max(200),
      otp: otpSchema,
      newPin: pinSchema,
    }).safeParse(req.body);

    if (!parsed.success) {
      return fail(
        res,
        400,
        "VALIDATION_ERROR",
        "Enter the mobile verification code and a new 4–6 digit PIN.",
      );
    }

    const challenge = await prisma.pinResetChallenge.findUnique({
      where: { tokenHash: challengeHash(parsed.data.resetToken) },
      include: {
        user: {
          select: {
            id: true,
            phoneNumber: true,
            status: true,
            phoneVerified: true,
            emailVerified: true,
          },
        },
      },
    });

    if (
      !challenge ||
      challenge.consumedAt ||
      challenge.expiresAt <= new Date() ||
      challenge.user.status !== "ACTIVE" ||
      !challenge.user.emailVerified ||
      !challenge.user.phoneVerified
    ) {
      return fail(res, 400, "RESET_CHALLENGE_INVALID", "Restart PIN recovery and try again.");
    }

    const phoneNumber = normalizePhone(challenge.user.phoneNumber);

    const result = await consumeOtp({
      destination: phoneNumber,
      purpose: purposeFor(challenge.pinType, "PHONE"),
      otp: parsed.data.otp,
      userId: challenge.userId,
    });

    if (!result.ok) return otpError(res, result);

    const newHash = await bcrypt.hash(parsed.data.newPin, 12);
    const model = pinModel(challenge.pinType);
    const now = new Date();

    await prisma.$transaction(async (tx) => {
      const consumed = await tx.pinResetChallenge.updateMany({
        where: {
          id: challenge.id,
          consumedAt: null,
          expiresAt: { gt: now },
        },
        data: { consumedAt: now },
      });

      if (consumed.count !== 1) {
        const error = new Error("Reset challenge has already been used.");
        error.code = "RESET_CHALLENGE_INVALID";
        throw error;
      }

      await tx[model].upsert({
        where: { userId: challenge.userId },
        create: {
          userId: challenge.userId,
          pinHash: newHash,
        },
        update: {
          pinHash: newHash,
          failedAttempts: 0,
          lockedUntil: null,
        },
      });

      // Revoke existing sessions after credential recovery.
      await tx.session.updateMany({
        where: {
          userId: challenge.userId,
          revokedAt: null,
        },
        data: { revokedAt: now },
      });

      await tx.pinResetChallenge.updateMany({
        where: {
          userId: challenge.userId,
          consumedAt: null,
        },
        data: { consumedAt: now },
      });
    });

    return res.status(200).json({
      message: "PIN reset successfully. Sign in again to continue.",
      nextStep: "LOGIN",
    });
  } catch (error) {
    if (error.code === "RESET_CHALLENGE_INVALID") {
      return fail(res, 400, error.code, "Restart PIN recovery and try again.");
    }

    return next(error);
  }
});

/*
 * Explicitly lock the current session on app exit/logout.
 */
router.post("/logout", requireSession, async (req, res, next) => {
  try {
    await prisma.session.update({
      where: { id: req.auth.sessionId },
      data: { revokedAt: new Date() },
    });

    return res.status(200).json({ message: "Signed out." });
  } catch (error) {
    return next(error);
  }
});

export default router;
