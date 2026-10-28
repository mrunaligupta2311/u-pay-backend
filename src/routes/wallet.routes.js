import { Router } from "express";
import bcrypt from "bcryptjs";
import { z } from "zod";

import { prisma } from "../lib/prisma.js";
import {
  requireSession,
  requireUnlockedSession,
} from "../lib/session.js";

const router = Router();

const MAX_AMOUNT = 1000000;
const MAX_DEMO_FUNDS = 100000;

const paymentSchema = z.object({
  recipientName: z.string().trim().min(1).max(100),
  recipientUpiId: z.string().trim().max(150).optional(),
  amount: z.union([z.string(), z.number()]),
  note: z.string().trim().max(200).optional(),
  pin: z.string().regex(/^\d{4,6}$/),
  idempotencyKey: z.string().min(8).max(100).optional(),
});

const demoFundsSchema = z.object({
  amount: z.union([z.string(), z.number()]),
});

function fail(res, status, code, message, extra = {}) {
  return res.status(status).json({
    error: { code, message, ...extra },
  });
}

function parseAmount(value, max = MAX_AMOUNT) {
  if (
    typeof value !== "string" &&
    typeof value !== "number"
  ) {
    return null;
  }

  const raw = String(value).trim();

  if (!/^\d{1,9}(\.\d{1,2})?$/.test(raw)) {
    return null;
  }

  const amount = Number(raw);

  if (
    !Number.isFinite(amount) ||
    amount <= 0 ||
    amount > max
  ) {
    return null;
  }

  return amount.toFixed(2);
}

function money(value) {
  return Number(value.toString());
}

function publicTransaction(transaction, userId) {
  const sent = transaction.senderId === userId;

  return {
    id: transaction.id,
    reference: transaction.reference,
    person: transaction.recipientName || (
      sent ? "UPI payment" : "Received payment"
    ),
    recipientName: transaction.recipientName,
    recipientUpiId: transaction.recipientUpiId,
    amount: money(transaction.amount),
    currency: transaction.currency,
    type: transaction.type === "WALLET_CREDIT"
      ? "received"
      : sent ? "sent" : "received",
    status: transaction.status,
    note: transaction.note || "",
    date: transaction.completedAt || transaction.createdAt,
  };
}

function publicProfile(user, wallet) {
  const slug = String(user.fullName || "user")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "")
    .slice(0, 18) || "user";

  return {
    id: user.id,
    name: user.fullName,
    phone: user.phoneNumber,
    email: user.email,
    upiId: `${slug}@upay.demo`,
    balance: money(wallet.balance),
    currency: wallet.currency,
  };
}

/*
 * Payment PIN verification.
 * Failed attempts are recorded server-side; five failures lock the PIN
 * for fifteen minutes.
 */
async function verifyPaymentPin(userId, pin) {
  const record = await prisma.paymentPin.findUnique({
    where: { userId },
  });

  if (!record) {
    return { ok: false, code: "PIN_NOT_SET" };
  }

  const now = new Date();

  if (record.lockedUntil && record.lockedUntil > now) {
    return {
      ok: false,
      code: "PIN_LOCKED",
      retryAfterSeconds: Math.ceil(
        (record.lockedUntil.getTime() - now.getTime()) / 1000,
      ),
    };
  }

  const expiredLock = Boolean(
    record.lockedUntil && record.lockedUntil <= now,
  );

  const matches = await bcrypt.compare(pin, record.pinHash);

  if (!matches) {
    const attempts = (expiredLock ? 0 : record.failedAttempts) + 1;
    const lockedUntil = attempts >= 5
      ? new Date(Date.now() + 15 * 60 * 1000)
      : null;

    const updated = await prisma.paymentPin.updateMany({
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

    if (updated.count !== 1) {
      const latest = await prisma.paymentPin.findUnique({
        where: { userId },
        select: { failedAttempts: true, lockedUntil: true },
      });

      if (latest?.lockedUntil && latest.lockedUntil > new Date()) {
        return {
          ok: false,
          code: "PIN_LOCKED",
          retryAfterSeconds: Math.max(
            1,
            Math.ceil((latest.lockedUntil.getTime() - Date.now()) / 1000),
          ),
        };
      }

      return { ok: false, code: "PIN_INVALID" };
    }

    return {
      ok: false,
      code: lockedUntil ? "PIN_LOCKED" : "PIN_INVALID",
      ...(lockedUntil ? { retryAfterSeconds: 900 } : {}),
    };
  }

  // Reset counters only if the record has not changed since verification began.
  const reset = await prisma.paymentPin.updateMany({
    where: {
      userId,
      failedAttempts: record.failedAttempts,
      lockedUntil: record.lockedUntil,
    },
    data: {
      failedAttempts: 0,
      lockedUntil: null,
    },
  });

  if (reset.count !== 1) {
    const latest = await prisma.paymentPin.findUnique({
      where: { userId },
      select: { failedAttempts: true, lockedUntil: true },
    });

    if (latest?.lockedUntil && latest.lockedUntil > new Date()) {
      return {
        ok: false,
        code: "PIN_LOCKED",
        retryAfterSeconds: Math.max(
          1,
          Math.ceil((latest.lockedUntil.getTime() - Date.now()) / 1000),
        ),
      };
    }
  }

  return { ok: true };
}
/*
 * GET /api/wallet
 * Return the authenticated user's server-side wallet and profile.
 */
router.get("/", requireSession, requireUnlockedSession, async (req, res, next) => {
  try {
    const [user, wallet] = await Promise.all([
      prisma.user.findUnique({
        where: { id: req.auth.user.id },
        select: {
          id: true,
          fullName: true,
          phoneNumber: true,
          email: true,
        },
      }),
      prisma.wallet.findUnique({
        where: { userId: req.auth.user.id },
      }),
    ]);

    if (!user || !wallet) {
      return fail(
        res,
        404,
        "WALLET_NOT_FOUND",
        "Your wallet could not be found.",
      );
    }

    return res.json({
      profile: publicProfile(user, wallet),
      wallet: {
        balance: money(wallet.balance),
        currency: wallet.currency,
      },
    });
  } catch (error) {
    return next(error);
  }
});

/*
 * GET /api/wallet/transactions
 * Return recent sent, received and demo-credit ledger entries.
 */
router.get(
  "/transactions",
  requireSession,
  requireUnlockedSession,
  async (req, res, next) => {
    try {
      const parsed = z.coerce.number().int().min(1).max(100)
        .safeParse(req.query.limit ?? 50);

      if (!parsed.success) {
        return fail(
          res,
          400,
          "VALIDATION_ERROR",
          "Limit must be between 1 and 100.",
        );
      }

      const transactions = await prisma.transaction.findMany({
        where: {
          OR: [
            { senderId: req.auth.user.id },
            { receiverId: req.auth.user.id },
          ],
        },
        orderBy: { createdAt: "desc" },
        take: parsed.data,
      });

      return res.json({
        transactions: transactions.map((transaction) =>
          publicTransaction(transaction, req.auth.user.id)
        ),
      });
    } catch (error) {
      return next(error);
    }
  },
);

/*
 * POST /api/wallet/demo-funds
 * Add simulated funds. This is not a real bank deposit.
 */
router.post(
  "/demo-funds",
  requireSession,
  requireUnlockedSession,
  async (req, res, next) => {
    try {
      const parsed = demoFundsSchema.safeParse(req.body);

      if (!parsed.success) {
        return fail(
          res,
          400,
          "VALIDATION_ERROR",
          "Enter a valid demo-funds amount.",
        );
      }

      const amount = parseAmount(parsed.data.amount, MAX_DEMO_FUNDS);

      if (amount === null) {
        return fail(
          res,
          400,
          "INVALID_AMOUNT",
          "Enter demo funds between ₹1 and ₹1,00,000.",
        );
      }

      const userId = req.auth.user.id;

      const result = await prisma.$transaction(async (tx) => {
        const wallet = await tx.wallet.update({
          where: { userId },
          data: {
            balance: { increment: amount },
          },
        });

        const transaction = await tx.transaction.create({
          data: {
            senderId: userId,
            type: "WALLET_CREDIT",
            status: "SUCCESS",
            amount,
            currency: wallet.currency,
            note: "Demo funds added",
            completedAt: new Date(),
          },
        });

        return { wallet, transaction };
      });

      return res.status(201).json({
        message: "Demo funds added. No real money was deposited.",
        wallet: {
          balance: money(result.wallet.balance),
          currency: result.wallet.currency,
        },
        transaction: publicTransaction(
          result.transaction,
          userId,
        ),
      });
    } catch (error) {
      return next(error);
    }
  },
);

/*
 * POST /api/wallet/payments
 * Record a simulated payment with server-side PIN verification.
 * The conditional balance update prevents concurrent overspending.
 */
router.post(
  "/payments",
  requireSession,
  requireUnlockedSession,
  async (req, res, next) => {
    let idempotencyKey;
    let paymentRequest;

    try {
      const parsed = paymentSchema.safeParse(req.body);

      if (!parsed.success) {
        return fail(
          res,
          400,
          "VALIDATION_ERROR",
          "Please check the payment details.",
        );
      }

      const data = parsed.data;
      const amount = parseAmount(data.amount);

      if (amount === null) {
        return fail(res, 400, "INVALID_AMOUNT", "Invalid payment amount.");
      }

      const recipientName = data.recipientName.trim();
      const recipientUpiId = data.recipientUpiId?.trim() || null;
      const note = data.note?.trim() || null;
      const userId = req.auth.user.id;

      if (
        recipientUpiId &&
        !/^[A-Za-z0-9._-]{2,100}@[A-Za-z0-9.-]{2,48}$/.test(recipientUpiId)
      ) {
        return fail(res, 400, "INVALID_UPI_ID", "Invalid UPI ID.");
      }

      idempotencyKey =
        data.idempotencyKey || req.get("x-idempotency-key") || undefined;

      paymentRequest = {
        userId,
        amount,
        recipientName,
        recipientUpiId,
        note,
      };

      const pinResult = await verifyPaymentPin(userId, data.pin);

      if (!pinResult.ok) {
        const status = pinResult.code === "PIN_LOCKED"
          ? 423
          : pinResult.code === "PIN_NOT_SET"
            ? 409
            : 400;

        return fail(
          res,
          status,
          pinResult.code,
          pinResult.message,
          pinResult.retryAfterSeconds,
        );
      }

      const matchesRequest = (existing) =>
        existing.senderId === paymentRequest.userId &&
        existing.type === "UPI_PAYMENT" &&
        existing.status === "SUCCESS" &&
        Number(existing.amount.toString()).toFixed(2) === paymentRequest.amount &&
        existing.recipientName === paymentRequest.recipientName &&
        (existing.recipientUpiId || null) === paymentRequest.recipientUpiId &&
        (existing.note || null) === paymentRequest.note;

      const sendReplay = async (existing) => {
        if (!matchesRequest(existing)) {
          return fail(
            res,
            409,
            "IDEMPOTENCY_CONFLICT",
            "This payment request key is already in use for different payment details.",
          );
        }

        const wallet = await prisma.wallet.findUnique({
          where: { userId },
          select: { balance: true, currency: true },
        });

        return res.status(200).json({
          message: "This payment was already recorded.",
          replayed: true,
          transaction: publicTransaction(existing, userId),
          wallet: wallet
            ? { balance: money(wallet.balance), currency: wallet.currency }
            : null,
        });
      };

      const result = await prisma.$transaction(async (tx) => {
        if (idempotencyKey) {
          const existing = await tx.transaction.findUnique({
            where: { idempotencyKey },
          });

          if (existing) {
            return { existing, replayed: true };
          }
        }

        const debit = await tx.wallet.updateMany({
          where: {
            userId,
            balance: { gte: amount },
          },
          data: {
            balance: { decrement: amount },
          },
        });

        if (debit.count !== 1) {
          const error = new Error("INSUFFICIENT_BALANCE");
          error.code = "INSUFFICIENT_BALANCE";
          throw error;
        }

        const transaction = await tx.transaction.create({
          data: {
            senderId: userId,
            type: "UPI_PAYMENT",
            status: "SUCCESS",
            amount,
            currency: "INR",
            recipientName,
            recipientUpiId,
            note,
            idempotencyKey,
            completedAt: new Date(),
          },
        });

        return { transaction, replayed: false };
      });

      if (result.replayed) {
        return await sendReplay(result.existing);
      }

      const wallet = await prisma.wallet.findUnique({
        where: { userId },
        select: { balance: true, currency: true },
      });

      return res.status(201).json({
        message: "Demo payment recorded. No real money was transferred.",
        replayed: false,
        transaction: publicTransaction(result.transaction, userId),
        wallet: wallet
          ? { balance: money(wallet.balance), currency: wallet.currency }
          : null,
      });
    } catch (error) {
      if (error.code === "INSUFFICIENT_BALANCE") {
        return fail(res, 409, "INSUFFICIENT_BALANCE", "Insufficient balance");
      }

      if (error.code === "IDEMPOTENCY_CONFLICT") {
        return fail(
          res,
          409,
          "IDEMPOTENCY_CONFLICT",
          "This payment request key is already in use for different payment details.",
        );
      }

      if (error.code === "P2002" && idempotencyKey && paymentRequest) {
        try {
          // A concurrent request may have created this key first.
          // The failed Prisma transaction rolls back its wallet debit.
          const existing = await prisma.transaction.findUnique({
            where: { idempotencyKey },
          });

          if (existing) {
            if (
              existing.senderId !== paymentRequest.userId ||
              existing.type !== "UPI_PAYMENT" ||
              existing.status !== "SUCCESS" ||
              Number(existing.amount.toString()).toFixed(2) !== paymentRequest.amount ||
              existing.recipientName !== paymentRequest.recipientName ||
              (existing.recipientUpiId || null) !== paymentRequest.recipientUpiId ||
              (existing.note || null) !== paymentRequest.note
            ) {
              return fail(
                res,
                409,
                "IDEMPOTENCY_CONFLICT",
                "This payment request key is already in use for different payment details.",
              );
            }

            const wallet = await prisma.wallet.findUnique({
              where: { userId: paymentRequest.userId },
              select: { balance: true, currency: true },
            });

            return res.status(200).json({
              message: "This payment was already recorded.",
              replayed: true,
              transaction: publicTransaction(existing, paymentRequest.userId),
              wallet: wallet
                ? { balance: money(wallet.balance), currency: wallet.currency }
                : null,
            });
          }
        } catch (recoveryError) {
          return next(recoveryError);
        }

        return fail(
          res,
          409,
          "DUPLICATE_PAYMENT",
          "This payment request may already have been processed. Refresh your transaction history.",
        );
      }

      return next(error);
    }
  },
);

export default router;
