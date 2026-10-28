import { beforeEach, describe, expect, it, vi } from "vitest";
import request from "supertest";

const mocks = vi.hoisted(() => ({
  comparePin: vi.fn(),
  prisma: {
    paymentPin: {
      findUnique: vi.fn(),
      updateMany: vi.fn(),
    },
    transaction: {
      findUnique: vi.fn(),
    },
    wallet: {
      findUnique: vi.fn(),
    },
    $transaction: vi.fn(),
  },
}));

vi.mock("../src/lib/prisma.js", () => ({
  prisma: mocks.prisma,
}));

vi.mock("bcryptjs", () => ({
  default: {
    compare: mocks.comparePin,
  },
}));

vi.mock("../src/lib/session.js", async (importOriginal) => {
  const actual = await importOriginal();

  return {
    ...actual,
    requireSession: (req, _res, next) => {
      req.auth = { user: { id: "user-1" } };
      next();
    },
    requireUnlockedSession: (_req, _res, next) => next(),
  };
});

import app from "../src/app.js";

const state = {
  balance: 100,
  transactions: [],
};

function findTransaction(idempotencyKey) {
  return (
    state.transactions.find(
      (transaction) => transaction.idempotencyKey === idempotencyKey,
    ) ?? null
  );
}

beforeEach(() => {
  vi.clearAllMocks();

  state.balance = 100;
  state.transactions = [];

  mocks.comparePin.mockResolvedValue(true);

  mocks.prisma.paymentPin.findUnique.mockResolvedValue({
    userId: "user-1",
    pinHash: "mock-pin-hash",
    failedAttempts: 0,
    lockedUntil: null,
  });

  mocks.prisma.paymentPin.updateMany.mockResolvedValue({ count: 1 });

  mocks.prisma.wallet.findUnique.mockImplementation(async () => ({
    balance: state.balance,
    currency: "INR",
  }));

  mocks.prisma.transaction.findUnique.mockImplementation(
    async ({ where }) => findTransaction(where.idempotencyKey),
  );

  mocks.prisma.$transaction.mockImplementation(async (callback) => {
    const tx = {
      transaction: {
        findUnique: vi.fn(async ({ where }) =>
          findTransaction(where.idempotencyKey),
        ),

        create: vi.fn(async ({ data }) => {
          const transaction = {
            ...data,
            id: `tx-${state.transactions.length + 1}`,
            reference: `ref-${state.transactions.length + 1}`,
            createdAt: new Date(),
            amount: {
              toString: () => String(data.amount),
            },
          };

          state.transactions.push(transaction);
          return transaction;
        }),
      },

      wallet: {
        updateMany: vi.fn(async ({ where, data }) => {
          const amount = Number(data.balance.decrement);

          if (
            where.userId !== "user-1" ||
            state.balance < amount
          ) {
            return { count: 0 };
          }

          state.balance -= amount;
          return { count: 1 };
        }),
      },
    };

    return callback(tx);
  });
});

const payment = (overrides = {}) => ({
  recipientName: "Test Recipient",
  recipientUpiId: "recipient@testbank",
  amount: "10.00",
  note: "Test payment",
  pin: "1234",
  idempotencyKey: "test-payment-key-001",
  ...overrides,
});

describe("UPI payment idempotency", () => {
  it("debits the wallet once for a new payment", async () => {
    const response = await request(app)
      .post("/api/wallet/payments")
      .send(payment());

    expect(response.status).toBe(201);
    expect(response.body.replayed).toBe(false);
    expect(state.balance).toBe(90);
    expect(state.transactions).toHaveLength(1);
  });

  it("does not debit again when the same payment is retried", async () => {
    const first = await request(app)
      .post("/api/wallet/payments")
      .send(payment());

    const second = await request(app)
      .post("/api/wallet/payments")
      .send(payment());

    expect(first.status).toBe(201);
    expect(second.status).toBe(200);
    expect(second.body.replayed).toBe(true);
    expect(state.balance).toBe(90);
    expect(state.transactions).toHaveLength(1);
  });

  it("rejects reuse of a key with different payment details", async () => {
    await request(app)
      .post("/api/wallet/payments")
      .send(payment());

    const response = await request(app)
      .post("/api/wallet/payments")
      .send(payment({ amount: "25.00" }));

    expect(response.status).toBe(409);
    expect(response.body.error.code).toBe("IDEMPOTENCY_CONFLICT");
    expect(state.balance).toBe(90);
    expect(state.transactions).toHaveLength(1);
  });

  it("recovers a duplicate-key race without debiting again", async () => {
    const first = await request(app)
      .post("/api/wallet/payments")
      .send(payment());

    expect(first.status).toBe(201);
    expect(state.balance).toBe(90);

    const duplicateError = new Error("Unique constraint conflict");
    duplicateError.code = "P2002";

    mocks.prisma.$transaction.mockRejectedValueOnce(duplicateError);

    const retry = await request(app)
      .post("/api/wallet/payments")
      .send(payment());

    expect(retry.status).toBe(200);
    expect(retry.body.replayed).toBe(true);
    expect(state.balance).toBe(90);
    expect(state.transactions).toHaveLength(1);
  });

  it("rejects payments when the wallet has insufficient funds", async () => {
    state.balance = 5;

    const response = await request(app)
      .post("/api/wallet/payments")
      .send(payment());

    expect(response.status).toBe(409);
    expect(response.body.error.code).toBe("INSUFFICIENT_BALANCE");
    expect(state.balance).toBe(5);
    expect(state.transactions).toHaveLength(0);
  });
});
