import {
  createHash,
  randomBytes,
} from "node:crypto";
import { prisma } from "./prisma.js";

const SESSION_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;

export function hashSessionToken(token) {
  return createHash("sha256").update(token).digest("hex");
}

export async function createSession(userId, req) {
  const token = randomBytes(32).toString("base64url");

  const session = await prisma.session.create({
    data: {
      userId,
      tokenHash: hashSessionToken(token),
      expiresAt: new Date(Date.now() + SESSION_LIFETIME_MS),
      userAgent: String(req.get("user-agent") || "").slice(0, 500) || null,
      ipAddress: req.ip || null,
    },
    select: {
      id: true,
      expiresAt: true,
    },
  });

  return {
    token,
    sessionId: session.id,
    expiresAt: session.expiresAt,
  };
}

export async function requireSession(req, res, next) {
  try {
    const authorization = req.get("authorization") || "";
    const bearer = authorization.match(/^Bearer\s+(.+)$/i)?.[1];
    const token = req.get("x-session-token") || bearer;

    if (
      typeof token !== "string" ||
      token.length < 32 ||
      token.length > 200
    ) {
      return res.status(401).json({
        error: {
          code: "SESSION_REQUIRED",
          message: "Please sign in again.",
        },
      });
    }

    const session = await prisma.session.findUnique({
      where: { tokenHash: hashSessionToken(token) },
      include: {
        user: {
          select: {
            id: true,
            fullName: true,
            email: true,
            phoneNumber: true,
            status: true,
            emailVerified: true,
            phoneVerified: true,
          },
        },
      },
    });

    if (
      !session ||
      session.revokedAt ||
      session.expiresAt <= new Date() ||
      session.user.status !== "ACTIVE" ||
      !session.user.emailVerified ||
      !session.user.phoneVerified
    ) {
      return res.status(401).json({
        error: {
          code: "SESSION_INVALID",
          message: "Your session has expired. Please sign in again.",
        },
      });
    }

    req.auth = {
      sessionId: session.id,
      user: session.user,
      entryPinVerifiedAt: session.entryPinVerifiedAt,
    };

    return next();
  } catch (error) {
    return next(error);
  }
}

export function requireUnlockedSession(req, res, next) {
  if (!req.auth?.entryPinVerifiedAt) {
    return res.status(423).json({
      error: {
        code: "ENTRY_PIN_REQUIRED",
        message: "Unlock U-Pay before continuing.",
      },
    });
  }

  return next();
}
