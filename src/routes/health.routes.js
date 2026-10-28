import { Router } from "express";
import { prisma } from "../lib/prisma.js";

const router = Router();

// Liveness check: confirms that the API process is running.
router.get("/", (_req, res) => {
  res.json({
    status: "ok",
    service: "u-pay-backend",
    timestamp: new Date().toISOString(),
  });
});

// Readiness check: confirms that PostgreSQL is reachable.
router.get("/ready", async (_req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;

    return res.json({
      status: "ok",
      service: "u-pay-backend",
      database: "connected",
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Database readiness check failed:", error.message);

    return res.status(503).json({
      status: "error",
      service: "u-pay-backend",
      database: "unavailable",
      error: {
        code: "DATABASE_UNAVAILABLE",
        message: "The database is currently unavailable.",
      },
      timestamp: new Date().toISOString(),
    });
  }
});

export default router;
