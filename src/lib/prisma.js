import { PrismaClient } from "../generated/prisma/index.js";

const globalForPrisma = globalThis;

export const prisma =
  globalForPrisma.__uPayPrisma ??
  new PrismaClient({
    log: process.env.NODE_ENV === "development"
      ? ["error", "warn"]
      : ["error"],
  });

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.__uPayPrisma = prisma;
}
