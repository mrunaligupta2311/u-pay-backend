-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "OtpPurpose" ADD VALUE 'ENTRY_PIN_RESET_EMAIL';
ALTER TYPE "OtpPurpose" ADD VALUE 'ENTRY_PIN_RESET_PHONE';
ALTER TYPE "OtpPurpose" ADD VALUE 'TRANSACTION_PIN_RESET_EMAIL';
ALTER TYPE "OtpPurpose" ADD VALUE 'TRANSACTION_PIN_RESET_PHONE';

-- AlterTable
ALTER TABLE "Transaction" ADD COLUMN     "recipientName" TEXT,
ADD COLUMN     "recipientUpiId" TEXT;

-- CreateTable
CREATE TABLE "EntryPin" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "pinHash" TEXT NOT NULL,
    "failedAttempts" INTEGER NOT NULL DEFAULT 0,
    "lockedUntil" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EntryPin_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "EntryPin_userId_key" ON "EntryPin"("userId");

-- AddForeignKey
ALTER TABLE "EntryPin" ADD CONSTRAINT "EntryPin_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
