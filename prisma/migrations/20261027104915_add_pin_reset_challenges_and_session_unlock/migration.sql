-- AlterTable
ALTER TABLE "Session" ADD COLUMN     "entryPinVerifiedAt" TIMESTAMP(3);

-- CreateTable
CREATE TABLE "PinResetChallenge" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "pinType" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PinResetChallenge_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "PinResetChallenge_tokenHash_key" ON "PinResetChallenge"("tokenHash");

-- CreateIndex
CREATE INDEX "PinResetChallenge_userId_expiresAt_idx" ON "PinResetChallenge"("userId", "expiresAt");

-- AddForeignKey
ALTER TABLE "PinResetChallenge" ADD CONSTRAINT "PinResetChallenge_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
