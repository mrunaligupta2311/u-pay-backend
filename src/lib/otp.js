import { createHmac, randomInt, timingSafeEqual } from "node:crypto";

export function generateOtp() {
  return String(randomInt(0, 1_000_000)).padStart(6, "0");
}

export function hashOtp(otp) {
  const secret = process.env.OTP_HASH_SECRET || process.env.SESSION_SECRET;

  if (!secret || secret.length < 32) {
    throw new Error("OTP hashing secret is missing or too short.");
  }

  return createHmac("sha256", secret)
    .update(String(otp))
    .digest("hex");
}

export function verifyOtpHash(otp, savedHash) {
  if (typeof savedHash !== "string") return false;

  const supplied = Buffer.from(hashOtp(otp), "hex");
  const saved = Buffer.from(savedHash, "hex");

  return supplied.length === saved.length &&
    timingSafeEqual(supplied, saved);
}
