import "dotenv/config";
import app from "./app.js";
import { prisma } from "./lib/prisma.js";

const port = Number(process.env.PORT || 4000);
const host = process.env.HOST || "127.0.0.1";

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  console.error("PORT must be a valid TCP port.");
  process.exit(1);
}

const server = app.listen(port, host, () => {
  console.log(`U-Pay API listening at http://${host}:${port}`);
});

let shuttingDown = false;

function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;

  console.log(`${signal} received. Closing server...`);

  const forceExit = setTimeout(() => {
    console.error("Graceful shutdown timed out.");
    process.exit(1);
  }, 10000);

  forceExit.unref();

  server.close(async (error) => {
    try {
      await prisma.$disconnect();

      if (error) {
        console.error("Failed to close server cleanly:", error.message);
        process.exitCode = 1;
      } else {
        console.log("Database connection closed.");
      }
    } catch (disconnectError) {
      console.error(
        "Failed to disconnect Prisma:",
        disconnectError.message
      );
      process.exitCode = 1;
    } finally {
      clearTimeout(forceExit);
      process.exit();
    }
  });
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
