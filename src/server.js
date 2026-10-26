import "dotenv/config";
import app from "./app.js";

const port = Number(process.env.PORT || 4000);
const host = process.env.HOST || "127.0.0.1";

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  console.error("PORT must be a valid TCP port.");
  process.exit(1);
}

const server = app.listen(port, host, () => {
  console.log(`U-Pay API listening at http://${host}:${port}`);
});

function shutdown(signal) {
  console.log(`${signal} received. Closing server...`);

  server.close((error) => {
    if (error) {
      console.error("Failed to close server cleanly:", error.message);
      process.exitCode = 1;
    }

    process.exit();
  });
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
