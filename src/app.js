import express from "express";
import helmet from "helmet";
import cors from "cors";
import healthRouter from "./routes/health.routes.js";

const app = express();

app.disable("x-powered-by");
app.use(helmet());

const allowedOrigins = (process.env.FRONTEND_ORIGINS || "http://localhost:5173")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error("Origin not allowed by CORS."));
  },
  credentials: true
}));

app.use(express.json({ limit: "20kb" }));

app.get("/", (_req, res) => {
  res.json({
    name: "U-Pay API",
    status: "running",
    message: "Backend scaffold is ready."
  });
});

app.use("/api/health", healthRouter);

app.use((_req, res) => {
  res.status(404).json({
    error: {
      code: "NOT_FOUND",
      message: "API endpoint not found."
    }
  });
});

app.use((error, _req, res, _next) => {
  if (error.message === "Origin not allowed by CORS.") {
    return res.status(403).json({
      error: {
        code: "ORIGIN_NOT_ALLOWED",
        message: "Request origin is not allowed."
      }
    });
  }

  if (error instanceof SyntaxError && "body" in error) {
    return res.status(400).json({
      error: {
        code: "INVALID_JSON",
        message: "Request body contains invalid JSON."
      }
    });
  }

  console.error("Unhandled API error:", error.message);

  return res.status(500).json({
    error: {
      code: "INTERNAL_SERVER_ERROR",
      message: "An unexpected server error occurred."
    }
  });
});

export default app;
