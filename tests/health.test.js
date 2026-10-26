import { describe, expect, it } from "vitest";
import request from "supertest";
import app from "../src/app.js";

describe("U-Pay API", () => {
  it("returns API information", async () => {
    const response = await request(app).get("/");
    expect(response.status).toBe(200);
    expect(response.body.name).toBe("U-Pay API");
  });

  it("returns a healthy status", async () => {
    const response = await request(app).get("/api/health");
    expect(response.status).toBe(200);
    expect(response.body.status).toBe("ok");
    expect(response.body.service).toBe("u-pay-backend");
  });

  it("returns 404 for unknown routes", async () => {
    const response = await request(app).get("/api/unknown");
    expect(response.status).toBe(404);
    expect(response.body.error.code).toBe("NOT_FOUND");
  });
});
