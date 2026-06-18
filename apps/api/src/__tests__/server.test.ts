import supertest from "supertest";
import { describe, it, expect, jest } from "@jest/globals";

jest.mock("@hermit/logger", () => ({
  log: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
  httpLogStream: {
    write: jest.fn(),
  },
}));

jest.mock("@hermit/vault-client", () => ({
  createVaultService: () => ({
    initialize: async () => undefined,
    testConnection: async () => true,
    checkHealth: async () => ({ initialized: true }),
  }),
}));

import { createServer } from "../server";

describe("Server", () => {
  it("health check returns 200", async () => {
    await supertest(createServer())
      .get("/health")
      .expect(200)
      .then((res) => {
        expect(res.ok).toBe(true);
      });
  });

  it("health check reports the documented status payload", async () => {
    const res = await supertest(createServer())
      .get("/health")
      .expect("Content-Type", /json/)
      .expect(200);

    expect(res.body).toMatchObject({
      status: "healthy",
      environment: expect.any(String),
    });
    expect(typeof res.body.uptime).toBe("number");
    expect(res.body.uptime).toBeGreaterThanOrEqual(0);
    expect(() => new Date(res.body.timestamp).toISOString()).not.toThrow();
    expect(new Date(res.body.timestamp).toISOString()).toBe(res.body.timestamp);
  });
});
