import { describe, it, expect, jest } from "@jest/globals";
import supertest from "supertest";

// Mocking in ESM requires jest.unstable_mockModule before any imports that might use the module
jest.unstable_mockModule("@hermit/logger", () => ({
  log: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
    http: jest.fn(),
  },
  httpLogStream: {
    write: jest.fn(),
  },
  default: {
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn(),
    http: jest.fn(),
    debug: jest.fn(),
  },
}));

jest.unstable_mockModule("@hermit/vault-client", () => ({
  createVaultService: () => ({
    initialize: async () => undefined,
    testConnection: async () => true,
    checkHealth: async () => ({ initialized: true }),
  }),
}));

jest.unstable_mockModule("../services/prisma.service", () => ({
  __esModule: true,
  default: () => ({
    $on: jest.fn(),
    $connect: jest.fn(),
    $disconnect: jest.fn(),
    $queryRaw: jest.fn(),
  }),
  checkDatabaseConnection: async () => true,
  getPrismaClient: () => ({
    $on: jest.fn(),
    $connect: jest.fn(),
    $disconnect: jest.fn(),
    $queryRaw: jest.fn(),
  }),
}));

// We need to dynamically import the server after mocking
const { createServer } = await import("../server");

describe("Server", () => {
  it("health check returns 200", async () => {
    const app = createServer();
    const response = await supertest(app).get("/health");
    expect(response.status).toBe(200);
    expect(response.body.status).toBe("healthy");
  });
});
