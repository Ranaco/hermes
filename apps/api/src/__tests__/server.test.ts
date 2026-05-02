import { describe, it, expect, jest } from "@jest/globals";

// Mocking in ESM requires jest.unstable_mockModule before any imports that might use the module
jest.unstable_mockModule("@hermit/logger", () => {
  const logMock = {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
    http: jest.fn(),
  };
  return {
    log: logMock,
    httpLogStream: {
      write: jest.fn(),
    },
    default: logMock, // default is the winston instance, but for tests we can use the same mock
  };
});

jest.unstable_mockModule("@hermit/vault-client", () => ({
  createVaultService: () => ({
    initialize: async () => undefined,
    testConnection: async () => true,
    checkHealth: async () => ({ initialized: true }),
  }),
}));

jest.unstable_mockModule("../services/prisma.service", () => {
  const prismaMock = {
    $on: jest.fn(),
    $connect: jest.fn(),
    $disconnect: jest.fn(),
    $queryRaw: jest.fn(),
  };
  const getPrismaClient = () => prismaMock;
  return {
    __esModule: true,
    default: getPrismaClient,
    getPrismaClient,
    checkDatabaseConnection: async () => true,
    disconnectPrisma: async () => undefined,
    prisma: prismaMock,
  };
});

import supertest from "supertest";

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
