import { jest } from "@jest/globals";

export const mockLogger = {
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
  http: jest.fn(),
};

export const mockPrisma = {
  $on: jest.fn(),
  $connect: jest.fn(),
  $disconnect: jest.fn(),
  $queryRaw: jest.fn(),
  user: {
    findUnique: jest.fn(),
    findFirst: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
  },
  organization: {
    findUnique: jest.fn(),
    create: jest.fn(),
  },
  vault: {
    findUnique: jest.fn(),
    create: jest.fn(),
  },
  secret: {
    findMany: jest.fn(),
    create: jest.fn(),
  },
};

export const setupMocks = () => {
  jest.unstable_mockModule("@hermit/logger", () => ({
    log: mockLogger,
    httpLogStream: {
      write: jest.fn(),
    },
    default: mockLogger,
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
    default: () => mockPrisma,
    getPrismaClient: () => mockPrisma,
    checkDatabaseConnection: async () => true,
    disconnectPrisma: async () => undefined,
    prisma: mockPrisma,
  }));
};
