import { describe, it, expect, jest } from "@jest/globals";
import { setupMocks } from "./utils/test-utils.js";

// Mocking in ESM requires jest.unstable_mockModule before any imports that might use the module
setupMocks();

import supertest from "supertest";

// We need to dynamically import the server after mocking
const { createServer } = await import("../server.js");

describe("Server", () => {
  it("health check returns 200", async () => {
    const app = createServer();
    const response = await supertest(app).get("/health");
    expect(response.status).toBe(200);
    expect(response.body.status).toBe("healthy");
  });
});
