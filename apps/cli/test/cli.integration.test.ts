import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { spawn } from "node:child_process";
import http from "node:http";
import type { AddressInfo } from "node:net";

const cliEntry = path.resolve("src/index.ts");

interface ServerState {
  loginCount: number;
  createdSecrets: Record<string, unknown>[];
  lastLoginBody: Record<string, unknown> | null;
}

function createServerState(): ServerState {
  return {
    loginCount: 0,
    createdSecrets: [],
    lastLoginBody: null,
  };
}

function jsonResponse(response: http.ServerResponse, statusCode: number, data: unknown) {
  response.writeHead(statusCode, { "content-type": "application/json" });
  response.end(JSON.stringify(data));
}

function collectBody(request: http.IncomingMessage): Promise<any> {
  return new Promise((resolve, reject) => {
    const chunks: Uint8Array[] = [];
    request.on("data", (chunk: Uint8Array) => chunks.push(chunk));
    request.on("end", () => {
      if (chunks.length === 0) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch (error) {
        reject(error);
      }
    });
    request.on("error", reject);
  });
}

async function startFakeHermitServer() {
  const state = createServerState();

  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url || "/", `http://${request.headers.host || "localhost"}`);

    if (request.method === "POST" && url.pathname === "/api/v1/auth/login") {
      const body = await collectBody(request);
      state.loginCount += 1;
      state.lastLoginBody = body;

      if (body.clientType !== "CLI" || !body.cliPublicKey || !body.hardwareFingerprint) {
        jsonResponse(response, 400, {
          success: false,
          error: { message: "Missing CLI device registration fields" },
        });
        return;
      }

      jsonResponse(response, 200, {
        success: true,
        data: {
          user: {
            id: "user-1",
            email: body.email,
            username: "runner",
            firstName: "Hermit",
            lastName: "Runner",
            isTwoFactorEnabled: false,
          },
          organization: { id: "org-1", name: "Acme Org" },
          tokens: { accessToken: "access-token", refreshToken: "refresh-token" },
          device: { id: "device-1", isTrusted: true, clientType: "CLI" },
        },
      });
      return;
    }

    if (request.method === "POST" && url.pathname === "/api/v1/auth/logout") {
      jsonResponse(response, 200, { success: true, data: { success: true } });
      return;
    }

    if (request.method === "GET" && url.pathname === "/api/v1/organizations") {
      jsonResponse(response, 200, {
        success: true,
        data: {
          organizations: [{ id: "org-1", name: "Acme Org", slug: "acme" }],
        },
      });
      return;
    }

    if (request.method === "GET" && url.pathname === "/api/v1/vaults") {
      jsonResponse(response, 200, {
        success: true,
        data: {
          vaults: [{ id: "vault-1", name: "app-vault", organizationId: "org-1", _count: { keys: 1 } }],
        },
      });
      return;
    }

    if (request.method === "GET" && url.pathname === "/api/v1/secrets") {
      const search = url.searchParams.get("search");
      const secrets =
        !search || search.toLowerCase() === "database_url"
          ? [
              {
                id: "secret-1",
                name: "DATABASE_URL",
                valueType: "STRING",
                updatedAt: "2026-03-01T00:00:00.000Z",
                currentVersion: { versionNumber: 1, createdAt: "2026-03-01T00:00:00.000Z" },
              },
            ]
          : [];
      jsonResponse(response, 200, {
        success: true,
        data: { secrets },
      });
      return;
    }

    if (request.method === "GET" && url.pathname === "/api/v1/keys") {
      jsonResponse(response, 200, {
        success: true,
        data: {
          keys: [{ id: "key-1", name: "default-key", vaultId: "vault-1", valueType: "STRING", createdAt: "2026-03-01T00:00:00.000Z" }],
        },
      });
      return;
    }

    if (request.method === "POST" && url.pathname === "/api/v1/secrets/secret-1/cli-reveal") {
      jsonResponse(response, 200, {
        success: true,
        data: {
          secret: {
            id: "secret-1",
            name: "DATABASE_URL",
            value: "postgres://db.example/hermit",
            versionNumber: 3,
            updatedAt: "2026-03-02T00:00:00.000Z",
          },
        },
      });
      return;
    }

    if (request.method === "POST" && url.pathname === "/api/v1/secrets/cli/bulk-reveal") {
      jsonResponse(response, 200, {
        success: true,
        data: {
          secrets: [
            { name: "DATABASE_URL", value: "postgres://db.example/hermit", valueType: "STRING" },
            { name: "APP_CONFIG", value: "API_KEY=abc123\nTIMEOUT=30", valueType: "MULTILINE" },
          ],
          skipped: [],
          count: 2,
        },
      });
      return;
    }

    if (request.method === "POST" && url.pathname === "/api/v1/secrets") {
      const body = await collectBody(request) as Record<string, unknown>;
      state.createdSecrets.push(body);
      jsonResponse(response, 200, {
        success: true,
        data: {
          secret: {
            id: `created-${state.createdSecrets.length}`,
            name: body.name,
            valueType: body.valueType,
            updatedAt: "2026-03-03T00:00:00.000Z",
          },
        },
      });
      return;
    }

    jsonResponse(response, 404, {
      success: false,
      error: { message: `Unhandled route: ${request.method} ${url.pathname}` },
    });
  });

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve());
  });

  const address = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${address.port}/api/v1`;

  return {
    server,
    baseUrl,
    state,
    async close() {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    },
  };
}

interface RunCliOptions {
  env?: Record<string, string>;
  stdin?: string;
}

function runCli(args: string[], options: RunCliOptions = {}): Promise<{ code: number | null, stdout: string, stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--import", "tsx", cliEntry, ...args], {
      cwd: path.resolve("."),
      env: {
        ...process.env,
        ...options.env,
      },
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });

    const stdout: Uint8Array[] = [];
    const stderr: Uint8Array[] = [];

    child.stdout.on("data", (chunk: Uint8Array) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Uint8Array) => stderr.push(chunk));
    child.on("error", reject);
    child.on("close", (code) => {
      resolve({
        code,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      });
    });

    if (options.stdin && child.stdin) {
      child.stdin.write(options.stdin);
    }
    if (child.stdin) {
      child.stdin.end();
    }
  });
}

async function findFiles(rootDir: string, targetName: string): Promise<string[]> {
  const matches: string[] = [];

  async function walk(currentDir: string) {
    const entries = await fs.readdir(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        await walk(fullPath);
        continue;
      }
      if (entry.name === targetName) {
        matches.push(fullPath);
      }
    }
  }

  await walk(rootDir);
  return matches;
}

describe("cli integration", () => {
  let tempRoot: string;
  let fakeServer: Awaited<ReturnType<typeof startFakeHermitServer>>;
  let baseEnv: Record<string, string>;

  beforeAll(async () => {
    tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "hermit-cli-test-"));
    fakeServer = await startFakeHermitServer();

    baseEnv = {
      APPDATA: tempRoot,
      LOCALAPPDATA: tempRoot,
      USERPROFILE: tempRoot,
      HOME: tempRoot,
      FORCE_COLOR: "0",
    };
  });

  afterAll(async () => {
    if (fakeServer) await fakeServer.close();
    if (tempRoot) await fs.rm(tempRoot, { recursive: true, force: true });
  });

  it("shorthand login uses the CLI device-aware auth flow", async () => {
    const result = await runCli(
      ["login", "-s", fakeServer.baseUrl, "-e", "user@example.com", "-p", "secret", "--json"],
      { env: baseEnv },
    );

    expect(result.code).toBe(0);
    const payload = JSON.parse(result.stdout);
    expect(payload.success).toBe(true);
    expect(payload.user.email).toBe("user@example.com");
    expect(fakeServer.state.lastLoginBody.clientType).toBe("CLI");
    expect(fakeServer.state.lastLoginBody.cliPublicKey).toBeTruthy();
    expect(fakeServer.state.lastLoginBody.hardwareFingerprint).toBeTruthy();

    const keyFiles = await findFiles(tempRoot, "store-key");
    expect(keyFiles.length).toBe(1);
  });

  it("version output does not depend on a readable auth store", async () => {
    const isolatedRoot = await fs.mkdtemp(path.join(os.tmpdir(), "hermit-cli-version-test-"));
    const isolatedEnv = {
      ...baseEnv,
      APPDATA: isolatedRoot,
      LOCALAPPDATA: isolatedRoot,
      USERPROFILE: isolatedRoot,
      HOME: isolatedRoot,
    };

    const bootstrapResult = await runCli(
      ["login", "-s", fakeServer.baseUrl, "-e", "bootstrap@example.com", "-p", "secret", "--json"],
      { env: isolatedEnv },
    );
    expect(bootstrapResult.code).toBe(0);

    const resolvedConfigFiles = await findFiles(isolatedRoot, "config.json");
    expect(resolvedConfigFiles.length >= 1).toBe(true);
    await fs.writeFile(resolvedConfigFiles[0], "not-json-and-not-decryptable", "utf8");

    const result = await runCli(["--version"], { env: isolatedEnv });
    expect(result.code).toBe(0);
    expect(result.stdout).toMatch(/\d+\.\d+\.\d+/);

    await fs.rm(isolatedRoot, { recursive: true, force: true });
  });

  it("default invocation does not depend on a readable auth store", async () => {
    const isolatedRoot = await fs.mkdtemp(path.join(os.tmpdir(), "hermit-cli-default-test-"));
    const isolatedEnv = {
      ...baseEnv,
      APPDATA: isolatedRoot,
      LOCALAPPDATA: isolatedRoot,
      USERPROFILE: isolatedRoot,
      HOME: isolatedRoot,
    };

    const bootstrapResult = await runCli(
      ["login", "-s", fakeServer.baseUrl, "-e", "bootstrap2@example.com", "-p", "secret", "--json"],
      { env: isolatedEnv },
    );
    expect(bootstrapResult.code).toBe(0);

    const resolvedConfigFiles = await findFiles(isolatedRoot, "config.json");
    expect(resolvedConfigFiles.length >= 1).toBe(true);
    await fs.writeFile(resolvedConfigFiles[0], "not-json-and-not-decryptable", "utf8");

    const result = await runCli([], { env: isolatedEnv });
    expect([0, 1]).toContain(result.code);
    expect(result.stdout || result.stderr).toMatch(/Usage: hermit/i);
    expect(`${result.stdout}\n${result.stderr}`).not.toMatch(/SyntaxError: Unexpected token/i);

    await fs.rm(isolatedRoot, { recursive: true, force: true });
  });

  it("nested auth login also succeeds and persists authenticated status", async () => {
    const loginResult = await runCli(
      ["auth", "login", "-s", fakeServer.baseUrl, "-e", "user2@example.com", "-p", "secret", "--json"],
      { env: baseEnv },
    );
    expect(loginResult.code).toBe(0);

    const statusResult = await runCli(["auth", "status", "--json"], { env: baseEnv });
    expect(statusResult.code).toBe(0);
    const statusPayload = JSON.parse(statusResult.stdout);
    expect(statusPayload.authenticated).toBe(true);
    expect(statusPayload.user.email).toBe("user2@example.com");
    expect(statusPayload.organization.name).toBe("Acme Org");
  });

  it("secret get prints the raw value to stdout in non-tty mode", async () => {
    const result = await runCli(["get", "DATABASE_URL", "--vault", "app-vault"], { env: baseEnv });
    expect(result.code).toBe(0);
    expect(result.stdout.trim()).toBe("postgres://db.example/hermit");
  });

  it("env export emits mapped environment variables as JSON", async () => {
    const result = await runCli(["export", "--vault", "app-vault", "--format", "json"], { env: baseEnv });
    expect(result.code).toBe(0);
    const payload = JSON.parse(result.stdout);
    expect(payload).toEqual({
      DATABASE_URL: "postgres://db.example/hermit",
      API_KEY: "abc123",
      TIMEOUT: "30",
    });
  });

  it("secret import creates secrets from dotenv input", async () => {
    const importFile = path.join(tempRoot, "import.env");
    await fs.writeFile(importFile, "FIRST_KEY=one\nSECOND_KEY=two\n", "utf8");

    const result = await runCli(
      ["secret", "import", importFile, "--vault", "app-vault", "--yes", "--json"],
      { env: baseEnv },
    );
    expect(result.code).toBe(0);
    const payload = JSON.parse(result.stdout);
    expect(payload.success).toBe(true);
    expect(payload.created).toBe(2);
    expect(fakeServer.state.createdSecrets.length).toBe(2);
    expect(fakeServer.state.createdSecrets[0].name).toBe("FIRST_KEY");
    expect(fakeServer.state.createdSecrets[1].name).toBe("SECOND_KEY");
  });

  it("logout clears the persisted session", async () => {
    const logoutResult = await runCli(["logout", "--json"], { env: baseEnv });
    expect(logoutResult.code).toBe(0);

    const statusResult = await runCli(["auth", "status", "--json"], { env: baseEnv });
    expect(statusResult.code).toBe(0);
    const statusPayload = JSON.parse(statusResult.stdout);
    expect(statusPayload.authenticated).toBe(false);
  });
});
