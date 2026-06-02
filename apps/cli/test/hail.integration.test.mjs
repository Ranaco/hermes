import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { spawn } from "node:child_process";
import http from "node:http";

const cliEntry = path.resolve("dist/index.js");

function jsonResponse(response, statusCode, data) {
  response.writeHead(statusCode, { "content-type": "application/json" });
  response.end(JSON.stringify(data));
}

async function startFakeHermitServer() {
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, "http://127.0.0.1");

    if (request.method === "POST" && url.pathname === "/api/v1/auth/login") {
      jsonResponse(response, 200, {
        success: true,
        data: {
          user: { id: "user-1", email: "user@example.com" },
          organization: { id: "org-1", name: "Acme Org" },
          tokens: { accessToken: "access-token", refreshToken: "refresh-token" },
          device: { id: "device-1", isTrusted: true, clientType: "CLI" },
        },
      });
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
          vaults: [
            { id: "vault-1", name: "vault-one", organizationId: "org-1" },
            { id: "vault-2", name: "vault-two", organizationId: "org-1" },
          ],
        },
      });
      return;
    }

    if (request.method === "GET" && url.pathname === "/api/v1/secrets") {
      const vaultId = url.searchParams.get("vaultId");
      if (vaultId === "vault-1") {
        jsonResponse(response, 200, {
          success: true,
          data: {
            secrets: [
              { id: "secret-1", name: "S1", valueType: "STRING", updatedAt: "2026-03-01T00:00:00.000Z" },
            ],
          },
        });
      } else if (vaultId === "vault-2") {
        jsonResponse(response, 200, {
          success: true,
          data: {
            secrets: [
              { id: "secret-2", name: "S2", valueType: "JSON", updatedAt: "2026-03-01T00:00:00.000Z" },
            ],
          },
        });
      } else {
        jsonResponse(response, 200, { success: true, data: { secrets: [] } });
      }
      return;
    }

    jsonResponse(response, 404, {
      success: false,
      error: { message: `Unhandled route: ${request.method} ${url.pathname}` },
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}/api/v1`;

  return {
    server,
    baseUrl,
    async close() {
      await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
    },
  };
}

function runCli(args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cliEntry, ...args], {
      cwd: path.resolve("."),
      env: {
        ...process.env,
        ...options.env,
      },
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });

    const stdout = [];
    const stderr = [];

    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.on("error", reject);
    child.on("close", (code) => {
      resolve({
        code,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      });
    });

    child.stdin.end();
  });
}

test("hail command", async (t) => {
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "hermit-hail-test-"));
  const fakeServer = await startFakeHermitServer();

  const baseEnv = {
    APPDATA: tempRoot,
    LOCALAPPDATA: tempRoot,
    USERPROFILE: tempRoot,
    HOME: tempRoot,
    FORCE_COLOR: "0",
  };

  await t.test("hail retrieves and displays all vault data in JSON mode", async () => {
    // First login
    await runCli(["login", "-s", fakeServer.baseUrl, "-e", "user@example.com", "-p", "password"], { env: baseEnv });

    const result = await runCli(["hail", "--json"], { env: baseEnv });
    assert.equal(result.code, 0, result.stderr);
    
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.success, true);
    assert.equal(payload.organization.name, "Acme Org");
    assert.equal(payload.vaults.length, 2);
    
    const v1 = payload.vaults.find(v => v.name === "vault-one");
    assert.equal(v1.secrets.length, 1);
    assert.equal(v1.secrets[0].name, "S1");

    const v2 = payload.vaults.find(v => v.name === "vault-two");
    assert.equal(v2.secrets.length, 1);
    assert.equal(v2.secrets[0].name, "S2");
  });

  await t.test("hail displays data in text mode", async () => {
    const result = await runCli(["hail"], { env: baseEnv });
    assert.equal(result.code, 0, result.stderr);
    assert.match(result.stdout, /Organization: Acme Org/);
    assert.match(result.stdout, /vault-one/);
    assert.match(result.stdout, /vault-two/);
    assert.match(result.stdout, /S1/);
    assert.match(result.stdout, /S2/);
  });

  await fakeServer.close();
  await fs.rm(tempRoot, { recursive: true, force: true });
});
