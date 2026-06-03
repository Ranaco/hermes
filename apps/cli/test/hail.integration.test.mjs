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

function collectBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
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
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, "http://127.0.0.1");

    if (request.method === "POST" && url.pathname === "/api/v1/auth/login") {
      const body = await collectBody(request);
      jsonResponse(response, 200, {
        success: true,
        data: {
          user: { id: "user-1", email: body.email },
          organization: { id: "org-1", name: "Acme Org" },
          tokens: { accessToken: "access-token", refreshToken: "refresh-token" },
          device: { id: "device-1", isTrusted: true },
        },
      });
      return;
    }

    if (request.method === "GET" && url.pathname === "/api/v1/organizations") {
      jsonResponse(response, 200, {
        success: true,
        data: {
          organizations: [{ id: "org-1", name: "Acme Org" }],
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
      const secrets = vaultId === "vault-1" 
        ? [{ id: "s1", name: "SECRET_ONE", valueType: "STRING", updatedAt: new Date().toISOString() }]
        : [{ id: "s2", name: "SECRET_TWO", valueType: "JSON", updatedAt: new Date().toISOString() }];
      
      jsonResponse(response, 200, {
        success: true,
        data: { secrets },
      });
      return;
    }

    jsonResponse(response, 404, { success: false, error: "Not Found" });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}/api/v1`;

  return {
    server,
    baseUrl,
    async close() {
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

function runCli(args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cliEntry, ...args], {
      cwd: path.resolve("."),
      env: { ...process.env, ...options.env },
      stdio: ["pipe", "pipe", "pipe"],
    });

    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.on("close", (code) => {
      resolve({
        code,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      });
    });
  });
}

await test("hail command integration", async (t) => {
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "hermit-hail-test-"));
  const fakeServer = await startFakeHermitServer();
  const baseEnv = { HOME: tempRoot, FORCE_COLOR: "0" };

  await t.test("hail command lists all vaults and secrets", async () => {
    // Login first
    await runCli(["login", "-s", fakeServer.baseUrl, "-e", "test@example.com", "-p", "pass"], { env: baseEnv });

    const result = await runCli(["hail"], { env: baseEnv });
    
    assert.equal(result.code, 0, result.stderr);
    assert.match(result.stdout, /vault-one/);
    assert.match(result.stdout, /vault-two/);
    assert.match(result.stdout, /SECRET_ONE/);
    assert.match(result.stdout, /SECRET_TWO/);
    assert.match(result.stdout, /Brought data from 2 vaults/);
  });

  await t.test("hail command supports --json output", async () => {
    const result = await runCli(["hail", "--json"], { env: baseEnv });
    
    assert.equal(result.code, 0, result.stderr);
    const data = JSON.parse(result.stdout);
    assert.ok(data.vaults);
    assert.equal(data.vaults.length, 2);
    assert.equal(data.vaults[0].vault.name, "vault-one");
    assert.equal(data.vaults[0].secrets[0].name, "SECRET_ONE");
  });

  await fakeServer.close();
  await fs.rm(tempRoot, { recursive: true, force: true });
});
