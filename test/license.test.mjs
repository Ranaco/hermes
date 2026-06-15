import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";

test("license file exists and has correct format", async () => {
  const licensePath = path.resolve("LICENSE.md");
  const stats = await fs.stat(licensePath);
  assert.ok(stats.isFile(), "LICENSE.md should be a file");

  const content = await fs.readFile(licensePath, "utf8");
  assert.ok(content.startsWith("# License"), "LICENSE.md should start with '# License'");
  assert.ok(content.includes("MIT License"), "LICENSE.md should contain 'MIT License'");
  assert.ok(content.includes("Copyright (c) 2026 Hermit KMS Contributors"), "LICENSE.md should have correct copyright");
});

test("original LICENSE file should be removed", async () => {
  const oldLicensePath = path.resolve("LICENSE");
  try {
    await fs.access(oldLicensePath);
    assert.fail("LICENSE file should have been removed in favor of LICENSE.md");
  } catch (error) {
    assert.strictEqual(error.code, "ENOENT", "LICENSE file should not exist");
  }
});
