import assert from "node:assert/strict";
import test from "node:test";

const ANSI_PATTERN = /\u001b\[[0-9;]*m/g;

function stripAnsi(value) {
  return value.replace(ANSI_PATTERN, "");
}

function visibleLines(output) {
  return output
    .trimEnd()
    .split("\n")
    .map((line) => stripAnsi(line));
}

async function loadUi() {
  return import("../src/lib/ui.ts");
}

function captureOutput(run, { columns = 60, outputMode = "interactive" } = {}) {
  const lines = [];
  const originalLog = console.log;
  const descriptor = Object.getOwnPropertyDescriptor(process.stdout, "columns");

  console.log = (...args) => {
    lines.push(args.join(" "));
  };

  Object.defineProperty(process.stdout, "columns", {
    configurable: true,
    value: columns,
  });

  return Promise.resolve()
    .then(run)
    .finally(() => {
      console.log = originalLog;
      if (descriptor) {
        Object.defineProperty(process.stdout, "columns", descriptor);
      }
    })
    .then(() => lines.join("\n"));
}

function getVisibleLines(output) {
  return visibleLines(output);
}

test("panel wraps long MFA secret with hanging indentation", async () => {
  const ui = await loadUi();
  ui.setRuntimeState({ outputMode: "interactive", colorEnabled: false, nonInteractive: false });

  const output = await captureOutput(() => {
    ui.panel("MFA Setup", [
      ui.kv("Secret", "JJBXGUJ4O5VUWKKVVNFYFI3LHLB5UYXRJHFXTMQKLKRIGG23SM5EA", { overflow: "wrap" }),
      ui.kv("Next", "Run `hermit auth mfa enable`", { overflow: "wrap" }),
    ]);
  });
  const lines = getVisibleLines(output);

  assert(lines.every((line) => line.length <= 60));
  assert.match(lines[1], /^\s*│\s+Secret\s{4,}\S/);
  assert.match(lines[2], /^\s*│\s{14,}\S/);
});

test("panel truncates routine metadata like long server URLs", async () => {
  const ui = await loadUi();
  ui.setRuntimeState({ outputMode: "interactive", colorEnabled: false, nonInteractive: false });

  const output = await captureOutput(() => {
    ui.panel("Authentication", [
      ui.kv("Server", "https://very-long-subdomain.hermit.internal.example.com/api/v1/session/current", { overflow: "truncate" }),
    ]);
  }, { columns: 58 });
  const lines = getVisibleLines(output);

  assert(lines.every((line) => line.length <= 58));
  assert(lines.some((line) => line.includes("…")));
});

test("cards keep header and footer aligned with long names and badges", async () => {
  const ui = await loadUi();
  ui.setRuntimeState({ outputMode: "interactive", colorEnabled: false, nonInteractive: false });

  const output = await captureOutput(() => {
    ui.cards([
      {
        id: "6ec10eaa-d87e-4041-9fff-1badf53f7745",
        name: "My Extremely Long Organization Name That Should Clamp Cleanly",
        badge: ui.formatBadge("owner", "accent"),
        fields: [
          { label: "Members", value: "14", overflow: "truncate" },
          { label: "Vaults", value: "2", overflow: "truncate" },
        ],
      },
    ]);
  }, { columns: 64 });
  const lines = getVisibleLines(output);

  const cardLines = lines.filter(Boolean);
  assert.equal(cardLines[0].length, cardLines[cardLines.length - 1].length);
  assert(cardLines.every((line) => line.length <= 64));
});

test("narrow terminals degrade stacked key value rows instead of breaking layout", async () => {
  const ui = await loadUi();
  ui.setRuntimeState({ outputMode: "interactive", colorEnabled: false, nonInteractive: false });

  const output = await captureOutput(() => {
    ui.panel("Session", [
      ui.kv("Server", "https://local.hermit.example.dev/api/v1", { overflow: "truncate" }),
      ui.kv("Vault", "customer-facing-platform-production", { overflow: "truncate" }),
    ]);
  }, { columns: 48 });
  const lines = getVisibleLines(output);

  assert(lines.every((line) => line.length <= 48));
  assert.match(lines[1], /^\s*│\s+Server\s*│?$/);
  assert.match(lines[2], /^\s*│\s{4,}\S/);
});

test("panel wraps multiline secret values cleanly", async () => {
  const ui = await loadUi();
  ui.setRuntimeState({ outputMode: "interactive", colorEnabled: false, nonInteractive: false });

  const output = await captureOutput(() => {
    ui.panel("DATABASE_URL", [
      ui.kv("Value", "postgres://app-user:secret-password@db.internal.example.com:5432/hermit_prod", { overflow: "wrap" }),
      ui.spacer(),
      ui.kv("Updated", ui.formatDateTime("2026-03-06T10:30:00.000Z"), { overflow: "wrap" }),
    ]);
  }, { columns: 60 });
  const lines = getVisibleLines(output);

  assert(lines.every((line) => line.length <= 60));
  assert(lines.some((line) => line.includes("postgres://")));
  assert(lines.some((line) => line.includes("Updated")));
});

test("panel shows copyright notice in footer", async () => {
  const ui = await loadUi();
  ui.setRuntimeState({ outputMode: "interactive", colorEnabled: false, quiet: false });

  const output = await captureOutput(() => {
    ui.panel("Test Panel", [ui.text("Hello World")]);
  });
  const lines = getVisibleLines(output);

  assert(lines.some(line => line.includes("© Ranaco")));
});

test("cards show copyright notice in footer", async () => {
  const ui = await loadUi();
  ui.setRuntimeState({ outputMode: "interactive", colorEnabled: false, quiet: false });

  const output = await captureOutput(() => {
    ui.cards([{ id: "1", name: "Test Card", fields: [{ label: "F1", value: "V1" }] }]);
  });
  const lines = getVisibleLines(output);

  assert(lines.some(line => line.includes("© Ranaco")));
});

test("footer shows copyright notice", async () => {
  const ui = await loadUi();
  ui.setRuntimeState({ outputMode: "interactive", colorEnabled: false, quiet: false });

  const output = await captureOutput(() => {
    ui.footer();
  });
  const lines = getVisibleLines(output);

  assert(lines.some(line => line.includes("© Ranaco")));
});

test("footer shows copyright notice even in plain mode non-TTY", async () => {
  const ui = await loadUi();
  ui.setRuntimeState({ outputMode: "plain", colorEnabled: false, quiet: false });
  // We don't easily mock process.stdout.isTTY but we removed the check in ui.ts

  const output = await captureOutput(() => {
    ui.footer();
  });
  const lines = getVisibleLines(output);

  assert(lines.some(line => line.includes("© Ranaco")));
});

test("theme can be changed and affects output", async () => {
  const ui = await loadUi();
  ui.setRuntimeState({ colorEnabled: true, theme: "default" });
  
  const defaultOutput = ui.colors.brand("test");
  assert.match(defaultOutput, /\u001b\[38;2;5;150;105mtest/); // Default brand color #059669

  ui.setTheme("dracula");
  const draculaOutput = ui.colors.brand("test");
  assert.match(draculaOutput, /\u001b\[38;2;189;147;249mtest/); // Dracula brand color #bd93f9

  ui.setTheme("ranaco");
  const ranacoOutput = ui.colors.brand("test");
  assert.match(ranacoOutput, /\u001b\[38;2;16;185;129mtest/); // Ranaco brand color #10b981
});

test("invalid theme name falls back to default", async () => {
  const ui = await loadUi();
  ui.setRuntimeState({ colorEnabled: true, theme: "invalid-theme" });
  
  const output = ui.colors.brand("test");
  assert.match(output, /\u001b\[38;2;5;150;105mtest/); // Default brand color #059669
});

