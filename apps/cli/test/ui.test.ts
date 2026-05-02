import { describe, it, expect } from '@jest/globals';

const ANSI_PATTERN = /\u001b\[[0-9;]*m/g;

function stripAnsi(value: string) {
  return value.replace(ANSI_PATTERN, "");
}

function visibleLines(output: string) {
  return output
    .trimEnd()
    .split("\n")
    .map((line) => stripAnsi(line));
}

async function loadUi() {
  return import("../src/lib/ui");
}

function captureOutput(run: () => void | Promise<void>, { columns = 60 } = {}) {
  const lines: string[] = [];
  const originalLog = console.log;
  const descriptor = Object.getOwnPropertyDescriptor(process.stdout, "columns");

  console.log = (...args: any[]) => {
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
      } else {
        // @ts-ignore
        delete process.stdout.columns;
      }
    })
    .then(() => visibleLines(lines.join("\n")));
}

describe('UI Tests', () => {
  it('panel wraps long MFA secret with hanging indentation', async () => {
    const ui = await loadUi();
    ui.setRuntimeState({ outputMode: "interactive", colorEnabled: false, nonInteractive: false });

    const lines = await captureOutput(() => {
      ui.panel("MFA Setup", [
        ui.kv("Secret", "JJBXGUJ4O5VUWKKVVNFYFI3LHLB5UYXRJHFXTMQKLKRIGG23SM5EA", { overflow: "wrap" }),
        ui.kv("Next", "Run `hermit auth mfa enable`", { overflow: "wrap" }),
      ]);
    });

    expect(lines.every((line) => line.length <= 60)).toBe(true);
    expect(lines[1]).toMatch(/^\s*│\s+Secret\s{4,}\S/);
    expect(lines[2]).toMatch(/^\s*│\s{14,}\S/);
  });

  it('panel truncates routine metadata like long server URLs', async () => {
    const ui = await loadUi();
    ui.setRuntimeState({ outputMode: "interactive", colorEnabled: false, nonInteractive: false });

    const lines = await captureOutput(() => {
      ui.panel("Authentication", [
        ui.kv("Server", "https://very-long-subdomain.hermit.internal.example.com/api/v1/session/current", { overflow: "truncate" }),
      ]);
    }, { columns: 58 });

    expect(lines.every((line) => line.length <= 58)).toBe(true);
    expect(lines.some((line) => line.includes("…"))).toBe(true);
  });

  it('cards keep header and footer aligned with long names and badges', async () => {
    const ui = await loadUi();
    ui.setRuntimeState({ outputMode: "interactive", colorEnabled: false, nonInteractive: false });

    const lines = await captureOutput(() => {
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

    const cardLines = lines.filter(Boolean);
    expect(cardLines[0].length).toBe(cardLines[cardLines.length - 1].length);
    expect(cardLines.every((line) => line.length <= 64)).toBe(true);
  });
});
