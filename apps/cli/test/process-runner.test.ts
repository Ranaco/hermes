import { describe, it, expect } from '@jest/globals';
import { runWithEnv } from '../src/lib/process-runner';

describe('process-runner', () => {
  it('spawns node --version and exits 0', async () => {
    const code = await runWithEnv('node', ['--version'], {});
    expect(code).toBe(0);
  });

  it('injects env vars into child process', async () => {
    const code = await runWithEnv(
      'node',
      ['-e', 'process.exit(process.env.HERMIT_INJECTED?0:1)'],
      { HERMIT_INJECTED: 'yes' },
    );
    expect(code).toBe(0);
  });

  it('non-zero exit code propagates', async () => {
    const code = await runWithEnv('node', ['-e', 'process.exit(42)'], {});
    expect(code).toBe(42);
  });

  it('preserves arguments containing shell metacharacters', async () => {
    const code = await runWithEnv(
      'node',
      [
        '-e',
        "const value = process.argv[1]; process.exit(value === 'hello & goodbye' ? 0 : 1)",
        'hello & goodbye',
      ],
      {},
    );
    expect(code).toBe(0);
  });

  it('preserves arguments containing spaces and quotes', async () => {
    const code = await runWithEnv(
      'node',
      [
        '-e',
        "const value = process.argv[1]; process.exit(value === 'say \"hello world\"' ? 0 : 1)",
        'say "hello world"',
      ],
      {},
    );
    expect(code).toBe(0);
  });

  if (process.platform === 'win32') {
    it('runs Windows shell commands safely via cmd /c', async () => {
      const code = await runWithEnv('cmd', ['/c', 'echo', 'hello'], {});
      expect(code).toBe(0);
    });
  }
});
