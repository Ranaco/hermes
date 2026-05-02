import { describe, it, expect } from '@jest/globals';
import { runWithEnv } from '../lib/process-runner';

describe('CLI Smoke Test', () => {
  it('should be able to import from lib', () => {
    expect(runWithEnv).toBeDefined();
  });
});
