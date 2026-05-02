# Initialize Jest Testing Framework Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Initialize Jest testing framework for the Hermit system, focusing on CLI and API modules.

**Architecture:** Use a monorepo-friendly Jest setup with shared presets in `packages/jest-presets`. CLI will be migrated from Node.js built-in test runner to Jest.

**Tech Stack:** Jest, ts-jest, TypeScript.

---

### Task 1: Update `@hermit/jest-presets`

**Files:**
- Modify: `packages/jest-presets/package.json`
- Modify: `packages/jest-presets/node/jest-preset.mjs`

- [ ] **Step 1: Ensure all dependencies are present in `packages/jest-presets/package.json`**

```json
  "dependencies": {
    "jest": "^29.7.0",
    "jest-environment-jsdom": "^29.7.0",
    "ts-jest": "^29.1.0",
    "@types/jest": "^29.5.0"
  }
```

- [ ] **Step 2: Update `jest-preset.mjs` to be more robust**

```javascript
/** @type {import('jest').Config} */
const config = {
  roots: ["<rootDir>"],
  transform: {
    "^.+\\.tsx?$": ["ts-jest", { useESM: true }],
  },
  extensionsToTreatAsEsm: [".ts"],
  moduleNameMapper: {
    "^(\\.{1,2}/.*)\\.js$": "$1",
  },
  moduleFileExtensions: ["ts", "tsx", "js", "jsx", "json", "node"],
  modulePathIgnorePatterns: [
    "<rootDir>/test/__fixtures__",
    "<rootDir>/node_modules",
    "<rootDir>/dist",
  ],
  preset: "ts-jest",
};

export default config;
```

### Task 2: Configure Jest for `apps/cli`

**Files:**
- Modify: `apps/cli/package.json`
- Create: `apps/cli/jest.config.js`

- [ ] **Step 1: Add Jest dependencies to `apps/cli/package.json`**

```json
"devDependencies": {
  ...
  "@hermit/jest-presets": "*",
  "jest": "^29.7.0",
  "@jest/globals": "^29.7.0"
}
```

- [ ] **Step 2: Add test script to `apps/cli/package.json`**

```json
"scripts": {
  ...
  "test": "jest"
}
```

- [ ] **Step 3: Create `apps/cli/jest.config.js`**

```javascript
import preset from '@hermit/jest-presets/node/jest-preset.mjs';

/** @type {import('jest').Config} */
export default {
  ...preset,
  displayName: 'cli',
};
```

### Task 3: Create Smoke Tests

**Files:**
- Create: `apps/cli/src/__tests__/smoke.test.ts`
- Create: `apps/api/src/__tests__/smoke.test.ts` (if not already there, but there is server.test.ts)

- [ ] **Step 1: Create `apps/cli/src/__tests__/smoke.test.ts`**

```typescript
import { describe, it, expect } from '@jest/globals';

describe('CLI Smoke Test', () => {
  it('should pass', () => {
    expect(true).toBe(true);
  });
});
```

- [ ] **Step 2: Run tests in `apps/cli`**

Run: `npm test -w @hermit-kms/cli`
Expected: PASS

- [ ] **Step 3: Run all tests via root**

Run: `npm test`
Expected: PASS for all modules that have tests

### Task 4: (Optional) Convert one existing CLI test to Jest to verify transformation

**Files:**
- Create: `apps/cli/test/process-runner.test.ts` (converted from .mjs)

- [ ] **Step 1: Convert `apps/cli/test/process-runner.test.mjs` to `apps/cli/test/process-runner.jest.test.ts`**

```typescript
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
});
```

- [ ] **Step 2: Run the new test**

Run: `npm test -w @hermit-kms/cli`
Expected: PASS
