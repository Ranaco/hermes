import preset from '@hermit/jest-presets/node/jest-preset.mjs';

/** @type {import('jest').Config} */
export default {
  ...preset,
  displayName: 'cli',
};
