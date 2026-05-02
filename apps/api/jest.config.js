/** @type {import('jest').Config} */
export default {
  preset: "@hermit/jest-presets/node",
  testPathIgnorePatterns: ["/node_modules/", "/dist/", "/utils/"],
};
