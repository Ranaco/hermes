/** @type {import('jest').Config} */
export default {
  preset: "@hermit/jest-presets/node",
  testEnvironment: "node",
  moduleNameMapper: {
    "^@hermit/prisma$": "<rootDir>/../../packages/prisma",
    "^@hermit/(.*)$": "<rootDir>/../../packages/$1/src",
    "^(\\.{1,2}/.*)\\.js$": "$1",
  },
  transform: {
    "^.+\\.tsx?$": ["ts-jest", { useESM: true }],
  },
  extensionsToTreatAsEsm: [".ts"],
};
