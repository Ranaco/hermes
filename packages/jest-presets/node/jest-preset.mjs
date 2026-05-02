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
  transformIgnorePatterns: [
    "/node_modules/(?!(chalk|ora|cli-cursor|restore-cursor|log-symbols|is-interactive|is-unicode-supported|figures|string-width|strip-ansi|ansi-regex|ansi-styles|onetime|mimic-fn|stdin-discarder|conf|clipboardy|execa)/)",
  ],
  preset: "ts-jest",
};

export default config;
