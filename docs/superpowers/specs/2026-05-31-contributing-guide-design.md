# Design: Comprehensive CONTRIBUTING.md

**Date:** 2026-05-31
**Topic:** CONTRIBUTING.md Improvement
**Goal:** Provide a clear, comprehensive guide for contributors to Hermit KMS.

## Overview

The current `CONTRIBUTING.md` exists but lacks specific details on how to report issues, how to run different types of checks (lint, test, type-check), and has some inconsistencies with the `README.md` (specifically regarding package manager usage). This design aims to consolidate and expand the guide.

## Components

### 1. Introduction & Code of Conduct
- Welcome message.
- Explicit link to `CODE_OF_CONDUCT.md`.

### 2. Issues & Feature Requests
- Guidelines for reporting bugs (searching existing issues, providing reproductions).
- Process for suggesting new features.

### 3. Development Setup
- Prerequisites (Node.js 18+, npm 9+, Docker).
- Step-by-step setup using `npm` (confirming `npm` is the preferred tool).
- Instructions for backing services (PostgreSQL, Vault) via Docker Compose.

### 4. Code Quality & Testing
- How to run tests: `npm test`.
- How to lint: `npm run lint`.
- How to format: `npm run format`.
- How to check types: `npm run check-types`.
- Mentioning that these are run in CI.

### 5. Git & PR Workflow
- Conventional Commits requirement.
- PR process: Forking, feature branches, changeset addition.
- Squashing commits on merge.

### 6. Changesets
- Why they are used (automated versioning).
- How to add one: `npx changeset add`.

## Approaches Considered

### Approach A: Minimal Update
Only fix the `npm` vs `yarn` discrepancy and add a line about tests.
*Pros:* Very low risk.
*Cons:* Still leaves many "how-to" questions for new contributors.

### Approach B: Comprehensive Guide (Recommended)
Add sections for Issue reporting, Feature requests, and explicit testing/linting commands. Refine the existing setup steps for clarity.
*Pros:* Reduces friction for new contributors, sets clear expectations.
*Cons:* Slightly more text to maintain.

## Architecture

The document will be structured as a standard GitHub `CONTRIBUTING.md` file in Markdown format.

## Testing Strategy

- Verify that all commands provided in the guide actually work in the current repository environment.
- Verify that links to other files (`CODE_OF_CONDUCT.md`, `SECURITY.md`, `docs/quickstart.md`) are correct.
