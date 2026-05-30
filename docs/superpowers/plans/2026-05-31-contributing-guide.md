# Comprehensive CONTRIBUTING.md Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish a comprehensive `CONTRIBUTING.md` that guides new contributors through setup, issue reporting, and the PR process.

**Architecture:** A single Markdown file in the repository root.

**Tech Stack:** Markdown.

---

### Task 1: Update CONTRIBUTING.md with Comprehensive Content

**Files:**
- Modify: `CONTRIBUTING.md`

- [ ] **Step 1: Replace existing content with comprehensive guide**

```markdown
# Contributing to Hermit KMS

Thank you for your interest in contributing to Hermit KMS! This guide covers everything you need to know to get started, from reporting bugs to submitting your first pull request.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Enhancements](#suggesting-enhancements)
  - [Pull Requests](#pull-requests)
- [Local Development Setup](#local-development-setup)
- [Development Workflow](#development-workflow)
  - [Commit Conventions](#commit-conventions)
  - [Changeset Requirement](#changeset-requirement)
- [Style Guide](#style-guide)

---

## Code of Conduct

This project and everyone participating in it is governed by the [Hermit KMS Code of Conduct](./CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the maintainers (see [SECURITY.md](./SECURITY.md)).

## How Can I Contribute?

### Reporting Bugs

Bugs are tracked as [GitHub issues](https://github.com/Ranaco/hermit/issues). When creating a bug report, please include as much detail as possible:

- **Use a clear and descriptive title.**
- **Describe the exact steps to reproduce the problem.**
- **Describe the behavior you observed** after following the steps and point out what exactly is the problem with that behavior.
- **Explain which behavior you expected to see instead and why.**
- **Include screenshots or animated GIFs** if helpful.

### Suggesting Enhancements

Enhancement suggestions are also tracked as [GitHub issues](https://github.com/Ranaco/hermit/issues).

- **Use a clear and descriptive title.**
- **Provide a step-by-step description of the suggested enhancement.**
- **Provide specific examples to demonstrate the steps.**
- **Explain why this enhancement would be useful** to most users.

### Pull Requests

1. **Fork** the repository and create your branch from `main`.
2. **Setup your local environment** (see below).
3. **Make your changes** in focused, atomic commits.
4. **Follow the Development Workflow** (testing, linting, changesets).
5. **Submit a PR** against the `main` branch.
6. **Stay involved** in the review process!

---

## Local Development Setup

### Prerequisites

- **Node.js**: 18.x or higher
- **npm**: 9.x or higher
- **Docker**: For running PostgreSQL and HashiCorp Vault

### Steps

```bash
# 1. Clone your fork
git clone https://github.com/YOUR_USERNAME/hermit.git
cd hermit

# 2. Install dependencies
npm install

# 3. Start backing services
docker compose up -d

# 4. Set up environment variables
cp apps/api/.env.example apps/api/.env
# (Optional) Edit apps/api/.env if your Docker setup differs

# 5. Run database migrations
npm run -w @hermit/prisma migrate:dev

# 6. Build the project
npm run build

# 7. Start development servers
npm run dev
```

---

## Development Workflow

### Quality Checks

Before submitting a PR, ensure all checks pass:

- **Linting**: `npm run lint`
- **Formatting**: `npm run format`
- **Type Checking**: `npm run check-types`
- **Testing**: `npm test`

### Commit Conventions

This project follows **Conventional Commits**. This is required for our automated changelog generation.

Format: `<type>(<scope>): <subject>`

- **feat**: A new feature
- **fix**: A bug fix
- **docs**: Documentation only changes
- **refactor**: A code change that neither fixes a bug nor adds a feature
- **test**: Adding missing tests or correcting existing tests
- **chore**: Updating build tasks, package manager configs, etc.

Examples:
- `feat(cli): add secret copy command`
- `fix(api): handle missing vault error`

### Changeset Requirement

If your change is user-facing (fix, feat), you **must** add a changeset file.

```bash
npx changeset add
```

Follow the prompts to select the affected packages and the version bump type.

---

## Style Guide

- **TypeScript**: Use explicit types. Avoid `any`.
- **Naming**: Use camelCase for variables/functions, PascalCase for classes/interfaces.
- **Testing**: Write tests for new functionality. We use Jest.
- **Documentation**: Update READMEs and JSDoc comments where appropriate.

---

Thank you for contributing!
```

- [ ] **Step 2: Verify the content**

Check that the links and commands are correct.

- [ ] **Step 3: Commit the changes**

```bash
git add CONTRIBUTING.md
git commit -m "docs: improve CONTRIBUTING.md with comprehensive guide"
```
