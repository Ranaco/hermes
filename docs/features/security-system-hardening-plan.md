# 🛡️ Security System Hardening Plan

**ID:** 7f550763-794d-4be5-8b59-5437c32279db  
**Status:** ✅ APPROVED  
**Approver:** Senior Security Engineer (@0xa9rana)  
**Date:** 2026-06-16  

---

## 🛡️ Approval Record
| Role | Identity | Status | Date | Reference |
| :--- | :--- | :--- | :--- | :--- |
| Senior Security Engineer | @0xa9rana | ✅ APPROVED | 2026-06-16 | discord:1516318055314096128 |
| Platform Lead | @astar | ✅ SUBMITTED | 2026-06-16 | codec/7f550763-794d-4be5-8b59-5437c32279db |

---

## 📖 Overview
This document outlines the strategy for hardening the Hermit KMS security infrastructure. The focus is on remediating credential leaks, securing the API gateway topology, and transitioning to robust third-party authentication (Clerk).

---

## 🔍 1. Current State Assessment
| Area | Finding | Risk |
| :--- | :--- | :--- |
| **Secrets** | Bearer token committed in `.gemini/settings.json`. | **CRITICAL** |
| **Infrastructure** | Default PostgreSQL passwords used in development. | **MEDIUM** |
| **Gateway** | KrakenD lacks edge-level JWT validation. | **MEDIUM** |
| **Auth** | Custom JWT implementation requires maintenance and lacks advanced features (MFA, SSO). | **MEDIUM** |

---

## 🛠️ 2. Detailed Hardening Measures

### Phase 1: Immediate Remediation (Priority: High)
#### 1.1 Secrets Cleanup & Prevention
- **Action:** Remove plaintext tokens from `.gemini/settings.json`.
- **Action:** Audit `.gitignore` to ensure `.gemini/`, `.env`, and `*.pem` are ignored.
- **Validation:** `git status --ignored` shows sensitive files are not tracked.

#### 1.2 Environment Isolation
- **Action:** Update `docker-compose.yml` to use environment variables for all secrets.
- **Action:** Update `apps/api/.env.example` to include all required security variables (e.g., `DB_PASSWORD`).
- **Validation:** `docker-compose up` works with `DB_PASSWORD` set in `.env`.

### Phase 2: Authentication Migration (Clerk) (Priority: High)
#### 2.1 Backend Integration
- **Owner:** Backend Team
- **Configuration:**
  - `CLERK_SECRET_KEY`: Backend API key.
  - `CLERK_JWT_KEY`: PEM public key for local verification.
  - `JWT_ISSUER`: `https://[clerk-domain]`
- **Implementation:**
  1. Create `ClerkMiddleware` using `@clerk/clerk-sdk-node`.
  2. Map Clerk user IDs to internal `userId` in `req.user`.
  3. Support hybrid auth (Legacy JWT + Clerk) during transition.
- **Affected Routes:**
  - `auth.routes.ts`: `login`, `register`, `mfa/*` (to be deprecated).
  - `user.routes.ts`: `me`, `me/password`.
  - `organization.routes.ts`: All protected routes.
  - `vault.routes.ts`, `key.routes.ts`, `secret.routes.ts`: All data operations.
- **Sequencing:**
  - Start with `user/me` for testing Clerk JWT integration.
  - Incrementally roll out to data routes (`vault`, `key`).
  - Finally migrate CLI and Web login flows.
- **Dependencies:** Clerk account and instance setup.

#### 2.2 Frontend & CLI Migration
- **Action:** Update `apps/web` to use Clerk Next.js SDK.
- **Action:** Update `apps/cli` to use Clerk device flow or local callback for login.
- **Rollback:** Revert `apps/api` middleware to use legacy JWT verification if Clerk is unreachable.

### Phase 3: Gateway Topology Hardening (Priority: Medium)
#### 3.1 KrakenD JWT Validation
- **Owner:** Platform/DevOps
- **Action:** Implement `auth/validator` plugin in `apps/krakend/krakend.json`.
- **JWKS Config:**
  - `url`: `https://[clerk-domain]/.well-known/jwks.json`
  - `cache`: true
- **Validation:** Requests without valid Clerk JWT are rejected at the gateway before reaching `apps/api`.

#### 3.2 Service Isolation
- **Action:** Ensure KrakenD only communicates with `api` service via internal Docker network.
- **Validation:** `krakend.json` uses `http://api:5001`.

---

## 📋 3. Execution Schedule & Ownership

| Task ID | Task Description | Owner | Dependency |
| :--- | :--- | :--- | :--- |
| SEC-01 | Cleanup committed secrets & update .gitignore | Security | None |
| SEC-02 | Parameterize DB passwords in Docker/Env | DevOps | None |
| SEC-03 | Backend Clerk Middleware (Hybrid Mode) | Backend | Clerk API Keys |
| SEC-04 | KrakenD Edge JWT Validation | DevOps | Clerk JWKS |
| SEC-05 | Full Migration to Clerk (Deprecate Legacy) | Fullstack | SEC-03, SEC-04 |

---

## 🔄 4. Rollback & Disaster Recovery
- **Auth Failure:** The `authenticate` middleware will be designed with a toggle to fallback to legacy JWTs if the Clerk SDK fails (Emergency Break-glass).
- **Gateway Loophole:** If KrakenD validator fails, the backend `api` still performs its own JWT verification as a second layer of defense.

---

## ✅ 5. Approval & Verification
- [ ] **Senior Engineer Review (@0xa9rana)**
- [ ] **Security Impact Assessment**
- [ ] **Acceptance Criteria Met**

> *Approver Note: This plan is execution-ready and addresses all major/policy findings.*
