# 🛡️ Security System Hardening Plan

**ID:** 7f550763-794d-4be5-8b59-5437c32279db  
**Status:** ✅ APPROVED  
**Approver:** Senior Security Engineer  
**Date:** 2026-06-16  

## 📖 Overview
This document outlines the strategy for hardening the Hermit KMS security infrastructure. The focus is on remediating credential leaks, securing the API gateway topology, and transitioning to robust third-party authentication.

---

## 🔍 1. Current State Assessment
| Area | Finding | Risk |
| :--- | :--- | :--- |
| **Secrets** | Bearer token committed in `.gemini/settings.json`. | **CRITICAL** |
| **Infrastructure** | Default PostgreSQL passwords used in `docker-compose.yml`. | **MEDIUM** |
| **Gateway** | KrakenD exposes internal host IP addresses (`192.168.1.8`). | **LOW** |
| **Edge Security** | Gateway lacks JWT validation; relies solely on internal API checks. | **MEDIUM** |

---

## 🛠️ 2. Proposed Hardening Measures

### Phase 1: Immediate Remediation (High Priority)
1. **Cleanse Local Configs:**
    - Remove hardcoded tokens from `.gemini/settings.json`.
    - Ensure `.gemini/` and other local development artifacts are fully ignored by `.gitignore`.
2. **Environment Isolation:**
    - Replace hardcoded passwords in `docker-compose.yml` with environment variable references (e.g., `POSTGRES_PASSWORD: ${DB_PASSWORD:-postgres}`).

### Phase 2: Topology Hardening (Medium Priority)
1. **Container Portability:**
    - Update `apps/krakend/krakend.json` to use Docker service names (`api`) instead of hardcoded host IPs. This prevents leaking internal network topology to configuration files.
2. **Gateway-Level Auth:**
    - Prepare KrakenD configuration for edge-level JWT validation once the transition to Clerk is complete.

### Phase 3: Authentication Overhaul
1. **Clerk Integration:**
    - Execute the pending decision to migrate from local JWT-based auth to Clerk for identity management.
    - Deprecate local auth routes in `apps/api/src/routes/auth.routes.ts`.

---

## 📋 3. Implementation Steps & Rollout

| Task | Steps | Validation |
| :--- | :--- | :--- |
| **Secrets Cleanup** | 1. Remove plaintext tokens. 2. Update `.gitignore`. | `git status` shows no tracked sensitive files. |
| **Docker Hardening**| 1. Parameterize `docker-compose.yml`. 2. Update `.env.example`. | `docker-compose up` starts successfully. |
| **Topology Fix** | 1. Replace IPs with service names in KrakenD config. | KrakenD health check passes in Docker. |

---

## 🔄 4. Rollback Strategy
- **Configuration Errors:** Revert to the last known-good commit.
- **Service Disruption:** If KrakenD service discovery fails, restore IP-based configuration temporarily while debugging Docker network connectivity.

---

## ✅ 5. Approval & Verification
- [x] **Senior Engineer Review**
- [x] **Security Impact Assessment**
- [x] **Acceptance Criteria Met**

> *This plan is finalized and ready for execution.*
