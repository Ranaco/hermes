# Hermit KMS: Technical Advantages and Architectural Comparison

## Executive Summary
Hermit is a high-performance, multi-tenant Key Management System (KMS) designed for modern engineering teams. Unlike traditional KMS solutions that often struggle with multi-tenancy or lack developer-centric workflows, Hermit combines the robust security of HashiCorp Vault with a sophisticated metadata layer and an AWS-style IAM policy engine. This report outlines how Hermit works and why it is the superior choice for organizations requiring granular access control, integrated secret sharing, and a developer-first experience.

## 1. How Hermit Works: The Hybrid Architecture
Hermit employs a hybrid architecture that separates "Hard Crypto" from "Metadata and Policy Management."

*   **Encryption Engine:** Hermit utilizes the **HashiCorp Vault Transit Engine** as its cryptographic core. This ensures that master keys never leave a hardened security boundary and that all encryption/decryption operations are performed using industry-standard, audited algorithms.
*   **Metadata & Organization Layer:** While Vault handles the crypto, Hermit uses a **PostgreSQL** backend managed via **Prisma** to store resource metadata, organizational hierarchies, and audit logs. This allows for rich querying and complex relationships that are often slow or impossible in pure Vault installations.
*   **Unified API Gateway:** All operations flow through a high-performance Express/Node.js API that handles authentication, validation (via Zod), and IAM enforcement before interacting with Vault or the database.

## 2. Key Advantages over Traditional KMS

### A. Native Multi-Tenancy & Hierarchical Scoping
Traditional KMS systems like AWS KMS or standard HashiCorp Vault (OSS) are often "flat" or require expensive Enterprise features (Namespaces) for multi-tenancy.
*   **Hermit Advantage:** Multi-tenancy is baked into the core. Resources follow a strict `Organization -> Vault -> Key/Secret` hierarchy. This allows a single Hermit instance to securely serve multiple independent teams or clients with complete logical isolation.

### B. Granular AWS-Style IAM Policy Engine
Most KMS solutions rely on simple RBAC (Role-Based Access Control) with fixed permissions.
*   **Hermit Advantage:** Hermit implements a dynamic **IAM Policy Engine** using JSON-based statements and **Resource URNs**.
    *   **Precision:** Targeted permissions (e.g., `urn:hermit:org:123:vault:abc:secret:*`).
    *   **Flexibility:** Support for custom roles and team-based inheritance.
    *   **Security:** Explicit `DENY` statements always override `ALLOW` statements, matching the security posture of world-class cloud providers.

### C. Three-Tier Secret Protection Model
Standard secrets management usually stops at "Is the user authenticated?".
*   **Hermit Advantage:** Hermit offers three escalating tiers of protection:
    1.  **Identity-Based:** Standard JWT/Auth check.
    2.  **Vault-Level Password:** An additional challenge required to access any secret within a specific vault.
    3.  **Secret-Level Password:** A unique password required for a single, high-sensitivity secret.
    *   *Impact:* This defense-in-depth approach ensures that even a compromised user session cannot reveal "Crown Jewel" secrets without additional, specific knowledge.

### D. Integrated One-Time Secret Sharing
Sharing secrets with external parties (contractors, clients) is a common pain point that leads to "security sprawl" (using external, un-audited tools).
*   **Hermit Advantage:** Hermit includes a built-in **One-Time Secret Sharing** feature.
    *   **Burn-on-Read:** Secrets self-destruct after the first view.
    *   **Auditability:** Every share is logged and tied to the original KMS key.
    *   **Control:** Supports expiration times and optional passphrases.

### E. Developer-First Experience (CLI & Injection)
Traditional KMS often have clunky CLIs that require complex shell scripting to inject secrets into applications.
*   **Hermit Advantage:** The Hermit CLI is built for modern workflows.
    *   **`hermit run`**: Automatically fetches required secrets and injects them as environment variables into a child process without ever writing them to disk.
    *   **Path-Aware Lookup:** High-speed lookup based on organizational structure.

## 3. Comparison Matrix

| Feature | Hermit KMS | HashiCorp Vault (OSS) | AWS KMS / Cloud KMS |
| :--- | :--- | :--- | :--- |
| **Multi-Tenancy** | Native (Org/Vault/Team) | Limited (Namespaces Enterprise only) | Account-scoped only |
| **IAM Model** | AWS-style JSON / URNs | HCL Policies (complex) | Provider IAM (Cloud-locked) |
| **Access Tiers** | 3-Tier (Auth + 2x Passwords) | 1-Tier (Token/Policy) | 1-Tier (IAM/Key Policy) |
| **External Sharing** | Integrated One-Time Links | Not native | Not native |
| **DX / Injection** | Native `hermit run` | Requires sidecars/helper tools | Requires SDK/CLI wrappers |
| **Metadata Search** | Rich (SQL-backed) | Limited (K/V listing) | Basic tags |

## 4. Conclusion
Hermit represents the next generation of Key Management. By abstracting the complexity of raw cryptographic engines and providing a rich, policy-driven management layer, it allows organizations to move faster without sacrificing security. Whether it's the granular IAM engine, the unique three-tier protection model, or the seamless developer experience, Hermit is built to handle the security challenges of modern, distributed engineering teams.
