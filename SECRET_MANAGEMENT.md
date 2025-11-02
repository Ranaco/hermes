# 🔐 Secret Management System

## Overview

Hermes KMS provides a **three-tier security model** for storing and accessing encrypted secrets using HashiCorp Vault's Transit Engine for encryption.

## Three-Tier Security Model

### 1. Secret-Level Password (Highest Security) 🔴
- Requires a password specific to **this secret only**
- Most secure option for highly sensitive data
- Use for: API keys, database passwords, private keys, certificates

```javascript
// Creating a secret with its own password
POST /api/v1/secrets
{
  "name": "prod-db-password",
  "value": "super-secret-password-123",
  "password": "SecretPass123!",  // <-- Secret-level password
  "vaultId": "...",
  "keyId": "..."
}

// Revealing requires the secret password
POST /api/v1/secrets/:id/reveal
{
  "password": "SecretPass123!"  // <-- Must provide secret password
}
```

### 2. Vault-Level Password (Medium Security) 🟡
- Requires the **vault password** (if vault has one)
- Applies to all secrets in the vault that don't have their own password
- Use for: Team secrets, environment variables, configuration

```javascript
// Creating a vault with a password
POST /api/v1/vaults
{
  "name": "Production Vault",
  "password": "VaultPass123!"  // <-- Vault-level password
}

// Creating a secret without its own password (inherits vault protection)
POST /api/v1/secrets
{
  "name": "api-endpoint",
  "value": "https://api.example.com",
  "vaultId": "...",  // Vault with password
  "keyId": "..."
  // No password field = uses vault password
}

// Revealing requires vault password
POST /api/v1/secrets/:id/reveal
{
  "vaultPassword": "VaultPass123!"  // <-- Provide vault password
}
```

### 3. Authentication Only (Basic Security) 🟢
- Requires only valid **authentication** (login)
- No additional passwords needed
- Use for: Less sensitive data, internal documentation, non-critical configs

```javascript
// Creating a vault without password
POST /api/v1/vaults
{
  "name": "Dev Vault"
  // No password = auth-only protection
}

// Creating a secret without password in password-less vault
POST /api/v1/secrets
{
  "name": "dev-api-key",
  "value": "dev-key-123",
  "vaultId": "...",  // Vault without password
  "keyId": "..."
  // No password = auth-only protection
}

// Revealing requires only authentication
POST /api/v1/secrets/:id/reveal
{
  // No password needed, just valid Bearer token
}
```

## Security Flow Chart

```
┌─────────────────────────────────────────┐
│         User Wants to Access Secret      │
└──────────────┬──────────────────────────┘
               │
               ▼
        ┌─────────────┐
        │ Authenticated?│──No──► 401 Unauthorized
        └──────┬───────┘
               │ Yes
               ▼
     ┌──────────────────┐
     │ Has Permission?  │──No──► 403 Forbidden
     └────────┬─────────┘
              │ Yes
              ▼
   ┌─────────────────────────┐
   │ Secret has password?     │──Yes──┐
   └───────┬─────────────────┘       │
           │ No                       ▼
           ▼                  ┌──────────────────┐
┌──────────────────────┐     │ Provide secret   │
│ Vault has password?   │     │ password?        │
└───┬──────────────────┘     └──────┬───────────┘
    │ No            Yes              │ Yes
    │               │                │
    │               ▼                │
    │      ┌──────────────────┐     │
    │      │ Provide vault    │     │
    │      │ password?        │     │
    │      └──────┬───────────┘     │
    │             │ Yes              │
    │             │                  │
    └─────────────┴──────────────────┘
                  │
                  ▼
        ┌──────────────────────┐
        │ Decrypt with Vault   │
        │ Transit Engine       │
        └──────────┬───────────┘
                   │
                   ▼
          ┌────────────────┐
          │ Return Secret  │
          │ Value          │
          └────────────────┘
```

## Key Features

### ✅ Encrypted Storage
- All secret values encrypted using **HashiCorp Vault Transit Engine**
- Encryption keys never leave Vault
- Industry-standard AES-256-GCM encryption

### ✅ Version Control
- Every secret update creates a new version
- Full version history with commit messages
- Ability to view previous versions
- Audit trail of all changes

### ✅ Access Tracking
- Last accessed timestamp
- Access count per secret
- Complete audit logs
- IP address and user agent tracking

### ✅ Expiration Support
- Set expiration dates for secrets
- Automatic validation on access
- Prevents access to expired secrets

### ✅ Metadata & Tagging
- Custom metadata (JSON)
- Tags for organization
- Search and filter capabilities

## API Endpoints

### Create Secret
```http
POST /api/v1/secrets
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "secret-name",
  "description": "Optional description",
  "value": "The actual secret value",
  "vaultId": "vault-uuid",
  "keyId": "key-uuid",
  "password": "OptionalSecretPassword",  // Secret-level protection
  "metadata": {
    "environment": "production",
    "owner": "team-api"
  },
  "tags": ["production", "api-key"],
  "expiresAt": "2026-01-01T00:00:00Z"  // Optional
}
```

### List Secrets
```http
GET /api/v1/secrets?vaultId=<vault-uuid>
Authorization: Bearer <token>
```

Returns metadata only (no secret values).

### Reveal Secret
```http
POST /api/v1/secrets/:id/reveal
Authorization: Bearer <token>
Content-Type: application/json

{
  "password": "SecretPassword",       // If secret has password
  "vaultPassword": "VaultPassword",   // If vault has password
  "versionNumber": 2                  // Optional: specific version
}
```

### Update Secret
```http
PUT /api/v1/secrets/:id
Authorization: Bearer <token>
Content-Type: application/json

{
  "value": "New secret value",        // Creates new version
  "description": "Updated desc",      // Optional
  "password": "NewPassword",          // Optional: update password
  "commitMessage": "Rotated key",     // Optional: version message
  "expiresAt": "2026-12-31T..."      // Optional: update expiration
}
```

### Get Version History
```http
GET /api/v1/secrets/:id/versions
Authorization: Bearer <token>
```

### Delete Secret
```http
DELETE /api/v1/secrets/:id
Authorization: Bearer <token>
```

Requires **ADMIN** permission on vault.

## Permission Levels

Secrets inherit vault permissions:

- **VIEW**: Can list secrets (metadata only)
- **USE**: Can reveal secret values
- **EDIT**: Can create/update secrets
- **ADMIN**: Full control including deletion

## Best Practices

### 🔴 Use Secret-Level Passwords For:
- Production database passwords
- API keys for external services
- Private keys and certificates
- OAuth client secrets
- Master encryption keys

### 🟡 Use Vault-Level Passwords For:
- Team shared secrets
- Environment-specific configs
- Service account credentials
- Internal API endpoints

### 🟢 Use Auth-Only For:
- Development secrets
- Public API endpoints
- Non-sensitive configuration
- Documentation links

### General Best Practices:
1. **Rotate Regularly**: Update secrets periodically
2. **Use Commit Messages**: Document why secrets were changed
3. **Set Expiration Dates**: For temporary credentials
4. **Tag Everything**: Makes organization easier
5. **Monitor Access**: Review audit logs regularly
6. **Limit Permissions**: Grant minimum required access
7. **Use Strong Passwords**: For secret and vault passwords

## Example Use Cases

### Storing AWS Credentials
```javascript
POST /api/v1/secrets
{
  "name": "aws-prod-access-key",
  "description": "AWS Production IAM Access Key",
  "value": "AKIAIOSFODNN7EXAMPLE",
  "password": "StrongPassword123!",
  "vaultId": "prod-vault-id",
  "keyId": "master-key-id",
  "tags": ["aws", "production", "iam"],
  "metadata": {
    "region": "us-east-1",
    "account": "123456789012",
    "service": "ec2"
  },
  "expiresAt": "2025-12-31T23:59:59Z"
}
```

### Storing Database Connection String
```javascript
POST /api/v1/secrets
{
  "name": "postgres-connection",
  "description": "Production PostgreSQL Connection",
  "value": "postgresql://user:password@prod-db.example.com:5432/myapp",
  "password": "DatabaseSecretPass",
  "vaultId": "prod-vault-id",
  "keyId": "db-key-id",
  "tags": ["database", "postgresql", "production"],
  "metadata": {
    "host": "prod-db.example.com",
    "database": "myapp",
    "pool_size": 20
  }
}
```

### Storing API Key with Auto-Rotation
```javascript
// Initial creation
POST /api/v1/secrets
{
  "name": "stripe-api-key",
  "value": "sk_live_xxxxxxxxxxxxx",
  "password": "StripeSecretPass",
  "vaultId": "payment-vault-id",
  "keyId": "payment-key-id",
  "expiresAt": "2025-12-01T00:00:00Z"
}

// Later: Rotate the key
PUT /api/v1/secrets/:id
{
  "value": "sk_live_yyyyyyyyyyyyy",
  "commitMessage": "Monthly rotation - November 2025",
  "expiresAt": "2025-13-01T00:00:00Z"
}
```

## Error Responses

### Secret Password Required
```json
{
  "success": false,
  "error": {
    "code": "SECRET_PASSWORD_REQUIRED",
    "message": "This secret is protected with a password"
  },
  "requiresPassword": "secret"
}
```

### Vault Password Required
```json
{
  "success": false,
  "error": {
    "code": "VAULT_PASSWORD_REQUIRED",
    "message": "This vault is protected with a password"
  },
  "requiresPassword": "vault"
}
```

### Invalid Password
```json
{
  "success": false,
  "error": {
    "code": "AUTH_1002",
    "message": "Invalid secret password",
    "statusCode": 401
  }
}
```

### Secret Expired
```json
{
  "success": false,
  "error": {
    "code": "SHARE_6009",
    "message": "This secret has expired",
    "statusCode": 410
  }
}
```

## Technical Architecture

```
┌──────────────┐
│   Client     │
└──────┬───────┘
       │ HTTPS
       ▼
┌──────────────┐
│  API Server  │
│  (Express)   │
└──────┬───────┘
       │
       ├──────► Check Auth (JWT)
       │
       ├──────► Check Permissions (Prisma)
       │
       ├──────► Verify Password (bcrypt)
       │
       ▼
┌──────────────────┐
│ HashiCorp Vault  │
│ Transit Engine   │
└──────┬───────────┘
       │ Encrypt/Decrypt
       ▼
┌──────────────────┐
│   PostgreSQL     │
│ (Encrypted Data) │
└──────────────────┘
```

### Data Flow:
1. **Create Secret**: Value → Vault Transit (encrypt) → Store ciphertext in DB
2. **Reveal Secret**: Ciphertext from DB → Vault Transit (decrypt) → Return plaintext
3. **Passwords**: Hashed with bcrypt (12 rounds), stored in DB
4. **Audit**: All access logged with timestamp, IP, user agent

## Comparison with Direct Key Encryption

| Feature | Secret Management | Direct Key Encryption |
|---------|------------------|----------------------|
| Storage | Persistent in DB | Ephemeral (you manage) |
| Versioning | ✅ Built-in | ❌ Manual |
| Password Protection | ✅ 3-tier model | ❌ No |
| Audit Logging | ✅ Comprehensive | ⚠️ Basic |
| Access Tracking | ✅ Yes | ❌ No |
| Expiration | ✅ Automatic | ❌ Manual |
| Metadata | ✅ JSON + Tags | ❌ No |
| Use Case | **Store secrets** | **Encrypt data** |

## Security Considerations

1. **Encryption at Rest**: All secret values encrypted with Vault Transit
2. **Encryption in Transit**: HTTPS required in production
3. **Password Hashing**: bcrypt with 12 rounds
4. **Access Control**: Permission-based + optional passwords
5. **Audit Trail**: Complete logging of all access
6. **Version Control**: Cannot modify past versions (immutable)
7. **Expiration**: Automatic enforcement
8. **Rate Limiting**: Prevents brute-force attacks

## Migration from Direct Encryption

If you've been using direct key encryption and want to migrate to secret management:

```javascript
// Old way (direct encryption)
POST /api/v1/keys/:id/encrypt
{ "plaintext": "my-secret" }
// Returns: { "ciphertext": "vault:v1:..." }
// You store and manage the ciphertext

// New way (secret management)
POST /api/v1/secrets
{
  "name": "my-secret-name",
  "value": "my-secret",
  "vaultId": "...",
  "keyId": "...",
  "password": "optional"
}
// Hermes stores the encrypted value and manages it for you

// Later retrieval
POST /api/v1/secrets/:id/reveal
{ "password": "optional" }
// Returns the decrypted value
```

---

**Need Help?** Check the [QUICKSTART.md](./QUICKSTART.md) for step-by-step examples!
