# Device Management Update

## Summary

Updated the authentication system to automatically handle device fingerprinting and management based on request metadata (IP address, user agent, etc.) instead of requiring users to manually provide device information.

## Changes Made

### 1. New Utility: `device.ts` ✅

Created `apps/api/src/utils/device.ts` with the following functions:

- **`generateDeviceFingerprint(req, customFingerprint?)`**
  - Automatically generates a unique device fingerprint from request headers
  - Uses User-Agent, Accept-Language, and Accept-Encoding headers
  - Creates SHA-256 hash for consistent identification
  - Falls back to custom fingerprint if provided in request body

- **`extractDeviceInfo(req)`**
  - Extracts device information from request
  - Determines device type (Mobile, Tablet, Windows PC, Mac, Linux, Postman, cURL, etc.)
  - Captures IP address and full user agent string

- **`getOrCreateDevice(userId, req, customFingerprint?)`**
  - Finds existing device by user + fingerprint combination
  - Creates new device if not found (marked as untrusted by default)
  - Updates device metadata (IP, user agent, last used time) on each login
  - Returns device object for session creation

- **`createSession(userId, deviceId, refreshToken, expiresAt)`**
  - Helper function to create a new session
  - Links session to user and device
  - Sets expiration and validity status

### 2. Updated Auth Controller ✅

Modified `apps/api/src/controllers/auth.controller.ts`:

#### Register Endpoint
- **Before**: Hardcoded device ID `'00000000-0000-0000-0000-000000000000'` (caused foreign key constraint error)
- **After**: Calls `getOrCreateDevice()` to automatically create device from request metadata
- Optionally accepts `deviceFingerprint` in request body for custom fingerprinting

#### Login Endpoint
- **Before**: Manual device creation with duplicate code
- **After**: Uses `getOrCreateDevice()` utility for consistent device management
- Automatically updates device info on each login

#### Benefits
- No more foreign key constraint errors
- Consistent device tracking across all auth endpoints
- Automatic device metadata updates
- Support for device trust levels (future feature)
- Better audit trail with accurate device information

## Database Schema

The existing `Device` and `Session` models work perfectly with these changes:

```prisma
model Device {
  id                String   @id @default(uuid())
  userId            String
  name              String?  // Auto-populated (e.g., "Windows PC", "Postman")
  fingerprint       String   // Auto-generated SHA-256 hash
  lastUsedAt        DateTime @updatedAt
  isTrusted         Boolean  @default(false)
  userAgent         String?  // Auto-captured from request
  ipAddress         String?  // Auto-captured from request
  createdAt         DateTime @default(now())
  user              User     @relation(...)
  sessions          Session[]
  @@unique([userId, fingerprint])
}

model Session {
  id                String   @id @default(uuid())
  userId            String
  deviceId          String   // Now properly linked to real Device records
  refreshToken      String   @unique
  expiresAt         DateTime
  isValid           Boolean  @default(true)
  ...
}
```

## Testing

### Register a User
```powershell
curl -X POST http://localhost:3000/api/v1/auth/register `
  -H "Content-Type: application/json" `
  -d '{
    "email": "admin@hermes.local",
    "password": "SecurePass123!@#",
    "name": "Admin User"
  }'
```

**What happens:**
1. User is created
2. Device fingerprint is auto-generated from your request headers
3. Device record is created with name "Postman" (or "Windows PC", etc.)
4. Session is created and linked to the device
5. Access and refresh tokens are returned

### Login
```powershell
curl -X POST http://localhost:3000/api/v1/auth/login `
  -H "Content-Type: application/json" `
  -d '{
    "email": "admin@hermes.local",
    "password": "SecurePass123!@#"
  }'
```

**What happens:**
1. User is authenticated
2. Device fingerprint is auto-generated
3. Existing device is found and updated (IP, last used time)
4. New session is created for this device
5. Tokens are returned

### Custom Device Fingerprint (Optional)

You can still provide a custom fingerprint if needed:

```powershell
curl -X POST http://localhost:3000/api/v1/auth/register `
  -H "Content-Type: application/json" `
  -d '{
    "email": "admin@hermes.local",
    "password": "SecurePass123!@#",
    "name": "Admin User",
    "deviceFingerprint": "my-custom-fingerprint-123"
  }'
```

## Security Features

### Automatic Device Tracking
- Each unique device gets a separate record
- Sessions are tied to specific devices
- Can revoke access per device

### Trust Levels
- New devices are marked as `isTrusted: false`
- Future: Can implement device verification flow
- Future: Can require MFA for untrusted devices

### Audit Trail
- Every login/register creates/updates device record
- IP addresses and user agents are logged
- `lastUsedAt` timestamp tracks device activity

## Future Enhancements

1. **Device Management Endpoints**
   - GET `/api/v1/devices` - List user's devices
   - DELETE `/api/v1/devices/:id` - Revoke device access
   - PATCH `/api/v1/devices/:id/trust` - Mark device as trusted

2. **Enhanced Security**
   - Require email verification for new devices
   - Send notifications when new device is added
   - Automatic device cleanup (remove inactive devices after X days)

3. **Device Limits**
   - Limit number of active devices per user
   - Automatic cleanup of oldest sessions when limit reached

## Migration Notes

No database migration required! The existing schema already supports all these features. The changes only affect the application logic.

## Rollback

If you need to rollback:
1. Remove the `import { getOrCreateDevice, createSession } from '../utils/device'` line
2. Restore the old hardcoded device ID approach
3. Delete `apps/api/src/utils/device.ts`
4. Rebuild: `yarn build`

However, this is not recommended as it will reintroduce the foreign key constraint bug.
