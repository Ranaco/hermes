/**
 * Authentication Controller
 * Handles user registration, login, logout, MFA, and device management
 */

import type { Request, Response } from 'express';
import { asyncHandler, AuthenticationError, ValidationError, ErrorCode, ConflictError, NotFoundError } from '@hermes/error-handling';
import getPrismaClient from '../services/prisma.service';
import { hashPassword, verifyPassword, validatePasswordStrength } from '../utils/password';
import { generateTokenPair, verifyRefreshToken } from '../utils/jwt';
import { 
  generateTotpSecret, 
  generateTotpQRCode, 
  verifyTotpToken,
  generateBackupCodes,
  hashBackupCode,
  validateMfaToken
} from '../utils/mfa';
import { getOrCreateDevice, createSession } from '../utils/device';
import { auditLog } from '../services/audit.service';
import config from '../config';

/**
 * Register a new user
 * POST /api/v1/auth/register
 */
export const register = asyncHandler(async (req: Request, res: Response) => {
  const { email, password, firstName, lastName, username, organizationName } = req.body;

  // Validate required fields
  if (!email || !password) {
    throw new ValidationError(ErrorCode.VALIDATION_ERROR, 'Email and password are required');
  }

  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    throw new ValidationError(ErrorCode.INVALID_EMAIL, 'Invalid email format');
  }

  // Validate password strength (throws if invalid)
  validatePasswordStrength(password);

  const prisma = getPrismaClient();

  // Check if user already exists
  const existingUser = await prisma.user.findUnique({
    where: { email: email.toLowerCase() },
  });

  if (existingUser) {
    throw new ConflictError(ErrorCode.USER_ALREADY_EXISTS, 'User with this email already exists');
  }

  // Hash password
  const passwordHash = await hashPassword(password);

  // Create user and optionally organization in a transaction
  const result = await prisma.$transaction(async (tx) => {
    // Create user
    const user = await tx.user.create({
      data: {
        email: email.toLowerCase(),
        username: username || email.split('@')[0],
        firstName: firstName || null,
        lastName: lastName || null,
        passwordHash,
      },
      select: {
        id: true,
        email: true,
        username: true,
        firstName: true,
        lastName: true,
        isEmailVerified: true,
        isTwoFactorEnabled: true,
        createdAt: true,
      },
    });

    // Create organization if organizationName provided
    let organization = null;
    if (organizationName) {
      organization = await tx.organization.create({
        data: {
          name: organizationName,
          members: {
            create: {
              userId: user.id,
              role: 'OWNER',
            },
          },
        },
        select: {
          id: true,
          name: true,
        },
      });
    }

    return { user, organization };
  });

  // Generate tokens
  const tokens = generateTokenPair({
    userId: result.user.id,
    email: result.user.email,
    organizationId: result.organization?.id,
  });

  // Get or create device from request
  const device = await getOrCreateDevice(result.user.id, req, req.body.deviceFingerprint);

  // Create session with device
  await createSession(
    result.user.id,
    device.id,
    tokens.refreshToken,
    new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
  );

  // Audit log
  await auditLog.login(result.user.id, req.ip || 'unknown', req.headers['user-agent'] || 'unknown');

  res.status(201).json({
    success: true,
    data: {
      user: result.user,
      organization: result.organization,
      tokens,
    },
    message: 'User registered successfully',
  });
});

/**
 * Login user
 * POST /api/v1/auth/login
 */
export const login = asyncHandler(async (req: Request, res: Response) => {
  const { email, password, mfaToken, deviceFingerprint } = req.body;

  if (!email || !password) {
    throw new ValidationError(ErrorCode.VALIDATION_ERROR, 'Email and password are required');
  }

  const prisma = getPrismaClient();

  // Find user
  const user = await prisma.user.findUnique({
    where: { email: email.toLowerCase() },
    include: {
      organizations: {
        include: {
          organization: true,
        },
      },
    },
  });

  if (!user) {
    await auditLog.loginFailed(email, req.ip || 'unknown', req.headers['user-agent'] || 'unknown', 'User not found');
    throw new AuthenticationError(ErrorCode.INVALID_CREDENTIALS, 'Invalid email or password');
  }

  // Check if account is locked
  if (user.lockedUntil && user.lockedUntil > new Date()) {
    const minutesRemaining = Math.ceil((user.lockedUntil.getTime() - Date.now()) / 60000);
    throw new AuthenticationError(
      ErrorCode.ACCOUNT_LOCKED,
      `Account is locked. Try again in ${minutesRemaining} minutes.`
    );
  }

  // Verify password
  const isPasswordValid = await verifyPassword(password, user.passwordHash);

  if (!isPasswordValid) {
    // Increment failed login attempts
    const failedAttempts = user.consecutiveFailedLogins + 1;
    const shouldLock = failedAttempts >= config.security.maxLoginAttempts;

    await prisma.user.update({
      where: { id: user.id },
      data: {
        consecutiveFailedLogins: failedAttempts,
        lockedUntil: shouldLock
          ? new Date(Date.now() + config.security.lockoutDuration)
          : null,
      },
    });

    await auditLog.loginFailed(email, req.ip || 'unknown', req.headers['user-agent'] || 'unknown', 'Invalid password');

    throw new AuthenticationError(ErrorCode.INVALID_CREDENTIALS, 'Invalid email or password');
  }

  // Check MFA if enabled
  if (user.isTwoFactorEnabled) {
    if (!mfaToken) {
      throw new AuthenticationError(ErrorCode.MFA_REQUIRED, 'MFA token required');
    }

    const mfaResult = await validateMfaToken(user.twoFactorSecret, user.backupCodes, mfaToken);

    if (!mfaResult.valid) {
      await auditLog.loginFailed(email, req.ip || 'unknown', req.headers['user-agent'] || 'unknown', 'Invalid MFA token');
      throw new AuthenticationError(ErrorCode.MFA_INVALID, 'Invalid MFA token');
    }

    // If backup code was used, remove it
    if (mfaResult.usedBackupCode && mfaResult.backupCodeIndex !== undefined) {
      const updatedBackupCodes = [...user.backupCodes];
      updatedBackupCodes.splice(mfaResult.backupCodeIndex, 1);
      await prisma.user.update({
        where: { id: user.id },
        data: { backupCodes: updatedBackupCodes },
      });
    }
  }

  // Reset failed login attempts
  await prisma.user.update({
    where: { id: user.id },
    data: {
      consecutiveFailedLogins: 0,
      lockedUntil: null,
      lastLoginAt: new Date(),
    },
  });

  // Get or create device from request
  const device = await getOrCreateDevice(user.id, req, deviceFingerprint);

  // Get user's primary organization
  const primaryOrg = user.organizations[0]?.organization;

  // Generate tokens
  const tokens = generateTokenPair({
    userId: user.id,
    email: user.email,
    organizationId: primaryOrg?.id,
  });

  // Create session with device
  await createSession(
    user.id,
    device.id,
    tokens.refreshToken,
    new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
  );

  // Audit log
  await auditLog.login(user.id, req.ip || 'unknown', req.headers['user-agent'] || 'unknown');

  res.json({
    success: true,
    data: {
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        isEmailVerified: user.isEmailVerified,
        isTwoFactorEnabled: user.isTwoFactorEnabled,
      },
      organization: primaryOrg ? { id: primaryOrg.id, name: primaryOrg.name } : null,
      device: device ? { id: device.id, isTrusted: device.isTrusted } : null,
      tokens,
    },
  });
});

/**
 * Logout user
 * POST /api/v1/auth/logout
 */
export const logout = asyncHandler(async (req: Request, res: Response) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    throw new ValidationError(ErrorCode.VALIDATION_ERROR, 'Refresh token is required');
  }

  const prisma = getPrismaClient();

  // Delete session
  await prisma.session.deleteMany({
    where: { refreshToken },
  });

  // Audit log
  if (req.user) {
    await auditLog.logout(req.user.id, req.ip || 'unknown', req.headers['user-agent'] || 'unknown');
  }

  res.json({
    success: true,
    message: 'Logged out successfully',
  });
});

/**
 * Refresh access token
 * POST /api/v1/auth/refresh
 */
export const refreshToken = asyncHandler(async (req: Request, res: Response) => {
  const { refreshToken: token } = req.body;

  if (!token) {
    throw new ValidationError(ErrorCode.VALIDATION_ERROR, 'Refresh token is required');
  }

  // Verify refresh token
  const payload = verifyRefreshToken(token);

  const prisma = getPrismaClient();

  // Check if session exists and is valid
  const session = await prisma.session.findFirst({
    where: {
      refreshToken: token,
      userId: payload.userId,
      expiresAt: { gt: new Date() },
    },
    include: {
      user: {
        include: {
          organizations: {
            include: {
              organization: true,
            },
          },
        },
      },
    },
  });

  if (!session) {
    throw new AuthenticationError(ErrorCode.TOKEN_INVALID, 'Invalid or expired refresh token');
  }

  // Generate new token pair
  const primaryOrg = session.user.organizations[0]?.organization;
  const tokens = generateTokenPair({
    userId: session.user.id,
    email: session.user.email,
    organizationId: primaryOrg?.id,
  });

  // Update session with new refresh token
  await prisma.session.update({
    where: { id: session.id },
    data: {
      refreshToken: tokens.refreshToken,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    },
  });

  res.json({
    success: true,
    data: { tokens },
  });
});

/**
 * Setup MFA (get QR code)
 * POST /api/v1/auth/mfa/setup
 */
export const setupMfa = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const prisma = getPrismaClient();

  // Check if MFA is already enabled
  const user = await prisma.user.findUnique({
    where: { id: req.user.id },
    select: { isTwoFactorEnabled: true, email: true, firstName: true, lastName: true },
  });

  if (!user) {
    throw new NotFoundError(ErrorCode.USER_NOT_FOUND, 'User not found');
  }

  if (user.isTwoFactorEnabled) {
    throw new ConflictError(ErrorCode.USER_ALREADY_EXISTS, 'MFA is already enabled');
  }

  // Generate TOTP secret
  const totpData = generateTotpSecret(user.email);

  // Generate QR code
  const qrCode = await generateTotpQRCode(totpData.otpauthUrl);

  // Store secret temporarily (not enabled yet)
  await prisma.user.update({
    where: { id: req.user.id },
    data: {
      twoFactorSecret: totpData.secret,
      // Don't enable yet - wait for verification
    },
  });

  res.json({
    success: true,
    data: {
      secret: totpData.secret,
      qrCode,
    },
    message: 'Scan the QR code with your authenticator app, then verify with a token to enable MFA',
  });
});

/**
 * Enable MFA (verify and activate)
 * POST /api/v1/auth/mfa/enable
 */
export const enableMfa = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { token } = req.body;

  if (!token) {
    throw new ValidationError(ErrorCode.VALIDATION_ERROR, 'MFA token is required');
  }

  const prisma = getPrismaClient();

  const user = await prisma.user.findUnique({
    where: { id: req.user.id },
    select: {
      twoFactorSecret: true,
      isTwoFactorEnabled: true,
    },
  });

  if (!user) {
    throw new NotFoundError(ErrorCode.USER_NOT_FOUND, 'User not found');
  }

  if (user.isTwoFactorEnabled) {
    throw new ConflictError(ErrorCode.USER_ALREADY_EXISTS, 'MFA is already enabled');
  }

  if (!user.twoFactorSecret) {
    throw new ValidationError(ErrorCode.VALIDATION_ERROR, 'MFA setup not initiated. Call /mfa/setup first');
  }

  // Verify token
  const isValid = verifyTotpToken(user.twoFactorSecret, token);

  if (!isValid) {
    throw new AuthenticationError(ErrorCode.MFA_INVALID, 'Invalid MFA token');
  }

  // Generate backup codes
  const backupCodes = generateBackupCodes();
  const hashedBackupCodes = await Promise.all(
    backupCodes.map(code => hashBackupCode(code))
  );

  // Enable MFA and store backup codes
  await prisma.user.update({
    where: { id: req.user.id },
    data: {
      isTwoFactorEnabled: true,
      backupCodes: hashedBackupCodes,
    },
  });

  // Audit log
  await auditLog.enable2FA(req.user.id, 'TOTP');

  res.json({
    success: true,
    data: {
      backupCodes,
    },
    message: 'MFA enabled successfully. Save these backup codes in a secure location.',
  });
});

/**
 * Disable MFA
 * POST /api/v1/auth/mfa/disable
 */
export const disableMfa = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { password, mfaToken } = req.body;

  if (!password || !mfaToken) {
    throw new ValidationError(ErrorCode.VALIDATION_ERROR, 'Password and MFA token are required');
  }

  const prisma = getPrismaClient();

  const user = await prisma.user.findUnique({
    where: { id: req.user.id },
  });

  if (!user) {
    throw new NotFoundError(ErrorCode.USER_NOT_FOUND, 'User not found');
  }

  if (!user.isTwoFactorEnabled) {
    throw new ValidationError(ErrorCode.VALIDATION_ERROR, 'MFA is not enabled');
  }

  // Verify password
  const isPasswordValid = await verifyPassword(password, user.passwordHash);
  if (!isPasswordValid) {
    throw new AuthenticationError(ErrorCode.INVALID_CREDENTIALS, 'Invalid password');
  }

  // Verify MFA token
  const mfaResult = await validateMfaToken(user.twoFactorSecret, user.backupCodes, mfaToken);
  if (!mfaResult.valid) {
    throw new AuthenticationError(ErrorCode.MFA_INVALID, 'Invalid MFA token');
  }

  // Disable MFA
  await prisma.user.update({
    where: { id: req.user.id },
    data: {
      isTwoFactorEnabled: false,
      twoFactorSecret: null,
      backupCodes: [],
    },
  });

  // Audit log
  await auditLog.disable2FA(req.user.id);

  res.json({
    success: true,
    message: 'MFA disabled successfully',
  });
});

/**
 * Get user's devices
 * GET /api/v1/auth/devices
 */
export const getDevices = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const prisma = getPrismaClient();

  const devices = await prisma.device.findMany({
    where: { userId: req.user.id },
    select: {
      id: true,
      name: true,
      fingerprint: true,
      isTrusted: true,
      lastUsedAt: true,
      ipAddress: true,
      createdAt: true,
    },
    orderBy: { lastUsedAt: 'desc' },
  });

  res.json({
    success: true,
    data: { devices },
  });
});

/**
 * Remove a device
 * DELETE /api/v1/auth/devices/:id
 */
export const removeDevice = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { id } = req.params;

  const prisma = getPrismaClient();

  // Check if device exists and belongs to user
  const device = await prisma.device.findFirst({
    where: {
      id,
      userId: req.user.id,
    },
  });

  if (!device) {
    throw new NotFoundError(ErrorCode.USER_NOT_FOUND, 'Device not found');
  }

  // Delete device
  await prisma.device.delete({
    where: { id },
  });

  // Audit log
  await auditLog.removeDevice(req.user.id, id);

  res.json({
    success: true,
    message: 'Device removed successfully',
  });
});
