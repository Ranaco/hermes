/**
 * User Controller
 * Handles user profile management and settings
 */

import type { Request, Response } from 'express';
import { asyncHandler, AuthenticationError, ValidationError, ErrorCode, ConflictError } from '@hermes/error-handling';
import getPrismaClient from '../services/prisma.service';
import { hashPassword, verifyPassword, validatePasswordStrength } from '../utils/password';
import { createAuditLog } from '../services/audit.service';

/**
 * Get current user profile
 * GET /api/v1/users/me
 */
export const getCurrentUser = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const prisma = getPrismaClient();

  const user = await prisma.user.findUnique({
    where: { id: req.user.id },
    select: {
      id: true,
      email: true,
      username: true,
      firstName: true,
      lastName: true,
      isEmailVerified: true,
      isTwoFactorEnabled: true,
      requiresMfaForSensitiveOps: true,
      lastLoginAt: true,
      createdAt: true,
      updatedAt: true,
      organizations: {
        include: {
          organization: {
            select: {
              id: true,
              name: true,
              createdAt: true,
            },
          },
        },
      },
    },
  });

  if (!user) {
    throw new AuthenticationError(ErrorCode.USER_NOT_FOUND);
  }

  res.json({
    success: true,
    data: { user },
  });
});

/**
 * Update user profile
 * PATCH /api/v1/users/me
 */
export const updateProfile = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { firstName, lastName, requiresMfaForSensitiveOps } = req.body;

  const prisma = getPrismaClient();

  const updateData: Partial<{ firstName: string | null; lastName: string | null; requiresMfaForSensitiveOps: boolean }> = {};
  if (firstName !== undefined) updateData.firstName = firstName;
  if (lastName !== undefined) updateData.lastName = lastName;
  if (requiresMfaForSensitiveOps !== undefined) updateData.requiresMfaForSensitiveOps = requiresMfaForSensitiveOps;

  const user = await prisma.user.update({
    where: { id: req.user.id },
    data: updateData,
    select: {
      id: true,
      email: true,
      username: true,
      firstName: true,
      lastName: true,
      requiresMfaForSensitiveOps: true,
      updatedAt: true,
    },
  });

  await createAuditLog({
    userId: req.user.id,
    action: 'UPDATE',
    resourceType: 'USER',
    resourceId: req.user.id,
    details: { fields: Object.keys(updateData) },
    ipAddress: req.ip || 'unknown',
    userAgent: req.headers['user-agent'] || 'unknown',
  });

  res.json({
    success: true,
    data: { user },
    message: 'Profile updated successfully',
  });
});

/**
 * Change password
 * POST /api/v1/users/me/password
 */
export const changePassword = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    throw new ValidationError(ErrorCode.VALIDATION_ERROR, 'Current and new password are required');
  }

  const prisma = getPrismaClient();

  const user = await prisma.user.findUnique({
    where: { id: req.user.id },
  });

  if (!user) {
    throw new AuthenticationError(ErrorCode.USER_NOT_FOUND);
  }

  // Verify current password
  const isValid = await verifyPassword(currentPassword, user.passwordHash);
  if (!isValid) {
    throw new AuthenticationError(ErrorCode.INVALID_CREDENTIALS, 'Current password is incorrect');
  }

  // Validate new password strength (throws if invalid)
  validatePasswordStrength(newPassword);

  // Hash new password
  const newPasswordHash = await hashPassword(newPassword);

  // Update password
  await prisma.user.update({
    where: { id: req.user.id },
    data: {
      passwordHash: newPasswordHash,
      passwordChangedAt: new Date(),
    },
  });

  // Invalidate all sessions except current one
  await prisma.session.deleteMany({
    where: {
      userId: req.user.id,
      // Keep sessions from the last hour (current session)
      createdAt: {
        lt: new Date(Date.now() - 60 * 60 * 1000),
      },
    },
  });

  await createAuditLog({
    userId: req.user.id,
    action: 'UPDATE',
    resourceType: 'USER',
    resourceId: req.user.id,
    details: { passwordChanged: true },
    ipAddress: req.ip || 'unknown',
    userAgent: req.headers['user-agent'] || 'unknown',
  });

  res.json({
    success: true,
    message: 'Password changed successfully. Other sessions have been logged out.',
  });
});

/**
 * Request password reset
 * POST /api/v1/users/password/reset-request
 */
export const requestPasswordReset = asyncHandler(async (req: Request, res: Response) => {
  const { email } = req.body;

  if (!email) {
    throw new ValidationError(ErrorCode.VALIDATION_ERROR, 'Email is required');
  }

  const prisma = getPrismaClient();

  const user = await prisma.user.findUnique({
    where: { email: email.toLowerCase() },
  });

  // Don't reveal if user exists or not
  if (!user) {
    res.json({
      success: true,
      message: 'If the email exists, a password reset link will be sent.',
    });
    return;
  }

  // Generate reset token
  const crypto = await import('crypto');
  const resetToken = crypto.randomBytes(32).toString('hex');

  await prisma.passwordReset.create({
    data: {
      userId: user.id,
      token: resetToken,
      expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
    },
  });

  // TODO: Send email with reset link
  // For now, just log it
  console.log(`Password reset token for ${email}: ${resetToken}`);

  await createAuditLog({
    userId: user.id,
    action: 'UPDATE',
    resourceType: 'USER',
    resourceId: user.id,
    details: { passwordResetRequested: true },
    ipAddress: req.ip || 'unknown',
    userAgent: req.headers['user-agent'] || 'unknown',
  });

  res.json({
    success: true,
    message: 'If the email exists, a password reset link will be sent.',
  });
});

/**
 * Reset password with token
 * POST /api/v1/users/password/reset
 */
export const resetPassword = asyncHandler(async (req: Request, res: Response) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    throw new ValidationError(ErrorCode.VALIDATION_ERROR, 'Token and new password are required');
  }

  const prisma = getPrismaClient();

  const resetRequest = await prisma.passwordReset.findFirst({
    where: {
      token,
      expiresAt: { gt: new Date() },
      usedAt: null,
    },
    include: {
      user: true,
    },
  });

  if (!resetRequest) {
    throw new AuthenticationError(ErrorCode.TOKEN_INVALID, 'Invalid or expired reset token');
  }

  // Validate password strength (throws if invalid)
  validatePasswordStrength(newPassword);

  // Hash new password
  const passwordHash = await hashPassword(newPassword);

  // Update password and mark reset as used
  await prisma.$transaction([
    prisma.user.update({
      where: { id: resetRequest.userId },
      data: {
        passwordHash,
        passwordChangedAt: new Date(),
        consecutiveFailedLogins: 0,
        lockedUntil: null,
      },
    }),
    prisma.passwordReset.update({
      where: { id: resetRequest.id },
      data: { usedAt: new Date() },
    }),
    // Invalidate all sessions
    prisma.session.deleteMany({
      where: { userId: resetRequest.userId },
    }),
  ]);

  await createAuditLog({
    userId: resetRequest.userId,
    action: 'UPDATE',
    resourceType: 'USER',
    resourceId: resetRequest.userId,
    details: { passwordReset: true },
    ipAddress: req.ip || 'unknown',
    userAgent: req.headers['user-agent'] || 'unknown',
  });

  res.json({
    success: true,
    message: 'Password reset successfully. Please log in with your new password.',
  });
});

/**
 * Verify email
 * POST /api/v1/users/verify-email
 */
export const verifyEmail = asyncHandler(async (req: Request, res: Response) => {
  const { token } = req.body;

  if (!token) {
    throw new ValidationError(ErrorCode.VALIDATION_ERROR, 'Verification token is required');
  }

  const prisma = getPrismaClient();

  // Find email verification record
  const verification = await prisma.emailVerification.findFirst({
    where: {
      token,
      expiresAt: { gt: new Date() },
      isVerified: false,
    },
  });

  if (!verification) {
    throw new AuthenticationError(ErrorCode.TOKEN_INVALID, 'Invalid or expired verification token');
  }

  // Update user and mark verification as complete
  await prisma.$transaction([
    prisma.user.update({
      where: { id: verification.userId },
      data: { isEmailVerified: true },
    }),
    prisma.emailVerification.update({
      where: { id: verification.id },
      data: { isVerified: true, verifiedAt: new Date() },
    }),
  ]);

  await createAuditLog({
    userId: verification.userId,
    action: 'UPDATE',
    resourceType: 'USER',
    resourceId: verification.userId,
    details: { emailVerified: true },
    ipAddress: req.ip || 'unknown',
    userAgent: req.headers['user-agent'] || 'unknown',
  });

  res.json({
    success: true,
    message: 'Email verified successfully',
  });
});

/**
 * Resend email verification
 * POST /api/v1/users/resend-verification
 */
export const resendVerification = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const prisma = getPrismaClient();

  const user = await prisma.user.findUnique({
    where: { id: req.user.id },
  });

  if (!user) {
    throw new AuthenticationError(ErrorCode.USER_NOT_FOUND);
  }

  if (user.isEmailVerified) {
    throw new ConflictError(ErrorCode.USER_ALREADY_EXISTS, 'Email is already verified');
  }

  const crypto = await import('crypto');
  const token = crypto.randomBytes(32).toString('hex');

  // Create new email verification record
  await prisma.emailVerification.create({
    data: {
      userId: req.user.id,
      email: user.email,
      token,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
    },
  });

  // TODO: Send email with verification link
  console.log(`Email verification token for ${user.email}: ${token}`);

  res.json({
    success: true,
    message: 'Verification email sent',
  });
});

/**
 * Delete account
 * DELETE /api/v1/users/me
 */
export const deleteAccount = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { password, mfaToken } = req.body;

  if (!password) {
    throw new ValidationError(ErrorCode.VALIDATION_ERROR, 'Password is required');
  }

  const prisma = getPrismaClient();

  const user = await prisma.user.findUnique({
    where: { id: req.user.id },
  });

  if (!user) {
    throw new AuthenticationError(ErrorCode.USER_NOT_FOUND);
  }

  // Verify password
  const isValid = await verifyPassword(password, user.passwordHash);
  if (!isValid) {
    throw new AuthenticationError(ErrorCode.INVALID_CREDENTIALS, 'Invalid password');
  }

  // Verify MFA if enabled
  if (user.isTwoFactorEnabled) {
    if (!mfaToken) {
      throw new AuthenticationError(ErrorCode.MFA_REQUIRED);
    }

    const { validateMfaToken } = await import('../utils/mfa');
    const mfaResult = await validateMfaToken(user.twoFactorSecret, user.backupCodes, mfaToken);
    if (!mfaResult.valid) {
      throw new AuthenticationError(ErrorCode.MFA_INVALID);
    }
  }

  // Check if user is the only owner of any organizations
  const ownerships = await prisma.organizationMember.findMany({
    where: {
      userId: req.user.id,
      role: 'OWNER',
    },
    include: {
      organization: {
        include: {
          members: {
            where: { role: 'OWNER' },
          },
        },
      },
    },
  });

  const soloOwnerships = ownerships.filter(o => o.organization.members.length === 1);
  if (soloOwnerships.length > 0) {
    throw new ConflictError(
      ErrorCode.PERMISSION_DENIED,
      'You are the only owner of one or more organizations. Transfer ownership or delete the organizations first.'
    );
  }

  await createAuditLog({
    userId: req.user.id,
    action: 'DELETE',
    resourceType: 'USER',
    resourceId: req.user.id,
    details: { accountDeleted: true },
    ipAddress: req.ip || 'unknown',
    userAgent: req.headers['user-agent'] || 'unknown',
  });

  // Delete user (cascade will handle related records)
  await prisma.user.delete({
    where: { id: req.user.id },
  });

  res.json({
    success: true,
    message: 'Account deleted successfully',
  });
});
