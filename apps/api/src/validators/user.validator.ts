/**
 * User Validation Schemas
 */

import { z } from 'zod';

// UUID validation
const uuidSchema = z.string().uuid('Invalid UUID format');

// Email validation
const emailSchema = z.string().email('Invalid email format').toLowerCase();

// Update user profile schema
export const updateProfileSchema = z.object({
  firstName: z.string().min(1).max(50, 'First name must be at most 50 characters').optional(),
  lastName: z.string().min(1).max(50, 'Last name must be at most 50 characters').optional(),
  username: z.string().min(3, 'Username must be at least 3 characters').max(30, 'Username must be at most 30 characters').regex(/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, underscores, and hyphens').optional(),
});

// Update user settings schema
export const updateUserSettingsSchema = z.object({
  requiresMfaForSensitiveOps: z.boolean().optional(),
  email: emailSchema.optional(),
});

// Get users query schema
export const getUsersQuerySchema = z.object({
  page: z.string().regex(/^\d+$/).transform(Number).optional(),
  limit: z.string().regex(/^\d+$/).transform(Number).optional(),
  search: z.string().max(100).optional(),
  organizationId: uuidSchema.optional(),
});

// User ID param schema
export const userIdParamSchema = z.object({
  id: uuidSchema,
});

// Deactivate user schema
export const deactivateUserSchema = z.object({
  reason: z.string().max(500, 'Reason must be at most 500 characters').optional(),
});
