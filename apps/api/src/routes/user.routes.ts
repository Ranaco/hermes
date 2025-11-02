/**
 * User Routes
 */

import { Router } from 'express';
import * as userController from '../controllers/user.controller';
import { authenticate } from '../middleware/auth';
import { sensitiveOperationsRateLimiter } from '../middleware/security';
import { validate } from '../validators/validation.middleware';
import { updateProfileSchema } from '../validators/user.validator';
import {
  changePasswordSchema,
  requestPasswordResetSchema,
  resetPasswordSchema,
  verifyEmailSchema,
} from '../validators/auth.validator';

const router = Router();

/**
 * Public routes
 */
router.post('/password/reset-request', validate({ body: requestPasswordResetSchema }), userController.requestPasswordReset);
router.post('/password/reset', validate({ body: resetPasswordSchema }), userController.resetPassword);
router.post('/verify-email', validate({ body: verifyEmailSchema }), userController.verifyEmail);

/**
 * Protected routes
 */
router.get('/me', authenticate, userController.getCurrentUser);
router.patch('/me', authenticate, validate({ body: updateProfileSchema }), userController.updateProfile);
router.post('/me/password', authenticate, sensitiveOperationsRateLimiter, validate({ body: changePasswordSchema }), userController.changePassword);
router.post('/resend-verification', authenticate, userController.resendVerification);
router.delete('/me', authenticate, sensitiveOperationsRateLimiter, userController.deleteAccount);

export default router;
