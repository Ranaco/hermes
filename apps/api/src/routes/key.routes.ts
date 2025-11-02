/**
 * Key Routes
 */

import { Router } from 'express';
import * as keyController from '../controllers/key.controller';
import { authenticate } from '../middleware/auth';
import { cryptoOperationsRateLimiter, generalRateLimiter } from '../middleware/security';
import { validate } from '../validators/validation.middleware';
import {
  createKeySchema,
  getKeysQuerySchema,
  keyIdParamSchema,
  encryptDataSchema,
  decryptDataSchema,
  batchEncryptSchema,
  batchDecryptSchema,
  rotateKeySchema,
} from '../validators/key.validator';

const router = Router();

// All key routes require authentication
router.use(authenticate);

/**
 * Key management
 */
router.post('/', generalRateLimiter, validate({ body: createKeySchema }), keyController.createKey);
router.get('/', validate({ query: getKeysQuerySchema }), keyController.getKeys);
router.get('/:id', validate({ params: keyIdParamSchema }), keyController.getKey);
router.post('/:id/rotate', generalRateLimiter, validate({ params: keyIdParamSchema, body: rotateKeySchema }), keyController.rotateKey);
router.delete('/:id', validate({ params: keyIdParamSchema }), keyController.deleteKey);

/**
 * Cryptographic operations
 */
router.post('/:id/encrypt', cryptoOperationsRateLimiter, validate({ params: keyIdParamSchema, body: encryptDataSchema }), keyController.encryptData);
router.post('/:id/decrypt', cryptoOperationsRateLimiter, validate({ params: keyIdParamSchema, body: decryptDataSchema }), keyController.decryptData);
router.post('/:id/encrypt/batch', cryptoOperationsRateLimiter, validate({ params: keyIdParamSchema, body: batchEncryptSchema }), keyController.batchEncrypt);
router.post('/:id/decrypt/batch', cryptoOperationsRateLimiter, validate({ params: keyIdParamSchema, body: batchDecryptSchema }), keyController.batchDecrypt);

export default router;
