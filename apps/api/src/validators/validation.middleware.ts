/**
 * Validation Middleware
 * Validates request body, query, and params using Zod schemas
 */

import type { Request, Response, NextFunction } from 'express';
import { z, ZodError } from 'zod';
import { ValidationError, ErrorCode } from '@hermes/error-handling';

export interface ValidationSchemas {
  body?: z.ZodSchema;
  query?: z.ZodSchema;
  params?: z.ZodSchema;
}

/**
 * Validate request using Zod schemas
 */
export const validate = (schemas: ValidationSchemas) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Validate body
      if (schemas.body) {
        req.body = await schemas.body.parseAsync(req.body);
      }

      // Validate query
      if (schemas.query) {
        req.query = await schemas.query.parseAsync(req.query);
      }

      // Validate params
      if (schemas.params) {
        req.params = await schemas.params.parseAsync(req.params);
      }

      next();
    } catch (error) {
      if (error instanceof ZodError) {
        const messages = error.errors.map(err => `${err.path.join('.')}: ${err.message}`).join(', ');
        throw new ValidationError(ErrorCode.VALIDATION_ERROR, messages);
      }
      throw error;
    }
  };
};
