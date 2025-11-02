/**
 * Request Context Middleware
 * Adds request tracking and context information
 */

import type { Request, Response, NextFunction } from 'express';
import { randomUUID } from 'crypto';

export interface RequestContext {
  requestId: string;
  startTime: number;
  userId?: string;
  organizationId?: string;
  deviceId?: string;
  ipAddress: string;
  userAgent: string;
}

declare global {
  namespace Express {
    interface Request {
      context: RequestContext;
    }
  }
}

/**
 * Add request context to each request
 */
export function requestContext(req: Request, res: Response, next: NextFunction): void {
  const requestId = req.headers['x-request-id'] as string || randomUUID();
  
  req.context = {
    requestId,
    startTime: Date.now(),
    ipAddress: (req.headers['x-forwarded-for'] as string || req.ip || '').split(',')[0].trim(),
    userAgent: req.headers['user-agent'] || 'Unknown',
  };

  res.setHeader('X-Request-ID', requestId);

  next();
}

/**
 * Log request completion
 */
export function logRequestCompletion(req: Request, res: Response, next: NextFunction): void {
  const originalSend = res.send;

  res.send = function (data): Response {
    const duration = Date.now() - req.context.startTime;
    
    // Log request completion (this would integrate with winston logger in production)
    if (config.app.env !== 'test') {
      console.log({
        requestId: req.context.requestId,
        method: req.method,
        path: req.path,
        statusCode: res.statusCode,
        duration: `${duration}ms`,
        userId: req.context.userId,
        ipAddress: req.context.ipAddress,
      });
    }

    return originalSend.call(this, data);
  };

  next();
}

import config from '../config';
