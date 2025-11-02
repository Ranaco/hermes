import type { Request, Response, NextFunction } from 'express';
import { AppError } from './errors';
import { ErrorCode } from './error-codes';

/**
 * Express Error Handler Middleware
 * Centralized error handling for the entire application
 */
export function errorHandler(
  err: Error | AppError,
  req: Request,
  res: Response,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  next: NextFunction
): void {
  // Log error for monitoring
  console.error('[Error Handler]', {
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    userId: (req as Request & { user?: { id: string } }).user?.id,
  });

  // Handle AppError instances
  if (err instanceof AppError) {
    res.status(err.statusCode).json(err.toJSON());
    return;
  }

  // Handle specific known errors
  if (err.name === 'ValidationError') {
    res.status(400).json({
      code: ErrorCode.VALIDATION_ERROR,
      message: err.message,
      statusCode: 400,
      timestamp: new Date(),
    });
    return;
  }

  if (err.name === 'UnauthorizedError' || err.name === 'JsonWebTokenError') {
    res.status(401).json({
      code: ErrorCode.TOKEN_INVALID,
      message: 'Invalid or expired token',
      statusCode: 401,
      timestamp: new Date(),
    });
    return;
  }

  if (err.name === 'TokenExpiredError') {
    res.status(401).json({
      code: ErrorCode.TOKEN_EXPIRED,
      message: 'Token has expired',
      statusCode: 401,
      timestamp: new Date(),
    });
    return;
  }

  // Handle Prisma errors
  if (err.name === 'PrismaClientKnownRequestError') {
    const prismaError = err as unknown as { code: string; meta?: { target?: string[] } };
    
    if (prismaError.code === 'P2002') {
      res.status(409).json({
        code: ErrorCode.KEY_ALREADY_EXISTS,
        message: 'Resource already exists',
        statusCode: 409,
        details: prismaError.meta,
        timestamp: new Date(),
      });
      return;
    }

    if (prismaError.code === 'P2025') {
      res.status(404).json({
        code: ErrorCode.KEY_NOT_FOUND,
        message: 'Resource not found',
        statusCode: 404,
        timestamp: new Date(),
      });
      return;
    }
  }

  // Default to 500 Internal Server Error
  const statusCode = 500;
  res.status(statusCode).json({
    code: ErrorCode.INTERNAL_SERVER_ERROR,
    message: process.env.NODE_ENV === 'production' 
      ? 'An unexpected error occurred' 
      : err.message,
    statusCode,
    timestamp: new Date(),
    ...(process.env.NODE_ENV !== 'production' && { stack: err.stack }),
  });
}

/**
 * 404 Not Found Handler
 */
export function notFoundHandler(req: Request, res: Response): void {
  res.status(404).json({
    code: ErrorCode.KEY_NOT_FOUND,
    message: `Route ${req.method} ${req.url} not found`,
    statusCode: 404,
    timestamp: new Date(),
  });
}

/**
 * Async Handler Wrapper
 * Wraps async route handlers to catch errors automatically
 */
export function asyncHandler<T>(
  fn: (req: Request, res: Response, next: NextFunction) => Promise<T>
) {
  return (req: Request, res: Response, next: NextFunction): void => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

/**
 * Validation Error Formatter
 * Formats validation errors into a consistent structure
 */
export function formatValidationErrors(errors: Array<{ field: string; message: string }>) {
  return {
    code: ErrorCode.VALIDATION_ERROR,
    message: 'Validation failed',
    statusCode: 400,
    details: errors,
    timestamp: new Date(),
  };
}
