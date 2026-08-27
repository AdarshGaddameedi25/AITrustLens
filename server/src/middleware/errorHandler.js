import logger from '../utils/logger.js';
import { errorResponse } from '../utils/responseFormatter.js';
import { env } from '../config/env.js';
import { AppError } from '../utils/errors.js';

/**
 * Global error handler middleware.
 * Must be the last middleware in the chain.
 * Never exposes stack traces or internal details in production.
 */
export function errorHandler(err, req, res, next) {
  const requestId = req.id || 'unknown';

  // Determine status code and codes
  let statusCode = 500;
  let code = 'INTERNAL_ERROR';
  let message = 'An unexpected error occurred.';

  if (err instanceof AppError) {
    statusCode = err.statusCode;
    code = err.code;
    message = err.message;
  } else {
    // Standard library/node errors
    statusCode = err.statusCode || err.status || 500;
    code = err.code || 'INTERNAL_ERROR';
    message = err.message || 'An unexpected error occurred.';
  }

  // Log the full error internally
  logger.error('Unhandled error occurred', {
    requestId,
    code,
    message,
    statusCode,
    path: req.path,
    method: req.method,
    stack: err.stack,
    userId: req.user?.id,
  });

  // Never expose internal details to client in production
  const isProduction = env.nodeEnv === 'production';
  const clientMessage =
    statusCode >= 500 && isProduction
      ? 'An internal server error occurred. Please try again later.'
      : message;

  const clientCode =
    statusCode >= 500 && isProduction ? 'INTERNAL_ERROR' : code;

  return res.status(statusCode).json(errorResponse(clientCode, clientMessage, err.stack));
}

/**
 * 404 Not Found handler.
 */
export function notFoundHandler(req, res) {
  return res.status(404).json(
    errorResponse('NOT_FOUND', `Route not found: ${req.method} ${req.path}`)
  );
}
