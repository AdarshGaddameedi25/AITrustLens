/**
 * Centralized Security Telemetry Logging Middleware
 *
 * Captures request details, execution timings, and responses,
 * while scrubbing sensitive data (passwords, tokens, headers)
 * before write.
 */

import logger, { sanitizeForLog } from '../utils/logger.js';

// Sensitive headers we must redact
const SENSITIVE_HEADERS = ['authorization', 'cookie', 'set-cookie', 'x-apikey', 'api-key'];

/**
 * Scrubs request/response headers.
 * @param {Object} headers
 * @returns {Object}
 */
function sanitizeHeaders(headers) {
  if (!headers) return {};
  const scrubbed = { ...headers };
  for (const h of SENSITIVE_HEADERS) {
    if (h in scrubbed) {
      scrubbed[h] = '[REDACTED]';
    }
  }
  return scrubbed;
}

/**
 * Express middleware for telemetry logs
 */
export default function telemetryMiddleware(req, res, next) {
  const start = process.hrtime();
  const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  // Log incoming request
  logger.info(`Incoming Request: ${req.method} ${req.originalUrl}`, {
    ip,
    method: req.method,
    url: req.originalUrl,
    headers: sanitizeHeaders(req.headers),
    body: sanitizeForLog(req.body),
  });

  // Intercept response finish
  res.on('finish', () => {
    const diff = process.hrtime(start);
    const durationMs = (diff[0] * 1e3 + diff[1] * 1e-6).toFixed(2);

    logger.info(`Response Sent: ${req.method} ${req.originalUrl} - ${res.statusCode} (${durationMs}ms)`, {
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      durationMs: parseFloat(durationMs),
    });
  });

  next();
}
