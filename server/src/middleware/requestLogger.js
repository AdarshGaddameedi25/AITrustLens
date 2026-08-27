import { v4 as uuidv4 } from 'uuid';
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
    const lowercaseHeader = h.toLowerCase();
    if (lowercaseHeader in scrubbed) {
      scrubbed[lowercaseHeader] = '[REDACTED]';
    }
  }
  return scrubbed;
}

/**
 * Centralized request logger / security telemetry middleware.
 * Attaches a unique request ID, sanitizes payloads, and measures execution durations.
 */
export function requestLogger(req, res, next) {
  req.id = uuidv4();
  const start = process.hrtime();
  const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  // Log incoming request
  logger.info(`Incoming Request: ${req.method} ${req.originalUrl}`, {
    requestId: req.id,
    ip,
    method: req.method,
    url: req.originalUrl,
    headers: sanitizeHeaders(req.headers),
    body: sanitizeForLog(req.body),
    userId: req.user?.id,
  });

  // Intercept response finish
  res.on('finish', () => {
    const diff = process.hrtime(start);
    const durationMs = (diff[0] * 1e3 + diff[1] * 1e-6).toFixed(2);
    const level = res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info';

    logger[level](`Request Completed: ${req.method} ${req.originalUrl} - ${res.statusCode} (${durationMs}ms)`, {
      requestId: req.id,
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      durationMs: parseFloat(durationMs),
      userId: req.user?.id,
    });
  });

  next();
}
