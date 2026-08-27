import winston from 'winston';
import { env } from '../config/env.js';

const { combine, timestamp, errors, json, colorize, simple } = winston.format;

const logger = winston.createLogger({
  level: env.isDev ? 'debug' : 'info',
  format: combine(
    timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    errors({ stack: true }),
    json()
  ),
  defaultMeta: { service: 'aitrustlens' },
  transports: [
    new winston.transports.Console({
      format: env.isDev
        ? combine(colorize(), simple())
        : combine(timestamp(), json()),
    }),
  ],
});

// Security: never log sensitive fields
const SENSITIVE_FIELDS = ['password', 'apiKey', 'token', 'secret', 'hash', 'passwordHash'];

export function sanitizeForLog(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const sanitized = { ...obj };
  for (const field of SENSITIVE_FIELDS) {
    if (field in sanitized) {
      sanitized[field] = '[REDACTED]';
    }
  }
  return sanitized;
}

export default logger;
