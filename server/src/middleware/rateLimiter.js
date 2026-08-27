import rateLimit from 'express-rate-limit';
import { getRedisClient, isRedisAvailable } from '../config/redis.js';
import { errorResponse } from '../utils/responseFormatter.js';
import logger from '../utils/logger.js';

const defaultHandler = (req, res) => {
  res.status(429).json(
    errorResponse('RATE_LIMIT_EXCEEDED', 'Too many requests. Please try again later.')
  );
};

/**
 * Creates a distributed rate limiter using Redis (if active),
 * fallback to memory-based express-rate-limit (if Redis is offline).
 *
 * @param {Object} options
 * @param {number} options.windowMs - Time window in milliseconds
 * @param {number} options.max - Max requests per window
 * @param {string} options.keyPrefix - Unique namespace prefix for Redis keys
 */
function createLimiter({ windowMs, max, keyPrefix }) {
  // Define in-memory fallback limiter
  const memoryLimiter = rateLimit({
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    handler: defaultHandler,
  });

  return async (req, res, next) => {
    if (!isRedisAvailable()) {
      // Redis is offline; fallback silently to in-memory rate limiting
      return memoryLimiter(req, res, next);
    }

    try {
      const redis = getRedisClient();
      const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;
      const key = `ratelimit:${keyPrefix}:${ip}`;

      // Increment request count
      const current = await redis.incr(key);

      if (current === 1) {
        // First request in this window, set expiry time
        const expirySeconds = Math.ceil(windowMs / 1000);
        await redis.expire(key, expirySeconds);
      }

      const ttl = await redis.ttl(key);
      const remaining = Math.max(0, max - current);

      res.setHeader('X-RateLimit-Limit', max);
      res.setHeader('X-RateLimit-Remaining', remaining);
      res.setHeader('X-RateLimit-Reset', Math.ceil(Date.now() / 1000) + (ttl > 0 ? ttl : 0));

      if (current > max) {
        logger.warn('Distributed Rate limit hit', { ip, keyPrefix, count: current });
        return defaultHandler(req, res);
      }

      next();
    } catch (err) {
      logger.error('Redis Rate limiter error, falling back to memory', { error: err.message });
      memoryLimiter(req, res, next);
    }
  };
}

// 1. General API Rate Limiter
export const generalLimiter = createLimiter({
  windowMs: 15 * 60 * 1000, // 15 mins
  max: 100,
  keyPrefix: 'general',
});

// 2. Auth Routes Limiter (Brute Force Protection)
export const authLimiter = createLimiter({
  windowMs: 15 * 60 * 1000, // 15 mins
  max: 10,
  keyPrefix: 'auth',
});

// 3. Scanner Endpoints Limiter
export const scanLimiter = createLimiter({
  windowMs: 60 * 1000, // 1 min
  max: 20,
  keyPrefix: 'scan',
});

// 4. File Upload Limiter
export const uploadLimiter = createLimiter({
  windowMs: 60 * 1000, // 1 min
  max: 5,
  keyPrefix: 'upload',
});

// 5. AI Endpoint Limiter
export const aiLimiter = createLimiter({
  windowMs: 60 * 1000, // 1 min
  max: 10,
  keyPrefix: 'ai',
});

// 6. Burst Limiter — per-IP hard cap: max 2 requests / second on scan endpoints
// Prevents rapid bursts that bypass the per-minute window
export const burstLimiter = createLimiter({
  windowMs: 1000,   // 1 second window
  max: 2,           // max 2 req / second
  keyPrefix: 'burst',
});

// 7. Per-user scan limiter — keyed by userId (not IP) when user is authenticated
// This is applied after authenticate() middleware so req.user is available
export function perUserScanLimiter(maxPerMinute = 10) {
  const counters = new Map(); // userId -> { count, resetAt }
  return (req, res, next) => {
    const userId = req.user?.id || req.ip;
    const now = Date.now();
    const entry = counters.get(userId);
    if (!entry || now > entry.resetAt) {
      counters.set(userId, { count: 1, resetAt: now + 60_000 });
      return next();
    }
    entry.count += 1;
    if (entry.count > maxPerMinute) {
      return res.status(429).json(
        errorResponse('RATE_LIMIT_EXCEEDED', `You have exceeded ${maxPerMinute} scans per minute. Please wait before retrying.`)
      );
    }
    next();
  };
}
