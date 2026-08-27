import crypto from 'crypto';
import { getRedisClient, isRedisAvailable } from '../config/redis.js';
import logger from './logger.js';

// In-memory fallback with automatic TTL eviction
const memStore = new Map(); // key -> { raw, expiresAt }

function memGet(key) {
  const e = memStore.get(key);
  if (!e) return null;
  if (e.expiresAt && Date.now() > e.expiresAt) { memStore.delete(key); return null; }
  return e.raw;
}

function memSet(key, raw, ttlSeconds) {
  memStore.set(key, { raw, expiresAt: ttlSeconds ? Date.now() + ttlSeconds * 1000 : null });
}

/**
 * Get a cached value. Returns null on miss or error.
 * @param {string} key
 * @returns {Promise<any|null>}
 */
export async function getCache(key) {
  if (isRedisAvailable()) {
    try {
      const data = await getRedisClient().get(key);
      if (data !== null) {
        logger.debug('Cache HIT (Redis)', { key });
        return JSON.parse(data);
      }
      logger.debug('Cache MISS (Redis)', { key });
      return null;
    } catch (err) {
      logger.warn('Redis getCache error, falling back to memory', { error: err.message });
    }
  }
  const raw = memGet(key);
  if (raw) { logger.debug('Cache HIT (memory)', { key }); return JSON.parse(raw); }
  return null;
}

/**
 * Set a cache value with optional TTL (seconds).
 * @param {string} key
 * @param {any} value
 * @param {number} [ttlSeconds]
 */
export async function setCache(key, value, ttlSeconds) {
  const raw = JSON.stringify(value);
  if (isRedisAvailable()) {
    try {
      if (ttlSeconds) {
        await getRedisClient().setex(key, ttlSeconds, raw);
      } else {
        await getRedisClient().set(key, raw);
      }
      logger.debug('Cache SET (Redis)', { key, ttl: ttlSeconds });
      return;
    } catch (err) {
      logger.warn('Redis setCache error, falling back to memory', { error: err.message });
    }
  }
  memSet(key, raw, ttlSeconds);
  logger.debug('Cache SET (memory)', { key, ttl: ttlSeconds });
}

/**
 * Delete a cache entry.
 * @param {string} key
 */
export async function delCache(key) {
  if (isRedisAvailable()) {
    try { await getRedisClient().del(key); } catch { /* non-fatal */ }
  }
  memStore.delete(key);
}

/**
 * Build a namespaced cache key from arbitrary parts.
 * Usage: cacheKey('scan', 'url', url) => 'scan:url:<sha256>'
 * @param {...string} parts
 * @returns {string}
 */
export function cacheKey(...parts) {
  const joined = parts.join(':');
  const hash = crypto.createHash('sha256').update(joined).digest('hex');
  return `${parts[0]}:${hash}`;
}
