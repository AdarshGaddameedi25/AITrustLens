/**
 * Scan Cache Service
 *
 * Prevents duplicate API calls for the same URL within a 24h TTL window.
 * Uses a SHA-256 hash of the normalized URL as the cache key.
 *
 * Degrades gracefully — if Redis is unavailable, caching is silently skipped.
 */

import crypto from 'crypto';
import { getRedisClient, isRedisAvailable } from '../config/redis.js';
import logger from '../utils/logger.js';

const CACHE_TTL_SECONDS = 60 * 60 * 24; // 24 hours
const CACHE_PREFIX = 'scan:url:';

/**
 * Generates a cache key from a normalized URL.
 * @param {string} normalizedUrl
 * @returns {string}
 */
function buildCacheKey(normalizedUrl) {
  const hash = crypto.createHash('sha256').update(normalizedUrl).digest('hex');
  return `${CACHE_PREFIX}${hash}`;
}

/**
 * Retrieves a cached scan result if one exists.
 * @param {string} normalizedUrl
 * @returns {Promise<Object|null>} Parsed result or null
 */
export async function getCachedScan(normalizedUrl) {
  if (!isRedisAvailable()) return null;

  try {
    const key = buildCacheKey(normalizedUrl);
    const cached = await getRedisClient().get(key);
    if (cached) {
      logger.info('Scan cache HIT', { url: normalizedUrl });
      return JSON.parse(cached);
    }
    logger.debug('Scan cache MISS', { url: normalizedUrl });
    return null;
  } catch (err) {
    logger.warn('Cache get failed (non-fatal)', { error: err.message });
    return null;
  }
}

/**
 * Stores a scan result in the cache.
 * @param {string} normalizedUrl
 * @param {Object} result
 */
export async function cacheScanResult(normalizedUrl, result) {
  if (!isRedisAvailable()) return;

  try {
    const key = buildCacheKey(normalizedUrl);
    await getRedisClient().setex(key, CACHE_TTL_SECONDS, JSON.stringify(result));
    logger.debug('Scan result cached', { url: normalizedUrl, ttl: CACHE_TTL_SECONDS });
  } catch (err) {
    logger.warn('Cache set failed (non-fatal)', { error: err.message });
  }
}

/**
 * Marks a URL as "currently being processed" using a short-lived lock.
 * Returns true if the lock was acquired (caller should proceed),
 * false if another process already holds the lock.
 * @param {string} normalizedUrl
 * @param {number} [ttl=120] - Lock TTL in seconds
 * @returns {Promise<boolean>}
 */
export async function acquireScanLock(normalizedUrl, ttl = 120) {
  if (!isRedisAvailable()) return true; // No Redis = no locking, allow through

  try {
    const key = `lock:${buildCacheKey(normalizedUrl)}`;
    // SET key value NX EX — atomic lock acquisition
    const result = await getRedisClient().set(key, '1', 'NX', 'EX', ttl);
    return result === 'OK';
  } catch (err) {
    logger.warn('Lock acquisition failed (non-fatal)', { error: err.message });
    return true; // Fail open
  }
}

/**
 * Releases the processing lock for a URL.
 * @param {string} normalizedUrl
 */
export async function releaseScanLock(normalizedUrl) {
  if (!isRedisAvailable()) return;

  try {
    const key = `lock:${buildCacheKey(normalizedUrl)}`;
    await getRedisClient().del(key);
  } catch (err) {
    logger.warn('Lock release failed (non-fatal)', { error: err.message });
  }
}
