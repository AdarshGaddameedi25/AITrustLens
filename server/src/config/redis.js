/**
 * Redis Connection Manager
 *
 * Provides a shared ioredis client with graceful error handling.
 * Falls back gracefully if Redis is not available — scans still work,
 * just without caching or job queue deduplication.
 */

import Redis from 'ioredis';
import { env } from './env.js';
import logger from '../utils/logger.js';

let redisClient = null;

export function getRedisClient() {
  if (redisClient) return redisClient;

  const host = env.redis?.host || 'localhost';
  const port = env.redis?.port || 6379;
  const password = env.redis?.password || undefined;

  redisClient = new Redis({
    host,
    port,
    password,
    // Retry with exponential backoff; after 5 failures stop retrying to avoid blocking app
    retryStrategy: (times) => {
      if (times > 5) {
        logger.error('Redis: too many failed connection attempts. Disabling Redis features.');
        return null; // stop retrying
      }
      return Math.min(times * 200, 2000);
    },
    maxRetriesPerRequest: null,
    enableReadyCheck: false,
    lazyConnect: true,
  });

  redisClient.on('connect', () => logger.info('Redis connected'));
  redisClient.on('error', (err) => {
    // Don't crash the app if Redis is unavailable
    if (err.code !== 'ECONNREFUSED') {
      logger.warn('Redis error', { error: err.message });
    }
  });

  return redisClient;
}

export function isRedisAvailable() {
  return redisClient?.status === 'ready';
}
