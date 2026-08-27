/**
 * HIBP Pwned Passwords Provider
 * Uses k-anonymity approach to check password exposure.
 *
 * SECURITY:
 * - Raw passwords are NEVER sent to any external service.
 * - Only the first 5 characters of the SHA-1 hash are sent.
 * - Comparison is done locally.
 * - Passwords are NEVER logged or stored.
 */

import axios from 'axios';
import { generateKAnonymityComponents } from '../utils/hashUtils.js';
import logger from '../utils/logger.js';

const HIBP_BASE_URL = 'https://api.pwnedpasswords.com/range';
const TIMEOUT_MS = 10000;

/**
 * @typedef {Object} PasswordBreachResult
 * @property {string} status - 'EXPOSED' | 'NOT_FOUND' | 'UNAVAILABLE' | 'ERROR'
 * @property {number|null} breachCount
 * @property {string|null} error
 */

/**
 * Checks if a password has been exposed in known data breaches.
 * Uses SHA-1 k-anonymity: only the 5-char prefix is sent externally.
 *
 * @param {string} password - Plaintext password (used only in memory, never logged or stored)
 * @returns {Promise<PasswordBreachResult>}
 */
export async function checkPasswordBreach(password) {
  // Security: validate input without logging the value
  if (!password || typeof password !== 'string') {
    return { status: 'ERROR', breachCount: null, error: 'Invalid password input' };
  }

  let prefix, suffix;
  try {
    // Generate k-anonymity components locally
    ({ prefix, suffix } = generateKAnonymityComponents(password));
    // Immediately clear reference to the raw password from this scope
    // (JS garbage collection will handle memory; we cannot force zero-fill in JS)
  } catch (error) {
    logger.error('Error generating k-anonymity components', { error: error.message });
    return { status: 'ERROR', breachCount: null, error: 'Failed to process password securely' };
  }

  try {
    // Send ONLY the 5-char prefix — the full hash is never transmitted
    const response = await axios.get(`${HIBP_BASE_URL}/${prefix}`, {
      timeout: TIMEOUT_MS,
      headers: {
        'Add-Padding': 'true', // Padding prevents traffic analysis
        'User-Agent': 'AITrustLens-BreachChecker/1.0',
      },
    });

    // Response is line-delimited: HASH_SUFFIX:COUNT
    const lines = response.data.split('\n');

    for (const line of lines) {
      const [hashSuffix, count] = line.trim().split(':');
      if (hashSuffix && hashSuffix.toUpperCase() === suffix) {
        const breachCount = parseInt(count, 10) || 0;
        logger.info('Password found in breach database', { count: breachCount });
        return {
          status: 'EXPOSED',
          breachCount,
          error: null,
        };
      }
    }

    return {
      status: 'NOT_FOUND',
      breachCount: 0,
      note: 'Not found in Pwned Passwords database. This does not guarantee the password is safe.',
      error: null,
    };
  } catch (error) {
    if (error.response?.status === 429) {
      logger.warn('HIBP rate limit hit');
      return { status: 'UNAVAILABLE', breachCount: null, error: 'Rate limit reached' };
    }
    logger.error('HIBP check error', { error: error.message });
    return { status: 'UNAVAILABLE', breachCount: null, error: error.message };
  } finally {
    // Attempt to minimize time sensitive data stays in scope
    prefix = null;
    suffix = null;
  }
}
