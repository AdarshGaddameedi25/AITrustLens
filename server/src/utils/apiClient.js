/**
 * Resilient API Client
 * Wraps Axios with timeout, exponential backoff, and strict 429 (Rate Limit) handling.
 */

import axios from 'axios';
import axiosRetry from 'axios-retry';
import logger from './logger.js';

/**
 * Creates a configured, resilient Axios instance.
 * @param {Object} options
 * @param {string} [options.baseURL]
 * @param {number} [options.timeout=10000] - Default 10 seconds
 * @param {number} [options.retries=2] - Number of retries
 * @returns {import('axios').AxiosInstance}
 */
export function createApiClient(options = {}) {
  const { baseURL, timeout = 10000, retries = 2, headers = {} } = options;

  const client = axios.create({
    baseURL,
    timeout,
    headers,
  });

  // Configure retries for transient errors and rate limits (429)
  axiosRetry(client, {
    retries,
    retryDelay: (retryCount, error) => {
      // If we got a 429, respect the Retry-After header if present, else backoff
      if (error.response && error.response.status === 429) {
        const retryAfter = error.response.headers['retry-after'];
        if (retryAfter) {
          const delay = parseInt(retryAfter, 10);
          if (!Number.isNaN(delay)) {
            // retry-after can be in seconds
            return delay * 1000;
          }
        }
        // Default backoff for 429: 2s, 4s, etc.
        return retryCount * 2000;
      }
      
      // Default exponential backoff for network/5xx errors
      return axiosRetry.exponentialDelay(retryCount);
    },
    retryCondition: (error) => {
      // Retry on network errors, 5xx, or 429
      return (
        axiosRetry.isNetworkOrIdempotentRequestError(error) ||
        (error.response && error.response.status === 429)
      );
    },
    onRetry: (retryCount, error, requestConfig) => {
      logger.warn(`Retrying request to ${requestConfig.url}`, {
        retryCount,
        status: error.response?.status,
        code: error.code,
      });
    },
  });

  return client;
}
