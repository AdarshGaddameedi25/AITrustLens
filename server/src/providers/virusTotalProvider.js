/**
 * VirusTotal API Provider (Refactored for Resiliency)
 *
 * Scans URLs against 70+ antivirus engines.
 * Respects rate limits via robust apiClient.
 */

import { env } from '../config/env.js';
import { createApiClient } from '../utils/apiClient.js';
import logger from '../utils/logger.js';

const client = createApiClient({
  baseURL: 'https://www.virustotal.com/api/v3',
  timeout: 10000,
  headers: {
    'x-apikey': env.apis.virusTotal,
    'Accept': 'application/json',
  },
});

/**
 * Analyzes a URL via VirusTotal.
 * @param {string} url
 * @returns {Promise<Object>}
 */
export async function analyzeUrl(url) {
  if (!env.apis.virusTotal) {
    logger.warn('VirusTotal API key missing, skipping provider');
    return { status: 'UNAVAILABLE' };
  }

  try {
    const urlId = Buffer.from(url).toString('base64url');
    
    // apiClient automatically handles retries and 429s
    const response = await client.get(`/urls/${urlId}`);
    
    const attributes = response.data?.data?.attributes;
    if (!attributes) {
      return { status: 'ERROR', error: 'Invalid response format' };
    }

    const stats = attributes.last_analysis_stats || {};
    return {
      status: 'AVAILABLE',
      maliciousCount: stats.malicious || 0,
      suspiciousCount: stats.suspicious || 0,
      totalEngines: Object.values(stats).reduce((a, b) => a + b, 0),
    };

  } catch (error) {
    if (error.response?.status === 404) {
      // 404 means VT hasn't analyzed this URL yet. We could submit it, 
      // but that takes too long. Treat as NOT_FOUND.
      return { status: 'NOT_FOUND' };
    }
    if (error.response?.status === 429) {
      logger.warn('VirusTotal rate limit exceeded after retries');
      return { status: 'RATE_LIMITED' };
    }
    
    logger.error('VirusTotal API error', { error: error.message, status: error.response?.status });
    return { status: 'ERROR', error: error.message };
  }
}
