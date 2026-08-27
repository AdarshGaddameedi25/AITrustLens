/**
 * Google Safe Browsing Provider
 * Checks URLs against Google's Safe Browsing threat database.
 *
 * IMPORTANT: A "no match" result does NOT mean the URL is safe.
 * The UI must communicate this distinction clearly.
 */

import { env } from '../config/env.js';
import { createApiClient } from '../utils/apiClient.js';
import logger from '../utils/logger.js';

const GSB_BASE_URL = 'https://safebrowsing.googleapis.com/v4';

const client = createApiClient({ baseURL: GSB_BASE_URL, timeout: 12000 });

const THREAT_TYPES = [
  'MALWARE',
  'SOCIAL_ENGINEERING',
  'UNWANTED_SOFTWARE',
  'POTENTIALLY_HARMFUL_APPLICATION',
  'THREAT_TYPE_UNSPECIFIED',
];

const PLATFORM_TYPES = ['ANY_PLATFORM', 'WINDOWS', 'LINUX', 'ANDROID', 'IOS'];
const URL_TYPES = ['URL'];

/**
 * @typedef {Object} SafeBrowsingResult
 * @property {string} status - 'SAFE' | 'THREAT_FOUND' | 'NO_DATA' | 'UNAVAILABLE' | 'ERROR'
 * @property {boolean} threatFound
 * @property {Array} threats
 * @property {string|null} error
 */

/**
 * Checks a URL against Google Safe Browsing.
 * @param {string} url
 * @returns {Promise<SafeBrowsingResult>}
 */
export async function checkUrl(url) {
  if (!env.apis.safeBrowsing) {
    logger.warn('Google Safe Browsing API key not configured');
    return { status: 'UNAVAILABLE', threatFound: false, threats: [], error: 'API key not configured' };
  }

  const requestBody = {
    client: {
      clientId: 'aitrustlens',
      clientVersion: '1.0.0',
    },
    threatInfo: {
      threatTypes: THREAT_TYPES,
      platformTypes: PLATFORM_TYPES,
      threatEntryTypes: URL_TYPES,
      threatEntries: [{ url }],
    },
  };

  try {
    const response = await client.post(
      `/threatMatches:find?key=${env.apis.safeBrowsing}`,
      requestBody,
      { headers: { 'Content-Type': 'application/json' } }
    );

    const matches = response.data?.matches;

    if (!matches || matches.length === 0) {
      // No match found — NOT guaranteed safe, just not in Google's database
      return {
        status: 'NO_MATCH',
        threatFound: false,
        threats: [],
        note: 'URL not found in Safe Browsing database. This does not guarantee safety.',
        error: null,
      };
    }

    // Normalize threat information
    const threats = matches.map((match) => ({
      threatType: match.threatType,
      platformType: match.platformType,
      url: match.threat?.url,
    }));

    return {
      status: 'THREAT_FOUND',
      threatFound: true,
      threats,
      error: null,
    };
  } catch (error) {
    if (error.response?.status === 403) {
      logger.error('Google Safe Browsing API key invalid or quota exceeded');
      return {
        status: 'ERROR',
        threatFound: false,
        threats: [],
        error: 'Safe Browsing API authentication failed or quota exceeded',
      };
    }
    logger.error('Google Safe Browsing error', { url, error: error.message });
    return {
      status: 'ERROR',
      threatFound: false,
      threats: [],
      error: error.message,
    };
  }
}

/**
 * Checks multiple URLs in a single batch request.
 * @param {string[]} urls
 * @returns {Promise<Map<string, SafeBrowsingResult>>}
 */
export async function checkUrls(urls) {
  if (!env.apis.safeBrowsing) {
    return new Map(urls.map((url) => [url, { status: 'UNAVAILABLE', threatFound: false, threats: [] }]));
  }

  const requestBody = {
    client: { clientId: 'aitrustlens', clientVersion: '1.0.0' },
    threatInfo: {
      threatTypes: THREAT_TYPES,
      platformTypes: PLATFORM_TYPES,
      threatEntryTypes: URL_TYPES,
      threatEntries: urls.map((url) => ({ url })),
    },
  };

  try {
    const response = await client.post(
      `/threatMatches:find?key=${env.apis.safeBrowsing}`,
      requestBody,
      { headers: { 'Content-Type': 'application/json' } }
    );

    const matches = response.data?.matches || [];
    const resultMap = new Map();

    // Initialize all as no-match
    for (const url of urls) {
      resultMap.set(url, { status: 'NO_MATCH', threatFound: false, threats: [] });
    }

    // Mark threats
    for (const match of matches) {
      const matchedUrl = match.threat?.url;
      if (matchedUrl && resultMap.has(matchedUrl)) {
        const existing = resultMap.get(matchedUrl);
        existing.status = 'THREAT_FOUND';
        existing.threatFound = true;
        existing.threats.push({
          threatType: match.threatType,
          platformType: match.platformType,
        });
      }
    }

    return resultMap;
  } catch (error) {
    logger.error('Google Safe Browsing batch check error', { error: error.message });
    return new Map(urls.map((url) => [url, { status: 'ERROR', threatFound: false, threats: [], error: error.message }]));
  }
}
