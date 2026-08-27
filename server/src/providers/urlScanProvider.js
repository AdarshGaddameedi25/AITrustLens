/**
 * URLScan.io Provider
 * Submits URLs for deep analysis and retrieves scan results.
 * Handles the async nature of URLScan (submit → poll → result).
 */

import { env } from '../config/env.js';
import { createApiClient } from '../utils/apiClient.js';
import logger from '../utils/logger.js';

const client = createApiClient({
  baseURL: 'https://urlscan.io/api/v1',
  timeout: 15000,
  headers: { 'API-Key': env.apis.urlScan },
});

const MAX_POLL_ATTEMPTS = 12;
const POLL_INTERVAL_MS = 5000;

/**
 * Submits a URL for scanning.
 * @param {string} url
 * @returns {Promise<{ scanId: string|null, status: string, error?: string }>}
 */
export async function submitScan(url) {
  if (!env.apis.urlScan) {
    return { scanId: null, status: 'UNAVAILABLE', error: 'API key not configured' };
  }

  try {
    const response = await client.post(
      '/scan/',
      { url, visibility: 'unlisted', tags: ['aitrustlens'] },
      { headers: { 'Content-Type': 'application/json' } }
    );

    return {
      scanId: response.data?.uuid || null,
      apiUrl: response.data?.api,
      resultUrl: response.data?.result,
      status: 'SUBMITTED',
      error: null,
    };
  } catch (error) {
    if (error.response?.status === 429) {
      logger.warn('URLScan rate limit hit');
      return { scanId: null, status: 'RATE_LIMITED', error: 'Rate limit reached' };
    }
    if (error.response?.status === 400) {
      logger.warn('URLScan rejected URL', { url, error: error.response?.data?.message });
      return { scanId: null, status: 'REJECTED', error: error.response?.data?.message };
    }
    logger.error('URLScan submission error', { error: error.message });
    return { scanId: null, status: 'ERROR', error: error.message };
  }
}

/**
 * Polls for a scan result until complete or timeout.
 * @param {string} scanId
 * @returns {Promise<Object>}
 */
export async function pollForResult(scanId) {
  if (!scanId) {
    return { status: 'ERROR', error: 'No scan ID provided' };
  }

  for (let attempt = 0; attempt < MAX_POLL_ATTEMPTS; attempt++) {
    try {
      const response = await client.get(`/result/${scanId}/`);

      return normalizeResult(response.data);
    } catch (error) {
      if (error.response?.status === 404) {
        // Still processing
        logger.debug(`URLScan still processing, attempt ${attempt + 1}/${MAX_POLL_ATTEMPTS}`);
        if (attempt < MAX_POLL_ATTEMPTS - 1) {
          await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
          continue;
        }
        return { status: 'TIMEOUT', error: 'URLScan analysis timed out' };
      }
      logger.error('URLScan poll error', { scanId, error: error.message });
      return { status: 'ERROR', error: error.message };
    }
  }

  return { status: 'TIMEOUT', error: 'Maximum poll attempts reached' };
}

/**
 * Normalizes URLScan result to a consistent format.
 * @param {Object} raw
 * @returns {Object}
 */
function normalizeResult(raw) {
  const page = raw?.page || {};
  const stats = raw?.stats || {};
  const verdicts = raw?.verdicts || {};
  const lists = raw?.lists || {};
  const meta = raw?.meta || {};

  return {
    status: 'AVAILABLE',
    scanId: raw?.task?.uuid,
    url: page.url,
    finalUrl: page.url,
    domain: page.domain,
    ip: page.ip,
    country: page.country,
    server: page.server,
    title: page.title,
    screenshot: raw?.screenshot,
    malicious: verdicts?.overall?.malicious ?? false,
    score: verdicts?.overall?.score ?? 0,
    categories: verdicts?.overall?.categories ?? [],
    brands: verdicts?.overall?.brands ?? [],
    urlsInPage: lists?.urls?.length ?? 0,
    ipsInPage: lists?.ips?.length ?? 0,
    domainsInPage: lists?.domains?.length ?? 0,
    tlsCertificate: meta?.processors?.cert?.data?.[0] || null,
    httpStatus: page.status,
    mimeType: page.mimeType,
    redirected: page.redirected,
    asn: meta?.processors?.asn?.data?.[0] || null,
    stats: {
      maliciousUrls: stats?.malicious ?? 0,
      totalRequests: stats?.requests?.total ?? 0,
    },
    error: null,
  };
}

/**
 * Submit and wait for URLScan result (combined operation).
 * @param {string} url
 * @returns {Promise<Object>}
 */
export async function analyzeUrl(url) {
  const submission = await submitScan(url);

  if (submission.status !== 'SUBMITTED' || !submission.scanId) {
    return { status: submission.status, error: submission.error };
  }

  // Wait initial processing time
  await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  return pollForResult(submission.scanId);
}
