/**
 * Evidence Collector — Phase 2 Architecture
 * Orchestrates concurrent evidence collection from all providers.
 * Translates raw API responses into the Normalized Evidence Model.
 */

import * as virusTotal from '../providers/virusTotalProvider.js';
import * as safeBrowsing from '../providers/safeBrowsingProvider.js';
import * as urlScan from '../providers/urlScanProvider.js';
import * as tls from '../providers/tlsInspectorProvider.js';
import * as rdap from '../providers/rdapProvider.js';
import { normalizeUrl, extractHostname, isHttps, detectSuspiciousUrlPatterns } from '../utils/urlNormalizer.js';
import logger from '../utils/logger.js';

import { createEvidenceCollection, detectConflicts } from './evidenceModel.js';
import { adaptVirusTotal, adaptSafeBrowsing, adaptTls, adaptRdap, adaptUrlScan, adaptUrlPatterns } from './providerAdapters.js';

/**
 * Collects and normalizes all evidence for a URL analysis.
 *
 * @param {string} url
 * @param {Object} options
 * @returns {Promise<Object>} Normalized Evidence Collection
 */
export async function collectUrlEvidence(url, options = {}) {
  const normalizedUrl = normalizeUrl(url);
  const hostname = extractHostname(normalizedUrl);
  const httpsEnabled = isHttps(normalizedUrl);
  const urlPatterns = detectSuspiciousUrlPatterns(normalizedUrl);
  const urlInfo = { original: url, normalized: normalizedUrl, hostname, isHttps: httpsEnabled };

  logger.info('Starting evidence collection', { url: normalizedUrl, hostname });

  // Run all independent providers concurrently
  const [vtResult, sbResult, tlsResult, rdapResult, urlscanResult] = await Promise.allSettled([
    virusTotal.analyzeUrl(normalizedUrl),
    safeBrowsing.checkUrl(normalizedUrl),
    httpsEnabled ? tls.inspectTlsCertificate(hostname) : Promise.resolve({ status: 'UNAVAILABLE', error: 'No HTTPS' }),
    rdap.queryDomain(hostname),
    options.skipUrlScan ? Promise.resolve({ status: 'UNAVAILABLE', error: 'Skipped' }) : urlScan.analyzeUrl(normalizedUrl),
  ]);

  // Extract raw results
  const vtRaw = extractSettled(vtResult, 'VirusTotal');
  const sbRaw = extractSettled(sbResult, 'Safe Browsing');
  const tlsRaw = extractSettled(tlsResult, 'TLS');
  const rdapRaw = extractSettled(rdapResult, 'RDAP');
  const urlscanRaw = extractSettled(urlscanResult, 'URLScan');

  // Adapt to normalized evidence items
  const items = [
    ...adaptUrlPatterns(urlPatterns, urlInfo),
    ...adaptVirusTotal(vtRaw),
    ...adaptSafeBrowsing(sbRaw),
    ...adaptTls(tlsRaw),
    ...adaptRdap(rdapRaw),
    ...adaptUrlScan(urlscanRaw),
  ];

  // Build the normalized collection
  const evidenceCollection = createEvidenceCollection({
    items,
    scanType: 'URL',
    metadata: urlInfo,
  });

  // Attach detected conflicts directly to the collection for the AI/Risk Engine to see
  evidenceCollection.conflicts = detectConflicts(items);

  // Re-build sourceStatus for the frontend UI
  evidenceCollection.sourceStatus = {
    virustotal: getSourceStatus(vtRaw),
    safeBrowsing: getSourceStatus(sbRaw),
    tls: getSourceStatus(tlsRaw),
    rdap: getSourceStatus(rdapRaw),
    urlscan: getSourceStatus(urlscanRaw),
  };

  logger.info('Evidence collection complete', {
    url: normalizedUrl,
    evidenceCoverage: evidenceCollection.evidenceCoverage,
    conflictCount: evidenceCollection.conflicts.length,
  });

  return evidenceCollection;
}

/**
 * Collects evidence for email analysis (URLs within the email).
 */
export async function collectEmailEvidence(extractedUrls = []) {
  if (extractedUrls.length === 0) return {};

  const urlsToCheck = extractedUrls.slice(0, 5); // Limit to avoid rate limits

  const urlResults = await Promise.allSettled(
    urlsToCheck.map(async (url) => {
      const [vtResult, sbResult] = await Promise.allSettled([
        virusTotal.analyzeUrl(url),
        safeBrowsing.checkUrl(url),
      ]);
      return {
        url,
        virustotal: extractSettled(vtResult, 'VirusTotal'),
        safeBrowsing: extractSettled(sbResult, 'Safe Browsing'),
      };
    })
  );

  return urlResults
    .filter((r) => r.status === 'fulfilled')
    .map((r) => r.value);
}

function extractSettled(settledResult, providerName) {
  if (settledResult.status === 'fulfilled') {
    return settledResult.value;
  }
  logger.warn(`${providerName} threw an exception`, { error: settledResult.reason?.message });
  return { status: 'ERROR', error: settledResult.reason?.message || 'Unknown error' };
}

function getSourceStatus(result) {
  if (!result) return 'UNAVAILABLE';
  const status = result.status;
  if (status === 'AVAILABLE' || status === 'NO_MATCH' || status === 'THREAT_FOUND' || status === 'NOT_FOUND' || status === 'EXPOSED') {
    return 'AVAILABLE';
  }
  if (status === 'RATE_LIMITED') return 'RATE_LIMITED';
  if (status === 'ERROR') return 'ERROR';
  return 'UNAVAILABLE';
}
