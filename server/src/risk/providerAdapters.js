/**
 * Provider Adapters — Phase 1 Enforced Pipeline
 *
 * Each adapter translates a raw provider API response into the
 * STRICT normalized Evidence Model format:
 * { source, indicator, value, severity, confidence, timestamp, status, freshness, rawRef }
 */

import {
  EvidenceSource,
  EvidenceStatus,
  createEvidence,
  createUnavailableEvidence,
  createErrorEvidence,
} from './evidenceModel.js';

function getFreshness(result) {
  if (result?.cachedAt) {
    return Math.round((Date.now() - new Date(result.cachedAt).getTime()) / 1000);
  }
  return 0; // Fresh
}

export function adaptVirusTotal(vtResult) {
  if (!vtResult || vtResult.status === 'UNAVAILABLE') {
    return [createUnavailableEvidence(EvidenceSource.VIRUSTOTAL, 'REPUTATION', 'VT_MALICIOUS_COUNT', 'VirusTotal API unavailable or not configured.')];
  }
  if (vtResult.status === 'ERROR' || vtResult.status === 'RATE_LIMITED') {
    return [createErrorEvidence(EvidenceSource.VIRUSTOTAL, 'REPUTATION', 'VT_MALICIOUS_COUNT', vtResult.error || vtResult.status)];
  }

  const items = [];
  const malicious = vtResult.maliciousCount ?? 0;
  const suspicious = vtResult.suspiciousCount ?? 0;
  const total = vtResult.totalEngines ?? 1;
  const ratio = malicious / total;

  let severity = 'INFO';
  if (malicious >= 10 || ratio >= 0.3) severity = 'CRITICAL';
  else if (malicious >= 5 || ratio >= 0.15) severity = 'HIGH';
  else if (malicious >= 2 || ratio >= 0.05) severity = 'MODERATE';
  else if (malicious === 1) severity = 'LOW';

  items.push(createEvidence({
    source: EvidenceSource.VIRUSTOTAL,
    indicator: 'VT_MALICIOUS_COUNT',
    status: malicious > 0 ? EvidenceStatus.POSITIVE : EvidenceStatus.NEGATIVE,
    value: { maliciousCount: malicious, totalEngines: total },
    severity,
    confidence: 'HIGH', // VT is high confidence
    freshness: getFreshness(vtResult),
    rawRef: vtResult,
  }));

  if (suspicious > 0) {
    let susSeverity = 'LOW';
    if (suspicious >= 5) susSeverity = 'HIGH';
    else if (suspicious >= 2) susSeverity = 'MODERATE';

    items.push(createEvidence({
      source: EvidenceSource.VIRUSTOTAL,
      indicator: 'VT_SUSPICIOUS_COUNT',
      status: EvidenceStatus.WARNING,
      value: { suspiciousCount: suspicious, totalEngines: total },
      severity: susSeverity,
      confidence: 'HIGH',
      freshness: getFreshness(vtResult),
    }));
  }

  return items;
}

export function adaptSafeBrowsing(sbResult) {
  if (!sbResult || sbResult.status === 'UNAVAILABLE') {
    return [createUnavailableEvidence(EvidenceSource.GOOGLE_SAFE_BROWSING, 'PHISHING', 'SB_THREAT_STATUS', 'Google Safe Browsing unavailable.')];
  }
  if (sbResult.status === 'ERROR' || sbResult.status === 'RATE_LIMITED') {
    return [createErrorEvidence(EvidenceSource.GOOGLE_SAFE_BROWSING, 'PHISHING', 'SB_THREAT_STATUS', sbResult.error || sbResult.status)];
  }

  const threatened = sbResult.status === 'THREAT_FOUND';
  return [createEvidence({
    source: EvidenceSource.GOOGLE_SAFE_BROWSING,
    indicator: 'SB_THREAT_STATUS',
    status: threatened ? EvidenceStatus.POSITIVE : EvidenceStatus.NEGATIVE,
    value: { threatTypes: sbResult.threats ?? [] },
    severity: threatened ? 'CRITICAL' : 'INFO',
    confidence: 'HIGH',
    freshness: getFreshness(sbResult),
    rawRef: sbResult,
  })];
}

export function adaptTls(tlsResult) {
  if (!tlsResult || tlsResult.status === 'UNAVAILABLE') {
    return [createUnavailableEvidence(EvidenceSource.TLS_INSPECTION, 'TLS', 'TLS_CERTIFICATE', 'TLS inspection not performed (non-HTTPS or unavailable).')];
  }
  if (tlsResult.status === 'ERROR') {
    return [createErrorEvidence(EvidenceSource.TLS_INSPECTION, 'TLS', 'TLS_CERTIFICATE', tlsResult.error || 'TLS inspection failed.')];
  }

  let status = EvidenceStatus.NEGATIVE;
  let severity = 'INFO';

  if (tlsResult.expired) {
    status = EvidenceStatus.POSITIVE;
    severity = 'HIGH';
  } else if (!tlsResult.authorized) {
    status = EvidenceStatus.WARNING;
    severity = 'MODERATE';
  } else if (tlsResult.selfSigned) {
    status = EvidenceStatus.WARNING;
    severity = 'LOW';
  } else if (tlsResult.daysUntilExpiry !== null && tlsResult.daysUntilExpiry < 14) {
    status = EvidenceStatus.WARNING;
    severity = 'LOW';
  }

  return [createEvidence({
    source: EvidenceSource.TLS_INSPECTION,
    indicator: 'TLS_CERTIFICATE',
    status,
    value: {
      authorized: tlsResult.authorized,
      expired: tlsResult.expired,
      selfSigned: tlsResult.selfSigned,
      daysUntilExpiry: tlsResult.daysUntilExpiry,
    },
    severity,
    confidence: 'HIGH',
    freshness: getFreshness(tlsResult),
    rawRef: tlsResult,
  })];
}

export function adaptRdap(rdapResult) {
  if (!rdapResult || rdapResult.status === 'UNAVAILABLE') {
    return [createUnavailableEvidence(EvidenceSource.RDAP, 'DOMAIN_AGE', 'DOMAIN_REGISTRATION_AGE', 'RDAP data unavailable.')];
  }
  if (rdapResult.status === 'ERROR') {
    return [createErrorEvidence(EvidenceSource.RDAP, 'DOMAIN_AGE', 'DOMAIN_REGISTRATION_AGE', rdapResult.error)];
  }

  const ageDays = rdapResult.domainAgeDays;
  let status = EvidenceStatus.NEGATIVE;
  let severity = 'INFO';
  
  if (ageDays !== null && ageDays !== undefined) {
    if (ageDays < 7) {
      status = EvidenceStatus.POSITIVE;
      severity = 'HIGH';
    } else if (ageDays < 30) {
      status = EvidenceStatus.POSITIVE;
      severity = 'MODERATE';
    } else if (ageDays < 90) {
      status = EvidenceStatus.WARNING;
      severity = 'LOW';
    }
  }

  return [createEvidence({
    source: EvidenceSource.RDAP,
    indicator: 'DOMAIN_REGISTRATION_AGE',
    status,
    value: { domainAgeDays: ageDays, registeredAt: rdapResult.registeredAt },
    severity,
    confidence: 'MEDIUM',
    freshness: getFreshness(rdapResult),
    rawRef: rdapResult,
  })];
}

export function adaptUrlScan(urlscanResult) {
  if (!urlscanResult || urlscanResult.status === 'UNAVAILABLE') {
    return [createUnavailableEvidence(EvidenceSource.URLSCAN, 'REPUTATION', 'URLSCAN_VERDICT', 'URLScan.io unavailable.')];
  }
  if (urlscanResult.status === 'ERROR') {
    return [createErrorEvidence(EvidenceSource.URLSCAN, 'REPUTATION', 'URLSCAN_VERDICT', urlscanResult.error)];
  }

  const malicious = urlscanResult.malicious === true;
  const score = urlscanResult.score ?? 0;

  let severity = 'INFO';
  if (malicious) severity = 'CRITICAL';
  else if (score > 50) severity = 'MODERATE';

  return [createEvidence({
    source: EvidenceSource.URLSCAN,
    indicator: 'URLSCAN_VERDICT',
    status: malicious ? EvidenceStatus.POSITIVE : score > 50 ? EvidenceStatus.WARNING : EvidenceStatus.NEGATIVE,
    value: { malicious, score },
    severity,
    confidence: 'MEDIUM',
    freshness: getFreshness(urlscanResult),
    rawRef: urlscanResult,
  })];
}

export function adaptUrlPatterns(patternResult, urlInfo) {
  const items = [];
  const flags = patternResult?.flags ?? [];

  let flagSeverity = 'INFO';
  if (flags.includes('CREDENTIAL_EMBEDDING')) flagSeverity = 'HIGH';
  else if (flags.length > 0) flagSeverity = 'MODERATE';

  items.push(createEvidence({
    source: EvidenceSource.URL_PATTERN,
    indicator: 'URL_SUSPICIOUS_PATTERNS',
    status: flags.length > 0 ? EvidenceStatus.POSITIVE : EvidenceStatus.NEGATIVE,
    value: { flags },
    severity: flagSeverity,
    confidence: 'LOW',
  }));

  items.push(createEvidence({
    source: EvidenceSource.LOCAL_ANALYSIS,
    indicator: 'HTTPS_ENABLED',
    status: urlInfo?.isHttps ? EvidenceStatus.NEGATIVE : EvidenceStatus.POSITIVE,
    value: { isHttps: urlInfo?.isHttps },
    severity: urlInfo?.isHttps ? 'INFO' : 'MODERATE',
    confidence: 'HIGH',
  }));

  return items;
}
