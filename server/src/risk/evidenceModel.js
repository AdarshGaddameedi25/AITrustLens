/**
 * Normalized Evidence Model — Phase 2
 *
 * Defines a common, structured format that every provider adapter must produce.
 * The Risk Engine consumes ONLY this format — never raw provider API responses.
 *
 * This is the "contract" between the Provider Layer and the Risk Engine.
 */

// ─── Evidence Status ──────────────────────────────────────────────────────────

/**
 * Possible statuses for an individual evidence piece.
 */
export const EvidenceStatus = {
  POSITIVE: 'POSITIVE',       // Evidence found and confirms a concern
  NEGATIVE: 'NEGATIVE',       // Evidence found and clears the concern
  WARNING: 'WARNING',         // Evidence found but inconclusive / mildly concerning
  UNAVAILABLE: 'UNAVAILABLE', // Provider not queried or API key missing
  RATE_LIMITED: 'RATE_LIMITED',
  ERROR: 'ERROR',             // Provider queried but threw an error
  CONFLICTING: 'CONFLICTING', // Multiple sources disagree on this indicator
  UNKNOWN: 'UNKNOWN',         // Queried but result cannot be interpreted
};

/**
 * Possible sources of evidence.
 */
export const EvidenceSource = {
  VIRUSTOTAL: 'VIRUSTOTAL',
  GOOGLE_SAFE_BROWSING: 'GOOGLE_SAFE_BROWSING',
  URLSCAN: 'URLSCAN',
  RDAP: 'RDAP',
  TLS_INSPECTION: 'TLS_INSPECTION',
  HIBP_PWNED_PASSWORDS: 'HIBP_PWNED_PASSWORDS',
  GOOGLE_FACTCHECK: 'GOOGLE_FACTCHECK',
  LOCAL_ANALYSIS: 'LOCAL_ANALYSIS',
  HEADER_ANALYSIS: 'HEADER_ANALYSIS',
  URL_PATTERN: 'URL_PATTERN',
};

/**
 * Reliability tiers for sources. Used in the confidence model.
 */
export const SourceReliability = {
  VIRUSTOTAL: 'HIGH',
  GOOGLE_SAFE_BROWSING: 'HIGH',
  URLSCAN: 'MEDIUM',
  RDAP: 'MEDIUM',
  TLS_INSPECTION: 'HIGH',
  HIBP_PWNED_PASSWORDS: 'HIGH',
  GOOGLE_FACTCHECK: 'HIGH',
  LOCAL_ANALYSIS: 'MEDIUM',
  HEADER_ANALYSIS: 'MEDIUM',
  URL_PATTERN: 'LOW',
};

// ─── Factory Functions ────────────────────────────────────────────────────────

/**
 * Creates a normalized evidence piece.
 *
 * @param {object} params
 * @param {string} params.source       — EvidenceSource key
 * @param {string} params.category     — e.g. "MALWARE", "PHISHING", "TLS", "DOMAIN_AGE"
 * @param {string} params.indicator    — human-readable name of the indicator
 * @param {string} params.status       — EvidenceStatus
 * @param {*}      [params.value]      — raw value for this indicator (e.g. 3, true, "THREAT_FOUND")
 * @param {string} [params.interpretation] — brief human-readable meaning
 * @param {number} [params.freshness]  — age of data in seconds (0 = fresh)
 * @param {*}      [params.rawRef]     — raw provider response for audit purposes
 */
export function createEvidence({
  source,
  indicator,
  value = null,
  severity = 'INFO',
  confidence = 'MEDIUM',
  status = EvidenceStatus.AVAILABLE,
  timestamp = new Date().toISOString(),
  freshness = 0,
  rawRef = null,
  // Backward compatible inputs:
  category,
  interpretation = null,
}) {
  return {
    source,
    indicator,
    value,
    severity,
    confidence,
    status,
    timestamp,
    freshness,
    rawRef,
    // Keep old fields for backward compatibility while refactoring
    category,
    interpretation,
    reliability: SourceReliability[source] || 'LOW',
    checkedAt: timestamp,
  };
}

/**
 * Creates a normalized evidence piece representing an unavailable source.
 */
export function createUnavailableEvidence(source, category, indicator, reason = 'Provider unavailable') {
  return createEvidence({
    source,
    category,
    indicator,
    status: EvidenceStatus.UNAVAILABLE,
    interpretation: reason,
  });
}

/**
 * Creates a normalized evidence piece representing a provider error.
 */
export function createErrorEvidence(source, category, indicator, errorMessage) {
  return createEvidence({
    source,
    category,
    indicator,
    status: EvidenceStatus.ERROR,
    interpretation: `Provider error: ${errorMessage}`,
  });
}

// ─── Evidence Collection Result ───────────────────────────────────────────────

/**
 * Wraps the full normalized evidence set returned after all providers are queried.
 * The Risk Engine operates on this structure.
 *
 * @param {object} params
 * @param {Array}  params.items         — array of normalized evidence objects
 * @param {string} params.scanType
 * @param {object} [params.metadata]    — additional context (url, hostname, etc.)
 */
export function createEvidenceCollection({ items = [], scanType, metadata = {} }) {
  const totalSources = new Set(items.map((e) => e.source)).size;
  const availableSources = new Set(
    items.filter((e) => e.status !== EvidenceStatus.UNAVAILABLE && e.status !== EvidenceStatus.ERROR).map((e) => e.source)
  ).size;

  return {
    items,
    scanType,
    metadata,
    totalSources,
    availableSources,
    evidenceCoverage: totalSources > 0 ? Math.round((availableSources / totalSources) * 100) : 0,
    collectedAt: new Date().toISOString(),
    
    // Helper for risk rules to easily fetch normalized values
    getIndicatorValue: (indicatorName) => {
      const item = items.find((e) => e.indicator === indicatorName);
      if (!item || item.status === EvidenceStatus.UNAVAILABLE || item.status === EvidenceStatus.ERROR) {
        return null;
      }
      return item.value;
    },
    
    // Helper to fetch the full indicator object
    getIndicator: (indicatorName) => items.find((e) => e.indicator === indicatorName),
  };
}

// ─── Conflict Detection ───────────────────────────────────────────────────────

/**
 * Detects conflicting evidence across sources for the same category.
 * Returns an array of conflict descriptions.
 *
 * Example: VT says malicious, but Safe Browsing says clean.
 * @param {Array} evidenceItems
 */
export function detectConflicts(evidenceItems) {
  const byIndicator = {};
  for (const e of evidenceItems) {
    if (!byIndicator[e.indicator]) byIndicator[e.indicator] = [];
    byIndicator[e.indicator].push(e);
  }

  const conflicts = [];
  
  // Cross-provider conflicts (e.g. Malicious vs Safe)
  const highSeverity = evidenceItems.filter((e) => e.severity === 'CRITICAL' || e.severity === 'HIGH');
  const lowSeverity = evidenceItems.filter((e) => e.severity === 'LOW' || e.severity === 'INFO');
  
  if (highSeverity.length > 0 && lowSeverity.length > 0) {
     // Ensure they are actually conflicting on the same general topic (e.g. both are reputation engines)
     const highSources = Array.from(new Set(highSeverity.map(e => e.source)));
     const lowSources = Array.from(new Set(lowSeverity.map(e => e.source)));
     
     // Only flag if they are distinct sources
     if (!highSources.every(s => lowSources.includes(s))) {
       conflicts.push({
         type: 'PROVIDER_CONFLICT',
         highSeverityFrom: highSources,
         lowSeverityFrom: lowSources,
         description: `⚠ Conflicting evidence: ${highSources.join(', ')} flagged significant risk, while ${lowSources.join(', ')} reported clean/low risk.`,
       });
     }
  }

  return conflicts;
}
