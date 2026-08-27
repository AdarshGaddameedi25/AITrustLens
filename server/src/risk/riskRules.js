/**
 * Risk Rules Configuration — Phase 3 Integrity Update
 *
 * Defines all scoring rules, weights, and thresholds for the deterministic
 * risk assessment engine.
 *
 * Now consumes normalized EvidenceCollection data, allowing unified access
 * regardless of the underlying raw provider API schema.
 */

// Bump version when rules or weights change to maintain historical reproducibility
export const RISK_ENGINE_VERSION = 'RISK_ENGINE_V2';

export const RISK_RULES = {
  // ── VirusTotal ──────────────────────────────────────────────────────────────
  VIRUSTOTAL_MALICIOUS_DETECTIONS: {
    id: 'VIRUSTOTAL_MALICIOUS_DETECTIONS',
    name: 'VirusTotal Malicious Detections',
    source: 'VIRUSTOTAL',
    description: 'Number of security engines that flagged this URL/domain as malicious.',
    weight: 0.35,
    calculate: (evidenceCollection) => {
      const val = evidenceCollection.getIndicatorValue('VT_MALICIOUS_COUNT');
      if (!val) return null;
      const { maliciousCount, totalEngines } = val;
      
      const ratio = maliciousCount / totalEngines;
      if (maliciousCount === 0) return 0;
      if (maliciousCount >= 10 || ratio >= 0.3) return 100;
      if (maliciousCount >= 5 || ratio >= 0.15) return 80;
      if (maliciousCount >= 2 || ratio >= 0.05) return 60;
      return 30;
    },
  },

  VIRUSTOTAL_SUSPICIOUS_DETECTIONS: {
    id: 'VIRUSTOTAL_SUSPICIOUS_DETECTIONS',
    name: 'VirusTotal Suspicious Detections',
    source: 'VIRUSTOTAL',
    weight: 0.10,
    calculate: (evidenceCollection) => {
      const val = evidenceCollection.getIndicatorValue('VT_SUSPICIOUS_COUNT');
      if (!val) return null;
      const count = val.suspiciousCount;
      if (count === 0) return 0;
      if (count >= 5) return 70;
      if (count >= 2) return 40;
      return 20;
    },
  },

  // ── Google Safe Browsing ────────────────────────────────────────────────────
  SAFE_BROWSING_THREAT: {
    id: 'SAFE_BROWSING_THREAT',
    name: 'Google Safe Browsing Threat',
    source: 'GOOGLE_SAFE_BROWSING',
    weight: 0.25,
    calculate: (evidenceCollection) => {
      const indicator = evidenceCollection.getIndicator('SB_THREAT_STATUS');
      if (!indicator || indicator.status === 'UNAVAILABLE' || indicator.status === 'ERROR') return null;
      return indicator.status === 'POSITIVE' ? 100 : 0;
    },
  },

  // ── URL Pattern Analysis ────────────────────────────────────────────────────
  URL_PATTERN_SUSPICIOUS: {
    id: 'URL_PATTERN_SUSPICIOUS',
    name: 'Suspicious URL Pattern',
    source: 'LOCAL_ANALYSIS',
    weight: 0.08,
    calculate: (evidenceCollection) => {
      const val = evidenceCollection.getIndicatorValue('URL_SUSPICIOUS_PATTERNS');
      if (!val) return null;
      const flags = val.flags;
      if (flags.length === 0) return 0;
      
      let score = 0;
      if (flags.includes('IP_ADDRESS_HOSTNAME')) score += 40;
      if (flags.includes('CREDENTIAL_EMBEDDING')) score += 50;
      if (flags.includes('EXCESSIVE_SUBDOMAINS')) score += 20;
      if (flags.includes('SUSPICIOUS_TLD')) score += 25;
      if (flags.some((f) => f.startsWith('LOOKALIKE_BRAND'))) score += 35;
      if (flags.includes('VERY_LONG_URL')) score += 10;
      return Math.min(score, 100);
    },
  },

  // ── HTTPS / TLS ─────────────────────────────────────────────────────────────
  HTTPS_MISSING: {
    id: 'HTTPS_MISSING',
    name: 'No HTTPS',
    source: 'LOCAL_ANALYSIS',
    weight: 0.07,
    calculate: (evidenceCollection) => {
      const val = evidenceCollection.getIndicatorValue('HTTPS_ENABLED');
      if (!val) return null;
      return val.isHttps === false ? 70 : 0;
    },
  },

  TLS_INVALID: {
    id: 'TLS_INVALID',
    name: 'TLS Certificate Issue',
    source: 'TLS_INSPECTION',
    weight: 0.06,
    calculate: (evidenceCollection) => {
      const val = evidenceCollection.getIndicatorValue('TLS_CERTIFICATE');
      if (!val) return null;
      
      if (val.expired) return 80;
      if (!val.authorized) return 60;
      if (val.selfSigned) return 40;
      if (val.daysUntilExpiry !== null && val.daysUntilExpiry < 7) return 30;
      return 0;
    },
  },

  // ── Domain Age ──────────────────────────────────────────────────────────────
  DOMAIN_AGE_VERY_NEW: {
    id: 'DOMAIN_AGE_VERY_NEW',
    name: 'Recently Registered Domain',
    source: 'RDAP',
    weight: 0.05,
    calculate: (evidenceCollection) => {
      const val = evidenceCollection.getIndicatorValue('DOMAIN_REGISTRATION_AGE');
      if (!val || val.domainAgeDays === null || val.domainAgeDays === undefined) return null;
      
      const ageDays = val.domainAgeDays;
      if (ageDays < 7) return 85;
      if (ageDays < 30) return 60;
      if (ageDays < 90) return 30;
      if (ageDays < 365) return 10;
      return 0;
    },
  },

  // ── URLScan ─────────────────────────────────────────────────────────────────
  URLSCAN_MALICIOUS: {
    id: 'URLSCAN_MALICIOUS',
    name: 'URLScan Malicious Verdict',
    source: 'URLSCAN',
    weight: 0.04,
    calculate: (evidenceCollection) => {
      const val = evidenceCollection.getIndicatorValue('URLSCAN_VERDICT');
      if (!val) return null;
      
      if (val.malicious === true) return 90;
      if (val.score > 50) return 50;
      return 0;
    },
  },
};

// Trust Score thresholds
export const TRUST_SCORE_THRESHOLDS = {
  CRITICAL: { min: 0, max: 29, label: 'CRITICAL RISK', color: 'critical' },
  HIGH: { min: 30, max: 49, label: 'HIGH RISK', color: 'high' },
  MODERATE: { min: 50, max: 69, label: 'MODERATE RISK', color: 'moderate' },
  LOW: { min: 70, max: 84, label: 'LOW RISK', color: 'low' },
  HIGH_TRUST: { min: 85, max: 100, label: 'HIGH TRUST', color: 'trust' },
};

export function getRiskLevel(trustScore) {
  for (const [level, range] of Object.entries(TRUST_SCORE_THRESHOLDS)) {
    if (trustScore >= range.min && trustScore <= range.max) {
      return level;
    }
  }
  return 'MODERATE';
}

export { IDENTITY_RISK_RULES } from './identityRiskRules.js';
export const EMAIL_RISK_RULES = {};
export const SCAM_RISK_RULES = {};
export const PRIVACY_RISK_RULES = {};

