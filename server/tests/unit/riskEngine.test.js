import { calculateRiskAssessment } from '../../src/risk/riskEngine.js';
import { EvidenceStatus } from '../../src/risk/evidenceModel.js';

describe('Risk Engine Deterministic Scoring (Phase 0)', () => {
  
  // Helper to create a mock EvidenceCollection
  const createMockEvidenceCollection = (indicatorValues, conflicts = []) => ({
    getIndicatorValue: (name) => indicatorValues[name] !== undefined ? indicatorValues[name] : null,
    getIndicator: (name) => {
      // For Safe Browsing check which uses getIndicator directly
      if (name === 'SB_THREAT_STATUS') {
         if (indicatorValues['SB_THREAT_STATUS'] === undefined) return null;
         return { status: indicatorValues['SB_THREAT_STATUS'] ? EvidenceStatus.POSITIVE : EvidenceStatus.NEGATIVE };
      }
      return null;
    },
    conflicts,
    evidenceCoverage: 100, // Mocked for calculation
  });

  test('Fully Safe URL - Should return 100 Trust Score', () => {
    const evidence = createMockEvidenceCollection({
      'VT_MALICIOUS_COUNT': { maliciousCount: 0, totalEngines: 90 },
      'VT_SUSPICIOUS_COUNT': { suspiciousCount: 0 },
      'SB_THREAT_STATUS': false, // Negative threat
      'URL_SUSPICIOUS_PATTERNS': { flags: [] },
      'HTTPS_ENABLED': { isHttps: true },
      'TLS_CERTIFICATE': { expired: false, authorized: true, selfSigned: false, daysUntilExpiry: 300 },
      'DOMAIN_REGISTRATION_AGE': { domainAgeDays: 500 },
      'URLSCAN_VERDICT': { malicious: false, score: 0 }
    });

    const result = calculateRiskAssessment(evidence, 'URL');
    expect(result.rawRiskScore).toBe(0);
    expect(result.trustScore).toBe(100);
    expect(result.riskLevel).toBe('HIGH_TRUST');
  });

  test('Fully Malicious URL - Should return 0 Trust Score', () => {
    const evidence = createMockEvidenceCollection({
      'VT_MALICIOUS_COUNT': { maliciousCount: 15, totalEngines: 90 }, // Penalty 100 (Weight 0.35)
      'VT_SUSPICIOUS_COUNT': { suspiciousCount: 10 }, // Penalty 70 (Weight 0.10)
      'SB_THREAT_STATUS': true, // Penalty 100 (Weight 0.25)
      'URL_SUSPICIOUS_PATTERNS': { flags: ['IP_ADDRESS_HOSTNAME', 'CREDENTIAL_EMBEDDING', 'SUSPICIOUS_TLD'] }, // Penalty 100 (capped) (Weight 0.08)
      'HTTPS_ENABLED': { isHttps: false }, // Penalty 70 (Weight 0.07)
      'TLS_CERTIFICATE': { expired: true, authorized: false, selfSigned: true, daysUntilExpiry: 0 }, // Penalty 80 (Weight 0.06)
      'DOMAIN_REGISTRATION_AGE': { domainAgeDays: 2 }, // Penalty 85 (Weight 0.05)
      'URLSCAN_VERDICT': { malicious: true, score: 100 } // Penalty 90 (Weight 0.04)
    });

    const result = calculateRiskAssessment(evidence, 'URL');
    
    // Calculate expected weighted sum:
    // VT_MAL: 100 * 0.35 = 35
    // VT_SUS: 70 * 0.10 = 7
    // SB_THR: 100 * 0.25 = 25
    // URL_PT: 100 * 0.08 = 8
    // HTTPS: 70 * 0.07 = 4.9
    // TLS: 80 * 0.06 = 4.8
    // DOMAIN: 85 * 0.05 = 4.25
    // URLSCAN: 90 * 0.04 = 3.6
    // Sum = 92.55. Normalized = 92.55 (since total weight is 1.0)
    // Trust Score = 100 - 93 = 7

    expect(result.rawRiskScore).toBe(93);
    expect(result.trustScore).toBe(7);
    expect(result.riskLevel).toBe('CRITICAL');
  });

  test('Missing Evidence Normalization (Partial Outage)', () => {
    // Only VT is available, and it says 100 penalty.
    // If the system works correctly, 100 penalty on the only available evidence means 100 Raw Risk.
    const evidence = createMockEvidenceCollection({
      'VT_MALICIOUS_COUNT': { maliciousCount: 15, totalEngines: 90 }, // Penalty 100 (Weight 0.35)
      // ALL OTHERS ARE NULL (Simulating API failure)
    });

    const result = calculateRiskAssessment(evidence, 'URL');
    
    // totalWeight = 0.35
    // weightedSum = 35
    // Normalized = 35 / 0.35 = 100.
    
    expect(result.rawRiskScore).toBe(100);
    expect(result.trustScore).toBe(0);
    expect(result.evidenceCoverage).toBe(35); // 0.35/1.0 * 100
  });

  test('No Evidence Available - Should fallback to 50 (Moderate Risk)', () => {
    const evidence = createMockEvidenceCollection({}); // All null

    const result = calculateRiskAssessment(evidence, 'URL');
    
    expect(result.rawRiskScore).toBe(50);
    expect(result.trustScore).toBe(50);
    expect(result.evidenceCoverage).toBe(0);
  });

  test('Conflict Detection', () => {
    // VT says extremely malicious (100 penalty), but SB says extremely safe (0 penalty)
    const evidence = createMockEvidenceCollection({
      'VT_MALICIOUS_COUNT': { maliciousCount: 15, totalEngines: 90 }, // 100 penalty
      'SB_THREAT_STATUS': false // 0 penalty
    });

    const result = calculateRiskAssessment(evidence, 'URL');
    
    expect(result.conflicts.length).toBeGreaterThan(0);
    expect(result.conflicts[0].type).toBe('MATHEMATICAL_CONFLICT');
    expect(result.confidence).toBe('LOW'); // Confidence drops strictly because of conflict
  });
});
