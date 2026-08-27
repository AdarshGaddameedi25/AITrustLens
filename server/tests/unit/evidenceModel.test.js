import { detectConflicts } from '../../src/risk/evidenceModel.js';

describe('Evidence Model Conflict Detection (Phase 1)', () => {

  test('Should detect cross-provider severity conflicts on same indicator', () => {
    const evidenceItems = [
      {
        source: 'VIRUSTOTAL',
        indicator: 'REPUTATION_TEST', // Mock indicator
        severity: 'CRITICAL',
        status: 'POSITIVE'
      },
      {
        source: 'GOOGLE_SAFE_BROWSING',
        indicator: 'REPUTATION_TEST',
        severity: 'INFO',
        status: 'NEGATIVE'
      }
    ];

    const conflicts = detectConflicts(evidenceItems);
    
    expect(conflicts.length).toBe(1);
    expect(conflicts[0].type).toBe('PROVIDER_CONFLICT');
    expect(conflicts[0].highSeverityFrom).toContain('VIRUSTOTAL');
    expect(conflicts[0].lowSeverityFrom).toContain('GOOGLE_SAFE_BROWSING');
  });

  test('Should not flag conflict if providers agree', () => {
    const evidenceItems = [
      {
        source: 'VIRUSTOTAL',
        indicator: 'REPUTATION_TEST',
        severity: 'CRITICAL'
      },
      {
        source: 'URLSCAN',
        indicator: 'REPUTATION_TEST',
        severity: 'HIGH'
      }
    ];

    const conflicts = detectConflicts(evidenceItems);
    expect(conflicts.length).toBe(0);
  });

  test('Should not flag conflict if different indicators from same source have different severities', () => {
    // E.g., URL_PATTERN might be INFO for HTTPS, but HIGH for Suspicious URL Patterns
    // The conflict detection must not cross-pollinate different sources just because one is HIGH and one is LOW, 
    // unless the sources themselves are distinct.
    const evidenceItems = [
      {
        source: 'LOCAL_ANALYSIS',
        indicator: 'HTTPS_ENABLED',
        severity: 'INFO'
      },
      {
        source: 'LOCAL_ANALYSIS',
        indicator: 'URL_SUSPICIOUS_PATTERNS',
        severity: 'HIGH'
      }
    ];

    const conflicts = detectConflicts(evidenceItems);
    expect(conflicts.length).toBe(0); // Because they are from the SAME source, it is not a cross-provider conflict.
  });

});
