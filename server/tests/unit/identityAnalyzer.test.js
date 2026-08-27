/**
 * Digital Identity & Email Domain Security Analyzer Unit Tests
 */

import { IDENTITY_RISK_RULES } from '../../src/risk/identityRiskRules.js';
import { calculateRiskAssessment } from '../../src/risk/riskEngine.js';
import { validate, identityAnalysisSchema } from '../../src/validators/inputValidator.js';

describe('Digital Identity Risk Engine & Rules', () => {
  test('Full Evidence Available — Safe Corporate Domain with MX, SPF, and DMARC', () => {
    const evidenceCollection = {
      email: 'security@company.com',
      domain: 'company.com',
      items: [
        { indicator: 'EMAIL_FORMAT_VALIDITY', status: 'VERIFIED', value: { validFormat: true } },
        { indicator: 'DOMAIN_CLASSIFICATION', status: 'VERIFIED', value: { isDisposable: false, isFreeProvider: false, isCustomDomain: true } },
        { indicator: 'DNS_MX_RECORDS', status: 'VERIFIED', value: { hasMx: true, recordCount: 2, exchanges: ['mail.company.com'] } },
        { indicator: 'DNS_SPF_RECORD', status: 'VERIFIED', value: { hasSpf: true, isStrict: true, isSoftFail: false } },
        { indicator: 'DNS_DMARC_RECORD', status: 'VERIFIED', value: { hasDmarc: true, policy: 'reject' } },
        { indicator: 'IDENTITY_BREACH_STATUS', status: 'UNAVAILABLE', reason: 'Public API required' },
      ],
    };

    const assessment = calculateRiskAssessment(evidenceCollection, 'DIGITAL_IDENTITY');

    expect(assessment.trustScore).toBe(100);
    expect(assessment.riskLevel).toBe('HIGH_TRUST');
    expect(assessment.availableIndicators).toBe(4);
    expect(assessment.evidenceCoverage).toBe(100);
    expect(assessment.confidence).toBe('HIGH');
  });

  test('Disposable Email Service — Should produce Critical Risk', () => {
    const evidenceCollection = {
      email: 'test@mailinator.com',
      domain: 'mailinator.com',
      items: [
        { indicator: 'EMAIL_FORMAT_VALIDITY', status: 'VERIFIED', value: { validFormat: true } },
        { indicator: 'DOMAIN_CLASSIFICATION', status: 'VERIFIED', value: { isDisposable: true, isFreeProvider: false } },
        { indicator: 'DNS_MX_RECORDS', status: 'VERIFIED', value: { hasMx: true, recordCount: 1 } },
        { indicator: 'DNS_SPF_RECORD', status: 'VERIFIED', value: { hasSpf: false } },
        { indicator: 'DNS_DMARC_RECORD', status: 'VERIFIED', value: { hasDmarc: false } },
      ],
    };

    const assessment = calculateRiskAssessment(evidenceCollection, 'DIGITAL_IDENTITY');

    expect(assessment.trustScore).toBeLessThanOrEqual(40);
    expect(['CRITICAL', 'HIGH']).toContain(assessment.riskLevel);
  });

  test('Missing MX Records — Should severely penalize score', () => {
    const evidenceCollection = {
      email: 'admin@unroutable-domain-example-xyz.com',
      domain: 'unroutable-domain-example-xyz.com',
      items: [
        { indicator: 'DOMAIN_CLASSIFICATION', status: 'VERIFIED', value: { isDisposable: false, isFreeProvider: false } },
        { indicator: 'DNS_MX_RECORDS', status: 'VERIFIED', value: { hasMx: false, recordCount: 0 } },
        { indicator: 'DNS_SPF_RECORD', status: 'VERIFIED', value: { hasSpf: false } },
        { indicator: 'DNS_DMARC_RECORD', status: 'VERIFIED', value: { hasDmarc: false } },
      ],
    };

    const assessment = calculateRiskAssessment(evidenceCollection, 'DIGITAL_IDENTITY');
    expect(assessment.trustScore).toBeLessThanOrEqual(50);
  });

  test('Provider/DNS Unavailable — Confidence downgrades according to coverage', () => {
    const partialEvidence = {
      email: 'user@slow-dns.com',
      domain: 'slow-dns.com',
      items: [
        { indicator: 'DOMAIN_CLASSIFICATION', status: 'VERIFIED', value: { isDisposable: false, isFreeProvider: false } },
        { indicator: 'DNS_MX_RECORDS', status: 'UNAVAILABLE', reason: 'DNS timeout' },
        { indicator: 'DNS_SPF_RECORD', status: 'UNAVAILABLE', reason: 'DNS timeout' },
        { indicator: 'DNS_DMARC_RECORD', status: 'UNAVAILABLE', reason: 'DNS timeout' },
      ],
    };

    const assessment = calculateRiskAssessment(partialEvidence, 'DIGITAL_IDENTITY');

    // Only 1 rule available (DISPOSABLE_EMAIL_DOMAIN)
    expect(assessment.availableIndicators).toBe(1);
    expect(assessment.evidenceCoverage).toBeLessThan(50);
    expect(['LOW', 'INSUFFICIENT']).toContain(assessment.confidence);
  });
});

describe('Digital Identity Input Validation', () => {
  test('Accepts valid email addresses', () => {
    const validEmails = ['user@example.com', 'first.last@company.org', 'test+tag@gmail.com'];
    for (const email of validEmails) {
      const { data, error } = validate(identityAnalysisSchema, { email });
      expect(error).toBeNull();
      expect(data.email).toBe(email);
    }
  });

  test('Rejects invalid or malformed email addresses', () => {
    const invalidInputs = ['', 'not-an-email', '@missinguser.com', 'missingdomain@', 'spaces in@email.com'];
    for (const email of invalidInputs) {
      const { error } = validate(identityAnalysisSchema, { email });
      expect(error).not.toBeNull();
    }
  });
});
