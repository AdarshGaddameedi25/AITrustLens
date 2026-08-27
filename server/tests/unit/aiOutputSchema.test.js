/**
 * Phase 3: Zod AI Output Schema — unit tests
 */
import { describe, it, expect } from '@jest/globals';
import { AiExplanationSchema, validateAiOutput } from '../../src/utils/aiOutputSchema.js';

describe('AI Output Schema Validation (Phase 3)', () => {
  const valid = {
    summary: 'This URL appears safe.',
    riskExplanation: 'No malicious indicators found.',
    keyIndicators: ['No VT flags', 'Domain age > 5 years'],
    recommendations: ['Continue safe browsing'],
    limitations: ['URLScan unavailable'],
    confidence: 'HIGH',
  };

  it('accepts a valid AI response', () => {
    const { success } = validateAiOutput(valid);
    expect(success).toBe(true);
  });

  it('rejects missing summary field', () => {
    const { success, error } = validateAiOutput({ ...valid, summary: undefined });
    expect(success).toBe(false);
    expect(error).toContain('summary');
  });

  it('rejects extra fields (strict mode prevents data exfiltration)', () => {
    const { success } = validateAiOutput({ ...valid, injectedField: 'evil' });
    expect(success).toBe(false);
  });

  it('rejects invalid confidence value', () => {
    const { success } = validateAiOutput({ ...valid, confidence: 'SUPER_HIGH' });
    expect(success).toBe(false);
  });

  it('rejects summary exceeding max length', () => {
    const { success } = validateAiOutput({ ...valid, summary: 'x'.repeat(2001) });
    expect(success).toBe(false);
  });

  it('defaults confidence to LOW if omitted', () => {
    const { confidence, ...rest } = valid;
    const { success, data } = validateAiOutput(rest);
    expect(success).toBe(true);
    expect(data.confidence).toBe('LOW');
  });

  it('accepts empty arrays for keyIndicators and recommendations', () => {
    const { success } = validateAiOutput({ ...valid, keyIndicators: [], recommendations: [] });
    expect(success).toBe(true);
  });

  it('rejects non-string items in keyIndicators', () => {
    const { success } = validateAiOutput({ ...valid, keyIndicators: [42] });
    expect(success).toBe(false);
  });
});
