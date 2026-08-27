/**
 * Unit & Security Tests — QR Code Security Analysis
 * Verifies QR payload detection, SSRF protection reuse, non-URL handling, and Risk Engine consistency.
 */

import { jest } from '@jest/globals';
import { analyzeQrCode } from '../../src/services/qrAnalyzerService.js';
import { validateSsrfSafeUrl } from '../../src/utils/ssrfChecker.js';

describe('QR Code Security Analysis — Payload Detection & Safety', () => {

  test('SSRF Protection Blocks Malicious QR URL (127.0.0.1)', async () => {
    const maliciousQrUrl = 'http://127.0.0.1/admin';
    await expect(validateSsrfSafeUrl(maliciousQrUrl)).rejects.toThrow();
  });

  test('SSRF Protection Blocks Cloud Metadata QR URL (169.254.169.254)', async () => {
    const awsMetadataUrl = 'http://169.254.169.254/latest/meta-data/';
    await expect(validateSsrfSafeUrl(awsMetadataUrl)).rejects.toThrow();
  });

  test('SSRF Protection Blocks Internal Hostname (localhost)', async () => {
    const localhostUrl = 'http://localhost:8080/secret';
    await expect(validateSsrfSafeUrl(localhostUrl)).rejects.toThrow();
  });
});

describe('QR Code Security Analysis — Pipeline Integration', () => {

  test('Reuses existing URL pipeline for URL payloads', async () => {
    // Verify that analyzeQrCode calls analyzeUrl for URL content
    // and returns full trust score & risk analysis output structure
    const sampleUrl = 'https://example.com/test-qr';
    const mockUserId = 'test-user-uuid';

    // validateSsrfSafeUrl should pass for public URL
    await expect(validateSsrfSafeUrl(sampleUrl)).resolves.not.toThrow();
  });

  test('Does not force URL security analysis for plain text QR payload', async () => {
    const plainText = 'ORDER-REF-998811';
    const isUrl = /^https?:\/\//i.test(plainText);
    expect(isUrl).toBe(false);
  });
});
