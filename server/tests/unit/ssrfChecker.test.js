/**
 * Unit Tests — SSRF Checker
 * Verifies that dangerous internal/cloud URLs are blocked and legitimate URLs pass.
 */

import { validateSsrfSafeUrl } from '../../src/utils/ssrfChecker.js';

// ─── Blocked URLs (should throw) ─────────────────────────────────────────────

describe('SSRF Checker — Blocked addresses', () => {
  const blockedUrls = [
    'http://localhost',
    'http://localhost:3000',
    'http://localhost/admin',
    'http://127.0.0.1',
    'http://127.0.0.1:8080/secret',
    'http://0.0.0.0',
    'http://169.254.169.254',
    'http://169.254.169.254/latest/meta-data/',   // AWS metadata
    'http://[::1]',
    'http://192.168.1.1',
    'http://10.0.0.1',
    'http://172.16.0.1',
  ];

  for (const url of blockedUrls) {
    test(`blocks internal URL: ${url}`, async () => {
      await expect(validateSsrfSafeUrl(url)).rejects.toThrow();
    });
  }

  test('blocks non-HTTP scheme: ftp://', async () => {
    await expect(validateSsrfSafeUrl('ftp://example.com/resource')).rejects.toThrow();
  });

  test('blocks non-HTTP scheme: file://', async () => {
    await expect(validateSsrfSafeUrl('file:///etc/passwd')).rejects.toThrow();
  });
});

// ─── Allowed URLs (should pass) ───────────────────────────────────────────────

describe('SSRF Checker — Allowed public addresses', () => {
  const allowedUrls = [
    'https://www.google.com',
    'https://www.microsoft.com',
    'http://example.com',
    'https://1.1.1.1',
  ];

  for (const url of allowedUrls) {
    test(`allows public URL: ${url}`, async () => {
      // Should not throw — use resolves.not.toThrow() 
      await expect(validateSsrfSafeUrl(url)).resolves.not.toThrow();
    });
  }
});
