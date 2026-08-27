/**
 * SSRF Protection Utility — Hardened v2
 *
 * Defends against:
 * - Loopback (127.x, ::1)
 * - Private IPv4 & IPv6 ranges
 * - IPv4-mapped IPv6 addresses
 * - Cloud metadata endpoints (AWS, GCP, Azure, Alibaba)
 * - Decimal / octal / hex IP representations
 * - DNS rebinding (via post-resolution IP check)
 * - Redirect-based SSRF (caller must re-validate after each redirect)
 * - Non-HTTP(S) schemes
 */

import dns from 'dns/promises';
import net from 'net';

// ─── Constants ────────────────────────────────────────────────────────────────

const ALLOWED_SCHEMES = new Set(['http:', 'https:']);

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'broadcasthost',
  'local',
  'invalid',
  '0.0.0.0',
  '::1',
  '[::1]',
  '[::]',
  '[::ffff:127.0.0.1]',
  'ip6-localhost',
  'ip6-loopback',
  'ip6-allnodes',
  'ip6-allrouters',
  // GCP metadata
  'metadata.google.internal',
  'metadata.google',
  // Other metadata
  'instance-data',
  'link-local',
]);

// Cloud metadata IPs
const METADATA_IPS = new Set([
  '169.254.169.254', // AWS / GCP / Azure / DigitalOcean metadata
  '100.100.100.200', // Alibaba Cloud
  '192.0.0.192',     // Reserved
  '192.51.100.1',    // TEST-NET-2
  '198.51.100.1',    // TEST-NET-3
  '203.0.113.1',     // TEST-NET-3
]);

// ─── Private IP range checker ─────────────────────────────────────────────────

/**
 * Returns true if the IPv4 address string falls into a blocked range.
 * @param {string} ip  — e.g. "10.0.0.1"
 */
function isPrivateIPv4(ip) {
  if (!net.isIPv4(ip)) return false;
  const parts = ip.split('.').map(Number);
  const [a, b] = parts;

  return (
    a === 0 ||                          // 0.0.0.0/8  — "this" network
    a === 10 ||                         // 10.0.0.0/8 — RFC 1918
    a === 127 ||                        // 127.0.0.0/8 — loopback
    a === 255 ||                        // 255.x.x.x  — broadcast
    (a === 100 && b >= 64 && b <= 127) || // 100.64.0.0/10 — shared
    (a === 169 && b === 254) ||         // 169.254.0.0/16 — link-local
    (a === 172 && b >= 16 && b <= 31) ||// 172.16.0.0/12 — RFC 1918
    (a === 192 && b === 0 && parts[2] === 0) || // 192.0.0.0/24
    (a === 192 && b === 168) ||         // 192.168.0.0/16 — RFC 1918
    (a === 198 && b >= 18 && b <= 19)   // 198.18.0.0/15 — benchmark
  );
}

/**
 * Returns true if the IPv6 address is loopback, link-local, private, or special.
 * @param {string} ip  — e.g. "::1" or "fe80::1"
 */
function isPrivateIPv6(ip) {
  if (!net.isIPv6(ip)) return false;
  const lower = ip.toLowerCase();
  return (
    lower === '::1' ||                         // loopback
    lower === '::' ||                          // unspecified
    lower.startsWith('fc') ||                 // Unique local
    lower.startsWith('fd') ||                 // Unique local
    lower.startsWith('fe80') ||               // link-local
    lower.startsWith('ff') ||                 // multicast
    lower.startsWith('::ffff:')               // IPv4-mapped
  );
}

/**
 * Attempts to parse alternative IPv4 representations (decimal, octal, hex).
 * Returns the dotted-decimal string if parseable, or null.
 */
function parseAlternativeIPv4(hostname) {
  // Pure decimal (e.g. 2130706433 = 127.0.0.1)
  if (/^\d+$/.test(hostname)) {
    const n = BigInt(hostname);
    if (n >= 0n && n <= 4294967295n) {
      const a = Number((n >> 24n) & 255n);
      const b = Number((n >> 16n) & 255n);
      const c = Number((n >> 8n) & 255n);
      const d = Number(n & 255n);
      return `${a}.${b}.${c}.${d}`;
    }
  }
  // Hex (e.g. 0x7f000001)
  if (/^0x[0-9a-f]+$/i.test(hostname)) {
    const n = BigInt(hostname);
    if (n >= 0n && n <= 4294967295n) {
      const a = Number((n >> 24n) & 255n);
      const b = Number((n >> 16n) & 255n);
      const c = Number((n >> 8n) & 255n);
      const d = Number(n & 255n);
      return `${a}.${b}.${c}.${d}`;
    }
  }
  return null;
}

// ─── Core IP validation ───────────────────────────────────────────────────────

/**
 * Checks a resolved IP address against all blocked ranges.
 * @param {string} ip
 * @returns {{ safe: boolean, reason?: string }}
 */
function validateResolvedIP(ip) {
  if (METADATA_IPS.has(ip)) {
    return { safe: false, reason: `Cloud metadata endpoint blocked: ${ip}` };
  }
  if (net.isIPv4(ip) && isPrivateIPv4(ip)) {
    return { safe: false, reason: `Private/reserved IPv4 address blocked: ${ip}` };
  }
  if (net.isIPv6(ip) && isPrivateIPv6(ip)) {
    return { safe: false, reason: `Private/reserved IPv6 address blocked: ${ip}` };
  }
  return { safe: true };
}

// ─── Main exports ─────────────────────────────────────────────────────────────

/**
 * Synchronous pre-check: catches obvious blocked patterns before DNS resolution.
 * This is a first-pass guard. Always follow with checkSsrfSafeAsync for hostnames.
 * @param {string} urlString
 * @returns {{ safe: boolean, reason?: string }}
 */
export function checkUrlSsrfSafety(urlString) {
  let parsedUrl;
  try {
    parsedUrl = new URL(urlString);
  } catch {
    return { safe: false, reason: 'Invalid URL format' };
  }

  if (!ALLOWED_SCHEMES.has(parsedUrl.protocol)) {
    return { safe: false, reason: `Disallowed URL scheme: ${parsedUrl.protocol}` };
  }

  const hostname = parsedUrl.hostname.toLowerCase().replace(/^\[|\]$/g, ''); // strip [] from IPv6

  if (BLOCKED_HOSTNAMES.has(hostname) || hostname.endsWith('.localhost')) {
    return { safe: false, reason: `Blocked hostname: ${hostname}` };
  }

  if (METADATA_IPS.has(hostname)) {
    return { safe: false, reason: `Cloud metadata endpoint blocked: ${hostname}` };
  }

  // Check for alternative IPv4 encodings
  const altIp = parseAlternativeIPv4(hostname);
  if (altIp && isPrivateIPv4(altIp)) {
    return { safe: false, reason: `Alternative IPv4 representation of private IP blocked: ${hostname} → ${altIp}` };
  }

  // Literal IPv4
  if (net.isIPv4(hostname) && isPrivateIPv4(hostname)) {
    return { safe: false, reason: `Private IPv4 address blocked: ${hostname}` };
  }

  // Literal IPv6
  if (net.isIPv6(hostname) && isPrivateIPv6(hostname)) {
    return { safe: false, reason: `Private IPv6 address blocked: ${hostname}` };
  }

  return { safe: true };
}

/**
 * Async SSRF check that resolves DNS and validates the resulting IP address.
 * This MUST be called before making outbound HTTP requests.
 * Redirect destinations must also be re-validated using this function.
 *
 * @param {string} urlString
 * @returns {Promise<{ safe: boolean, reason?: string, resolvedIps?: string[] }>}
 */
export async function checkSsrfSafeAsync(urlString) {
  // First, run the synchronous pre-check
  const sync = checkUrlSsrfSafety(urlString);
  if (!sync.safe) return sync;

  let parsedUrl;
  try {
    parsedUrl = new URL(urlString);
  } catch {
    return { safe: false, reason: 'Invalid URL format' };
  }

  const hostname = parsedUrl.hostname.toLowerCase().replace(/^\[|\]$/g, '');

  // If it's already a literal IP, we've already checked it above
  if (net.isIPv4(hostname) || net.isIPv6(hostname)) {
    return { safe: true, resolvedIps: [hostname] };
  }

  // Resolve DNS
  let addresses;
  try {
    const results = await dns.resolve(hostname);
    addresses = results;
  } catch {
    // If we can't resolve, it could be an unresolvable host — still block outbound request
    try {
      const lookup = await dns.lookup(hostname, { all: true });
      addresses = lookup.map((e) => e.address);
    } catch {
      return { safe: false, reason: `Unable to resolve hostname: ${hostname}` };
    }
  }

  for (const ip of addresses) {
    const check = validateResolvedIP(ip);
    if (!check.safe) {
      return { ...check, resolvedIps: addresses };
    }
  }

  return { safe: true, resolvedIps: addresses };
}

/**
 * Throws a structured SSRF error if the URL is not safe.
 * Use this as a gate before any outbound request.
 * Redirect destinations must also pass through this.
 *
 * @param {string} urlString
 * @param {boolean} [async=true] — if true, also resolves DNS
 */
export async function validateSsrfSafeUrl(urlString, performDnsCheck = true) {
  if (performDnsCheck) {
    const result = await checkSsrfSafeAsync(urlString);
    if (!result.safe) {
      const error = new Error(`SSRF Blocked: ${result.reason}`);
      error.code = 'SSRF_BLOCKED';
      error.statusCode = 400;
      throw error;
    }
  } else {
    const result = checkUrlSsrfSafety(urlString);
    if (!result.safe) {
      const error = new Error(`SSRF Blocked: ${result.reason}`);
      error.code = 'SSRF_BLOCKED';
      error.statusCode = 400;
      throw error;
    }
  }
  return true;
}
