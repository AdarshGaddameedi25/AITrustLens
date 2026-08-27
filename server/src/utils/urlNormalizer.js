/**
 * URL normalization and validation utilities.
 */

/**
 * Normalizes a URL for consistent processing.
 * Adds https:// if no scheme is provided.
 * @param {string} rawUrl
 * @returns {string} normalized URL
 */
export function normalizeUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') {
    throw new Error('URL must be a non-empty string');
  }

  let url = rawUrl.trim();

  // Add scheme if missing
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = `https://${url}`;
  }

  // Parse and re-serialize for consistency
  const parsed = new URL(url);
  return parsed.href;
}

/**
 * Extracts the hostname from a URL.
 * @param {string} url
 * @returns {string} hostname
 */
export function extractHostname(url) {
  try {
    const parsed = new URL(url);
    return parsed.hostname;
  } catch {
    return '';
  }
}

/**
 * Checks whether a URL uses HTTPS.
 * @param {string} url
 * @returns {boolean}
 */
export function isHttps(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Checks for suspicious URL patterns common in phishing.
 * @param {string} url
 * @returns {{ suspicious: boolean, flags: string[] }}
 */
export function detectSuspiciousUrlPatterns(url) {
  const flags = [];

  // Excessive subdomains (potential brand spoofing)
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname;
    const parts = hostname.split('.');
    if (parts.length > 5) {
      flags.push('EXCESSIVE_SUBDOMAINS');
    }

    // IP address as hostname
    if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
      flags.push('IP_ADDRESS_HOSTNAME');
    }

    // Suspicious TLDs commonly used in phishing
    const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.loan'];
    if (suspiciousTlds.some((tld) => hostname.endsWith(tld))) {
      flags.push('SUSPICIOUS_TLD');
    }

    // Lookalike brand names in subdomain
    const brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'bank'];
    const subdomain = parts.slice(0, -2).join('.');
    for (const brand of brands) {
      if (subdomain.toLowerCase().includes(brand)) {
        flags.push(`LOOKALIKE_BRAND_IN_SUBDOMAIN:${brand}`);
      }
    }

    // @ symbol in URL (credential embedding)
    if (url.includes('@')) {
      flags.push('CREDENTIAL_EMBEDDING');
    }

    // URL encoded characters that may obfuscate
    if (parsed.pathname.includes('%') || parsed.search.includes('%2F')) {
      flags.push('ENCODED_PATH_CHARACTERS');
    }

    // Very long URLs
    if (url.length > 250) {
      flags.push('VERY_LONG_URL');
    }
  } catch {
    flags.push('INVALID_URL_STRUCTURE');
  }

  return { suspicious: flags.length > 0, flags };
}
