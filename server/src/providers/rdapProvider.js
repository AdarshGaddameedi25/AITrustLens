/**
 * RDAP Provider
 * Retrieves domain registration information via RDAP (Registration Data Access Protocol).
 * Open standard — no API key required.
 */

import axios from 'axios';
import logger from '../utils/logger.js';

const IANA_RDAP_BOOTSTRAP = 'https://data.iana.org/rdap/dns.json';
const TIMEOUT_MS = 10000;
const BOOTSTRAP_CACHE = { data: null, fetchedAt: null };
const BOOTSTRAP_CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Gets the RDAP bootstrap data (maps TLDs to RDAP services).
 */
async function getBootstrapData() {
  const now = Date.now();
  if (
    BOOTSTRAP_CACHE.data &&
    BOOTSTRAP_CACHE.fetchedAt &&
    now - BOOTSTRAP_CACHE.fetchedAt < BOOTSTRAP_CACHE_TTL_MS
  ) {
    return BOOTSTRAP_CACHE.data;
  }

  try {
    const response = await axios.get(IANA_RDAP_BOOTSTRAP, { timeout: TIMEOUT_MS });
    BOOTSTRAP_CACHE.data = response.data;
    BOOTSTRAP_CACHE.fetchedAt = now;
    return response.data;
  } catch {
    return null;
  }
}

/**
 * Finds the RDAP service URL for a given domain.
 * @param {string} domain
 * @returns {Promise<string|null>}
 */
async function findRdapServiceUrl(domain) {
  const bootstrap = await getBootstrapData();
  if (!bootstrap?.services) return null;

  const tld = domain.split('.').slice(-1)[0]?.toLowerCase();
  if (!tld) return null;

  for (const [tlds, urls] of bootstrap.services) {
    if (tlds.includes(tld) && urls.length > 0) {
      return urls[0]; // Use first available service
    }
  }
  return null;
}

/**
 * Queries RDAP for domain registration information.
 * @param {string} domain
 * @returns {Promise<Object>}
 */
export async function queryDomain(domain) {
  try {
    const serviceUrl = await findRdapServiceUrl(domain);
    const rdapUrl = serviceUrl
      ? `${serviceUrl.replace(/\/$/, '')}/domain/${domain}`
      : `https://rdap.org/domain/${domain}`;

    const response = await axios.get(rdapUrl, {
      timeout: TIMEOUT_MS,
      headers: { Accept: 'application/rdap+json' },
    });

    return normalizeRdapResponse(response.data);
  } catch (error) {
    if (error.response?.status === 404) {
      return { status: 'NOT_FOUND', error: 'Domain not found in RDAP' };
    }
    logger.debug('RDAP query error', { domain, error: error.message });
    return { status: 'UNAVAILABLE', error: error.message };
  }
}

function normalizeRdapResponse(raw) {
  const events = raw?.events || [];

  const getEventDate = (type) => {
    const event = events.find((e) => e.eventAction === type);
    return event?.eventDate || null;
  };

  const registrationDate = getEventDate('registration');
  const expirationDate = getEventDate('expiration');
  const lastChangedDate = getEventDate('last changed');

  // Calculate domain age
  let domainAgeDays = null;
  if (registrationDate) {
    const regDate = new Date(registrationDate);
    domainAgeDays = Math.floor((Date.now() - regDate.getTime()) / (1000 * 60 * 60 * 24));
  }

  const nameservers = (raw?.nameservers || []).map((ns) => ns.ldhName || ns.unicodeName);

  return {
    status: 'AVAILABLE',
    domain: raw?.ldhName || raw?.unicodeName,
    registrationDate,
    expirationDate,
    lastChangedDate,
    domainAgeDays,
    nameservers,
    status: raw?.status || [],
    handle: raw?.handle || null,
    error: null,
  };
}
