/**
 * Digital Identity Evidence Collector
 * Gathers DNS, MX, SPF, DMARC, Disposable Domain, and Identity Exposure indicators.
 * Every evidence item is strictly marked: VERIFIED, UNAVAILABLE (with reason), or USER_PROVIDED.
 */

import dns from 'dns/promises';
import logger from '../utils/logger.js';

// Common disposable/temporary email domains
const DISPOSABLE_DOMAINS = new Set([
  'mailinator.com',
  '10minutemail.com',
  'tempmail.com',
  'guerrillamail.com',
  'sharklasers.com',
  'yopmail.com',
  'trashmail.com',
  'throwawaymail.com',
  'getairmail.com',
  'dispostable.com',
  'temp-mail.org',
  'fakeinbox.com',
  'maildrop.cc',
  'inboxkitten.com',
]);

// Common public/free webmail providers
const FREE_EMAIL_PROVIDERS = new Set([
  'gmail.com',
  'googlemail.com',
  'yahoo.com',
  'ymail.com',
  'outlook.com',
  'hotmail.com',
  'live.com',
  'msn.com',
  'icloud.com',
  'me.com',
  'mac.com',
  'aol.com',
  'proton.me',
  'protonmail.com',
  'zoho.com',
  'gmx.com',
  'mail.com',
]);

/**
 * Collects identity intelligence evidence for an email address.
 * @param {string} email
 * @returns {Promise<Object>} Evidence collection with strict statuses
 */
export async function collectIdentityEvidence(email) {
  const parts = email.split('@');
  const localPart = parts[0] || '';
  const domain = (parts[1] || '').toLowerCase().trim();

  logger.info('Starting identity evidence collection', { email, domain });

  const isDisposable = DISPOSABLE_DOMAINS.has(domain);
  const isFreeProvider = FREE_EMAIL_PROVIDERS.has(domain);

  // 1. Email format evidence
  const emailFormatEvidence = {
    indicator: 'EMAIL_FORMAT_VALIDITY',
    source: 'SYNTAX_PARSER',
    status: 'VERIFIED',
    value: {
      validFormat: /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email),
      localPartLength: localPart.length,
      domain,
    },
  };

  // 2. Domain classification evidence
  const domainTypeEvidence = {
    indicator: 'DOMAIN_CLASSIFICATION',
    source: 'DOMAIN_REPUTATION',
    status: 'VERIFIED',
    value: {
      domain,
      isDisposable,
      isFreeProvider,
      isCustomDomain: !isFreeProvider && !isDisposable,
    },
  };

  // 3. Concurrently query DNS: MX, SPF, DMARC
  const [mxResult, spfResult, dmarcResult] = await Promise.allSettled([
    resolveMxRecords(domain),
    resolveSpfRecord(domain),
    resolveDmarcRecord(domain),
  ]);

  const mxEvidence = mxResult.status === 'fulfilled'
    ? mxResult.value
    : { indicator: 'DNS_MX_RECORDS', source: 'DNS_RESOLVER', status: 'UNAVAILABLE', reason: mxResult.reason?.message || 'DNS resolution failed', value: null };

  const spfEvidence = spfResult.status === 'fulfilled'
    ? spfResult.value
    : { indicator: 'DNS_SPF_RECORD', source: 'DNS_RESOLVER', status: 'UNAVAILABLE', reason: spfResult.reason?.message || 'DNS resolution failed', value: null };

  const dmarcEvidence = dmarcResult.status === 'fulfilled'
    ? dmarcResult.value
    : { indicator: 'DNS_DMARC_RECORD', source: 'DNS_RESOLVER', status: 'UNAVAILABLE', reason: dmarcResult.reason?.message || 'DNS resolution failed', value: null };

  // 4. Breach monitoring provider status
  const breachEvidence = {
    indicator: 'IDENTITY_BREACH_STATUS',
    source: 'HIBP_PWNED_API',
    status: 'UNAVAILABLE',
    reason: 'Public dark-web breach lookup for custom domains requires specialized corporate API credentials. Free k-anonymity check is available for passwords.',
    value: {
      kAnonymitySupported: true,
      domainMonitoring: 'REQUIRES_SUBSCRIPTION',
    },
  };

  const items = [
    emailFormatEvidence,
    domainTypeEvidence,
    mxEvidence,
    spfEvidence,
    dmarcEvidence,
    breachEvidence,
  ];

  // Calculate evidence coverage based on available verified items
  const availableItems = items.filter((i) => i.status === 'VERIFIED' || i.status === 'USER_PROVIDED');
  const evidenceCoverage = Math.round((availableItems.length / items.length) * 100);

  return {
    email,
    domain,
    evidenceCoverage,
    availableCount: availableItems.length,
    totalCount: items.length,
    items,
    metadata: {
      email,
      domain,
      isDisposable,
      isFreeProvider,
    },
  };
}

async function resolveMxRecords(domain) {
  try {
    const records = await dns.resolveMx(domain);
    if (!records || records.length === 0) {
      return {
        indicator: 'DNS_MX_RECORDS',
        source: 'DNS_RESOLVER',
        status: 'VERIFIED',
        value: { hasMx: false, recordCount: 0, exchanges: [] },
      };
    }
    const exchanges = records.sort((a, b) => a.priority - b.priority).map((r) => r.exchange);
    return {
      indicator: 'DNS_MX_RECORDS',
      source: 'DNS_RESOLVER',
      status: 'VERIFIED',
      value: { hasMx: true, recordCount: records.length, exchanges },
    };
  } catch (error) {
    if (error.code === 'ENOTFOUND' || error.code === 'ENODATA' || error.code === 'ESERVFAIL') {
      return {
        indicator: 'DNS_MX_RECORDS',
        source: 'DNS_RESOLVER',
        status: 'VERIFIED',
        value: { hasMx: false, recordCount: 0, exchanges: [], error: error.code },
      };
    }
    return {
      indicator: 'DNS_MX_RECORDS',
      source: 'DNS_RESOLVER',
      status: 'UNAVAILABLE',
      reason: `DNS MX lookup failed: ${error.message}`,
      value: null,
    };
  }
}

async function resolveSpfRecord(domain) {
  try {
    const records = await dns.resolveTxt(domain);
    const flatRecords = records.map((r) => (Array.isArray(r) ? r.join('') : r));
    const spfRecord = flatRecords.find((r) => r.toLowerCase().startsWith('v=spf1'));

    if (spfRecord) {
      const isStrict = spfRecord.includes('-all');
      const isSoftFail = spfRecord.includes('~all');
      return {
        indicator: 'DNS_SPF_RECORD',
        source: 'DNS_RESOLVER',
        status: 'VERIFIED',
        value: { hasSpf: true, record: spfRecord, isStrict, isSoftFail },
      };
    }

    return {
      indicator: 'DNS_SPF_RECORD',
      source: 'DNS_RESOLVER',
      status: 'VERIFIED',
      value: { hasSpf: false, record: null },
    };
  } catch (error) {
    if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
      return {
        indicator: 'DNS_SPF_RECORD',
        source: 'DNS_RESOLVER',
        status: 'VERIFIED',
        value: { hasSpf: false, record: null },
      };
    }
    return {
      indicator: 'DNS_SPF_RECORD',
      source: 'DNS_RESOLVER',
      status: 'UNAVAILABLE',
      reason: `DNS SPF lookup failed: ${error.message}`,
      value: null,
    };
  }
}

async function resolveDmarcRecord(domain) {
  try {
    const dmarcHost = `_dmarc.${domain}`;
    const records = await dns.resolveTxt(dmarcHost);
    const flatRecords = records.map((r) => (Array.isArray(r) ? r.join('') : r));
    const dmarcRecord = flatRecords.find((r) => r.toLowerCase().startsWith('v=dmarc1'));

    if (dmarcRecord) {
      let policy = 'none';
      if (/p=reject/i.test(dmarcRecord)) policy = 'reject';
      else if (/p=quarantine/i.test(dmarcRecord)) policy = 'quarantine';

      return {
        indicator: 'DNS_DMARC_RECORD',
        source: 'DNS_RESOLVER',
        status: 'VERIFIED',
        value: { hasDmarc: true, record: dmarcRecord, policy },
      };
    }

    return {
      indicator: 'DNS_DMARC_RECORD',
      source: 'DNS_RESOLVER',
      status: 'VERIFIED',
      value: { hasDmarc: false, record: null, policy: null },
    };
  } catch (error) {
    if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
      return {
        indicator: 'DNS_DMARC_RECORD',
        source: 'DNS_RESOLVER',
        status: 'VERIFIED',
        value: { hasDmarc: false, record: null, policy: null },
      };
    }
    return {
      indicator: 'DNS_DMARC_RECORD',
      source: 'DNS_RESOLVER',
      status: 'UNAVAILABLE',
      reason: `DNS DMARC lookup failed: ${error.message}`,
      value: null,
    };
  }
}
