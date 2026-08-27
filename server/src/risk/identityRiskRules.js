/**
 * Digital Identity Risk Rules Configuration
 * Defines mathematical rules for scoring email identity and domain trust.
 */

export const IDENTITY_RISK_RULES = {
  DISPOSABLE_EMAIL_DOMAIN: {
    id: 'DISPOSABLE_EMAIL_DOMAIN',
    name: 'Disposable Email Service',
    source: 'DOMAIN_REPUTATION',
    weight: 0.40,
    calculate: (evidenceCollection) => {
      const item = findEvidenceItem(evidenceCollection, 'DOMAIN_CLASSIFICATION');
      if (!item || item.status === 'UNAVAILABLE') return null;
      return item.value?.isDisposable ? 100 : 0;
    },
  },

  NO_MX_RECORDS: {
    id: 'NO_MX_RECORDS',
    name: 'Missing Mail Exchanger (MX) Records',
    source: 'DNS_RESOLVER',
    weight: 0.30,
    calculate: (evidenceCollection) => {
      const item = findEvidenceItem(evidenceCollection, 'DNS_MX_RECORDS');
      if (!item || item.status === 'UNAVAILABLE') return null;
      return item.value?.hasMx === false ? 100 : 0;
    },
  },

  MISSING_SPF_RECORD: {
    id: 'MISSING_SPF_RECORD',
    name: 'Sender Policy Framework (SPF) Exposure',
    source: 'DNS_RESOLVER',
    weight: 0.15,
    calculate: (evidenceCollection) => {
      const domainInfo = findEvidenceItem(evidenceCollection, 'DOMAIN_CLASSIFICATION');
      if (domainInfo?.value?.isFreeProvider) return 0; // Free webmail manages SPF upstream

      const item = findEvidenceItem(evidenceCollection, 'DNS_SPF_RECORD');
      if (!item || item.status === 'UNAVAILABLE') return null;
      if (item.value?.hasSpf === false) return 70;
      if (item.value?.isSoftFail) return 25;
      return 0;
    },
  },

  MISSING_DMARC_RECORD: {
    id: 'MISSING_DMARC_RECORD',
    name: 'DMARC Domain Authentication Exposure',
    source: 'DNS_RESOLVER',
    weight: 0.15,
    calculate: (evidenceCollection) => {
      const domainInfo = findEvidenceItem(evidenceCollection, 'DOMAIN_CLASSIFICATION');
      if (domainInfo?.value?.isFreeProvider) return 0; // Free webmail manages DMARC upstream

      const item = findEvidenceItem(evidenceCollection, 'DNS_DMARC_RECORD');
      if (!item || item.status === 'UNAVAILABLE') return null;
      if (item.value?.hasDmarc === false) return 70;
      if (item.value?.policy === 'none') return 30;
      return 0;
    },
  },
};

function findEvidenceItem(evidenceCollection, indicator) {
  if (!evidenceCollection) return null;
  if (Array.isArray(evidenceCollection.items)) {
    return evidenceCollection.items.find((i) => i.indicator === indicator);
  }
  if (Array.isArray(evidenceCollection)) {
    return evidenceCollection.find((i) => i.indicator === indicator);
  }
  return null;
}
