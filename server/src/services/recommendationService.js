/**
 * Recommendation Service
 * Generates evidence-based recommendations from analysis results.
 * All recommendations must be tied to actual findings — no generic filler.
 */

/**
 * @typedef {Object} Recommendation
 * @property {'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'|'INFO'} priority
 * @property {string} category
 * @property {string} title
 * @property {string} detail
 * @property {string} action
 * @property {string} evidenceBasis
 */

/**
 * Generates recommendations for URL analysis results.
 * @param {Object} evidence
 * @param {Object} riskAssessment
 * @returns {Recommendation[]}
 */
export function generateUrlRecommendations(evidence, riskAssessment) {
  const recommendations = [];

  // Malicious detections
  const vtMalicious = evidence?.virustotal?.maliciousCount ?? 0;
  if (vtMalicious > 0) {
    recommendations.push({
      priority: 'CRITICAL',
      category: 'THREAT',
      title: 'Malicious URL Detected',
      detail: `${vtMalicious} security engine(s) flagged this URL as malicious. Do not proceed.`,
      action: 'Close the page immediately. Do not enter any credentials, payment details, or personal information.',
      evidenceBasis: `VirusTotal: ${vtMalicious} malicious detections out of ${evidence.virustotal.totalEngines} engines`,
    });
  }

  // Safe Browsing threat
  if (evidence?.safeBrowsing?.threatFound) {
    const threats = evidence.safeBrowsing.threats.map((t) => t.threatType).join(', ');
    recommendations.push({
      priority: 'CRITICAL',
      category: 'PHISHING',
      title: 'Google Safe Browsing Threat Detected',
      detail: `Google Safe Browsing has flagged this URL as: ${threats}`,
      action: 'Do not visit this website. Report it to your organization\'s security team.',
      evidenceBasis: `Google Safe Browsing: ${threats}`,
    });
  }

  // No HTTPS
  if (!evidence?.urlInfo?.isHttps) {
    recommendations.push({
      priority: 'HIGH',
      category: 'SECURITY',
      title: 'Insecure Connection (No HTTPS)',
      detail: 'This website does not use HTTPS encryption. Your data may be transmitted in plaintext.',
      action: 'Avoid entering any sensitive information on this website. Look for the HTTPS padlock in your browser.',
      evidenceBasis: 'URL uses HTTP protocol without SSL/TLS encryption',
    });
  }

  // TLS expired
  if (evidence?.tls?.status === 'AVAILABLE' && evidence.tls.expired) {
    recommendations.push({
      priority: 'HIGH',
      category: 'SECURITY',
      title: 'Expired TLS Certificate',
      detail: 'The website\'s SSL/TLS certificate has expired. This could indicate abandonment or compromise.',
      action: 'Do not enter sensitive information. The certificate has expired.',
      evidenceBasis: `TLS certificate expired: valid until ${evidence.tls.validTo}`,
    });
  }

  // Very new domain
  const domainAgeDays = evidence?.rdap?.domainAgeDays;
  if (domainAgeDays !== null && domainAgeDays !== undefined && domainAgeDays < 30) {
    recommendations.push({
      priority: 'HIGH',
      category: 'DOMAIN',
      title: 'Recently Registered Domain',
      detail: `This domain was registered only ${domainAgeDays} day(s) ago. Phishing sites are often registered recently.`,
      action: 'Be extremely cautious. Verify the website through official channels before proceeding.',
      evidenceBasis: `RDAP: Domain age ${domainAgeDays} days`,
    });
  }

  // Suspicious URL patterns
  const flags = evidence?.urlPatterns?.flags ?? [];
  if (flags.includes('CREDENTIAL_EMBEDDING')) {
    recommendations.push({
      priority: 'CRITICAL',
      category: 'URL_PATTERN',
      title: 'Suspicious URL Contains Credentials',
      detail: 'The URL contains an @ symbol which can be used to hide the real destination.',
      action: 'Do not follow this link. This is a common phishing technique.',
      evidenceBasis: 'URL pattern: credential embedding (@) detected',
    });
  }

  if (flags.some((f) => f.startsWith('LOOKALIKE_BRAND'))) {
    const brand = flags.find((f) => f.startsWith('LOOKALIKE_BRAND'))?.split(':')?.[1];
    recommendations.push({
      priority: 'HIGH',
      category: 'URL_PATTERN',
      title: `Potential Brand Impersonation (${brand})`,
      detail: `The URL appears to impersonate a well-known brand (${brand}) in its subdomain structure.`,
      action: `Visit ${brand}'s official website directly by typing it in your browser. Do not use this link.`,
      evidenceBasis: `URL pattern: ${brand} brand name found in subdomain`,
    });
  }

  if (flags.includes('IP_ADDRESS_HOSTNAME')) {
    recommendations.push({
      priority: 'MEDIUM',
      category: 'URL_PATTERN',
      title: 'Website Uses IP Address Instead of Domain',
      detail: 'Legitimate websites rarely use raw IP addresses. This may indicate a malicious or temporary site.',
      action: 'Be cautious. Verify the site\'s legitimacy through another method.',
      evidenceBasis: 'URL pattern: IP address used as hostname',
    });
  }

  // URLScan malicious
  if (evidence?.urlscan?.malicious === true) {
    recommendations.push({
      priority: 'HIGH',
      category: 'THREAT',
      title: 'URLScan Flagged as Malicious',
      detail: 'URLScan.io analysis determined this URL may be malicious.',
      action: 'Exercise extreme caution. Do not proceed unless you are certain of the URL\'s legitimacy.',
      evidenceBasis: `URLScan.io malicious verdict (score: ${evidence.urlscan.score})`,
    });
  }

  // General trust recommendations
  if (riskAssessment.trustScore >= 85) {
    recommendations.push({
      priority: 'INFO',
      category: 'GENERAL',
      title: 'Standard Security Precautions',
      detail: 'While this URL appears legitimate based on available evidence, always exercise basic security hygiene.',
      action: 'Keep your browser updated, use strong unique passwords, and enable MFA where possible.',
      evidenceBasis: `Trust Score: ${riskAssessment.trustScore}/100 with ${riskAssessment.evidenceCoverage}% evidence coverage`,
    });
  }

  return recommendations;
}

/**
 * Generates recommendations for email phishing analysis.
 */
export function generateEmailRecommendations(evidence, riskAssessment) {
  const recommendations = [];

  if (riskAssessment.trustScore < 50) {
    recommendations.push({
      priority: 'CRITICAL',
      category: 'PHISHING',
      title: 'High-Risk Email Detected',
      detail: 'This email shows multiple indicators of a phishing attempt.',
      action: 'Do not click any links, open attachments, or provide any information. Report to your IT security team.',
      evidenceBasis: `Trust Score: ${riskAssessment.trustScore}/100`,
    });
  }

  if (evidence?.credentialRequest?.detected) {
    recommendations.push({
      priority: 'CRITICAL',
      category: 'CREDENTIALS',
      title: 'Email Requests Credentials',
      detail: 'This email is requesting your password, OTP, or account credentials.',
      action: 'Legitimate organizations never ask for credentials via email. Do not respond.',
      evidenceBasis: 'Credential/OTP request detected in email content',
    });
  }

  return recommendations;
}

/**
 * Generates password security recommendations.
 */
export function generatePasswordRecommendations(breachResult) {
  const recommendations = [];

  if (breachResult.status === 'EXPOSED') {
    recommendations.push({
      priority: 'CRITICAL',
      category: 'PASSWORD',
      title: 'Password Found in Data Breach',
      detail: `This password has been exposed in ${breachResult.breachCount.toLocaleString()} known data breaches.`,
      action: 'Change this password immediately on all services where you use it.',
      evidenceBasis: `HIBP Pwned Passwords: ${breachResult.breachCount} breach occurrences`,
    });
    recommendations.push({
      priority: 'HIGH',
      category: 'MFA',
      title: 'Enable Multi-Factor Authentication',
      detail: 'Even with a new password, enable MFA on all important accounts for additional protection.',
      action: 'Enable authenticator app-based MFA (not SMS) on all critical accounts.',
      evidenceBasis: 'Password was exposed — additional authentication layer is critical',
    });
  }

  recommendations.push({
    priority: 'MEDIUM',
    category: 'PASSWORD',
    title: 'Use a Unique Password for Each Service',
    detail: 'Reusing passwords across services means one breach can compromise all your accounts.',
    action: 'Use a password manager to generate and store unique passwords for every service.',
    evidenceBasis: 'General password security best practice',
  });

  return recommendations;
}

/**
 * Generates recommendations for APK permission analysis.
 */
export function generateApkRecommendations(permissions, _riskAssessment) {
  const recommendations = [];
  const criticalPermissions = permissions.filter((p) => p.riskLevel === 'CRITICAL');
  const highPermissions = permissions.filter((p) => p.riskLevel === 'HIGH');

  if (criticalPermissions.length > 0) {
    recommendations.push({
      priority: 'CRITICAL',
      category: 'PERMISSIONS',
      title: 'Dangerous Permission Combination Detected',
      detail: `App requests ${criticalPermissions.length} critical permission(s): ${criticalPermissions.map((p) => p.name).join(', ')}`,
      action: 'Only install from trusted sources. Review whether these permissions are justified by the app\'s purpose.',
      evidenceBasis: `Critical permissions: ${criticalPermissions.map((p) => p.name).join(', ')}`,
    });
  }

  if (highPermissions.length > 3) {
    recommendations.push({
      priority: 'HIGH',
      category: 'PERMISSIONS',
      title: 'Excessive Permission Requests',
      detail: `App requests ${highPermissions.length} high-risk permissions which may exceed what is necessary.`,
      action: 'Question whether the app\'s stated purpose requires all these permissions.',
      evidenceBasis: `High-risk permissions: ${highPermissions.length} found`,
    });
  }

  return recommendations;
}

/**
 * Generates actionable recommendations for Digital Identity analysis.
 * @param {Object} evidenceCollection
 * @param {Object} riskAssessment
 * @returns {Recommendation[]}
 */
export function generateIdentityRecommendations(evidenceCollection, riskAssessment) {
  const recommendations = [];
  const items = evidenceCollection?.items || [];

  const disposable = items.find((i) => i.indicator === 'DOMAIN_CLASSIFICATION')?.value?.isDisposable;
  const mx = items.find((i) => i.indicator === 'DNS_MX_RECORDS')?.value;
  const spf = items.find((i) => i.indicator === 'DNS_SPF_RECORD')?.value;
  const dmarc = items.find((i) => i.indicator === 'DNS_DMARC_RECORD')?.value;
  const isFree = items.find((i) => i.indicator === 'DOMAIN_CLASSIFICATION')?.value?.isFreeProvider;

  if (disposable) {
    recommendations.push({
      priority: 'CRITICAL',
      category: 'IDENTITY',
      title: 'Disposable Email Service Detected',
      detail: 'This address belongs to a temporary or throwaway email service. Accounts registered with disposable addresses have zero long-term recovery security.',
      action: 'Do not use disposable email addresses for banking, identity verification, or critical accounts.',
      evidenceBasis: 'Domain matches known temporary email provider list',
    });
  }

  if (mx && mx.hasMx === false) {
    recommendations.push({
      priority: 'HIGH',
      category: 'DNS',
      title: 'No Valid Mail Exchanger (MX) Records',
      detail: 'The email domain has no active MX records configured and cannot receive incoming mail or security password reset tokens.',
      action: 'Verify domain registration and MX DNS configuration with your email administrator.',
      evidenceBasis: 'DNS MX query returned 0 valid mail exchangers',
    });
  }

  if (!isFree && spf && spf.hasSpf === false) {
    recommendations.push({
      priority: 'HIGH',
      category: 'AUTHENTICATION',
      title: 'Missing SPF (Sender Policy Framework)',
      detail: 'The domain lacks an SPF DNS record, making it vulnerable to sender spoofing and business email compromise (BEC).',
      action: 'Publish a strict v=spf1 TXT record in domain DNS specifying authorized outbound mail servers.',
      evidenceBasis: 'DNS TXT lookup found no v=spf1 record',
    });
  }

  if (!isFree && dmarc && dmarc.hasDmarc === false) {
    recommendations.push({
      priority: 'MEDIUM',
      category: 'AUTHENTICATION',
      title: 'Missing DMARC Policy',
      detail: 'The domain does not have a DMARC policy (_dmarc TXT record), allowing unauthorized senders to forge emails without rejection.',
      action: 'Deploy a DMARC policy with at least p=quarantine or p=reject to protect domain brand identity.',
      evidenceBasis: 'DNS TXT lookup on _dmarc host returned no DMARC record',
    });
  }

  // Universal Best Practices
  recommendations.push({
    priority: riskAssessment?.trustScore < 50 ? 'HIGH' : 'MEDIUM',
    category: 'IDENTITY_HYGIENE',
    title: 'Enforce Multi-Factor Authentication (MFA)',
    detail: 'Protect accounts associated with this email address with hardware security keys (FIDO2) or authenticator apps (TOTP).',
    action: 'Enable app-based 2FA on primary email and connected sensitive online portals.',
    evidenceBasis: 'Standard digital identity protection protocol',
  });

  recommendations.push({
    priority: 'INFO',
    category: 'MONITORING',
    title: 'Monitor for Credential Breaches',
    detail: 'Periodically check if your password or credentials appear in public leak databases.',
    action: 'Use the AITrustLens Password Check tool and subscribe to breach alerts.',
    evidenceBasis: 'Continuous identity exposure risk reduction',
  });

  return recommendations;
}

