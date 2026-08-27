/**
 * Privacy Policy Analyzer Service
 */

import { generatePrivacyPolicySummary } from '../providers/openRouterProvider.js';
import { calculateRiskAssessment } from '../risk/riskEngine.js';
import prisma from '../config/database.js';
import logger from '../utils/logger.js';

const DATA_COLLECTION_PATTERNS = {
  location: /location|gps|geolocation|whereabouts/i,
  contacts: /contact list|address book|contacts/i,
  camera: /camera|photos|images|pictures/i,
  microphone: /microphone|voice|audio|recordings/i,
  sms: /sms|text messages|messages/i,
  deviceId: /device id|imei|advertising id|idfa/i,
  biometrics: /biometric|fingerprint|face recognition|face id/i,
  financial: /financial|payment|credit card|bank/i,
  health: /health|medical|fitness|heartrate/i,
  browsing: /browsing history|search history|web activity/i,
};

const SHARING_PATTERNS = {
  thirdParty: /third.?party|partners|affiliates|vendors/i,
  advertising: /advertis|marketing partner|ad network/i,
  sold: /sell your data|sold to|data sale|purchase data/i,
  government: /law enforcement|government|legal request/i,
};

const RIGHTS_PATTERNS = {
  deletion: /delete your (data|account)|right to delete|right to erasure|gdpr/i,
  access: /access your data|data portability|download your/i,
  optOut: /opt.?out|unsubscribe|withdraw consent/i,
};

/**
 * Analyzes a privacy policy for risk indicators.
 */
export async function analyzePrivacyPolicy(content, userId) {
  const scan = await prisma.scan.create({
    data: { userId, scanType: 'PRIVACY_POLICY', status: 'PROCESSING' },
  });

  await prisma.scanInput.create({
    data: { scanId: scan.id, rawInput: content.substring(0, 50000) },
  });

  try {
    const dataCollection = analyzeDataCollection(content);
    const thirdPartySharing = analyzeThirdPartySharing(content);
    const userRights = analyzeUserRights(content);
    const retention = analyzeRetention(content);
    const dataSale = { mentioned: SHARING_PATTERNS.sold.test(content) };

    const evidence = {
      dataCollection,
      thirdPartySharing,
      userRights,
      retention,
      dataSale,
      wordCount: content.split(/\s+/).length,
    };

    const riskAssessment = calculateRiskAssessment(evidence, 'PRIVACY_POLICY');
    const aiExplanation = await generatePrivacyPolicySummary(content, riskAssessment);

    const recommendations = [];
    if (dataSale.mentioned) recommendations.push({ priority: 'HIGH', category: 'PRIVACY', title: 'Data May Be Sold', detail: 'This privacy policy mentions selling user data to third parties.', action: 'Consider whether you are comfortable with your data being sold. Look for opt-out options.', evidenceBasis: 'Data sale language detected in policy' });
    if (!userRights.deletion) recommendations.push({ priority: 'MEDIUM', category: 'RIGHTS', title: 'No Clear Data Deletion Rights', detail: 'The policy does not clearly state your right to delete your data.', action: 'Contact the service to ask about data deletion options.', evidenceBasis: 'Deletion rights not found in policy' });

    await prisma.scanResult.create({
      data: { scanId: scan.id, trustScore: riskAssessment.trustScore, riskLevel: riskAssessment.riskLevel, confidence: riskAssessment.confidence, evidenceCoverage: riskAssessment.evidenceCoverage, aiSummary: aiExplanation.summary, aiExplanation, keyIndicators: riskAssessment.indicators, rawApiResponses: evidence },
    });

    await prisma.scan.update({ where: { id: scan.id }, data: { status: 'COMPLETED', completedAt: new Date() } });

    return { scanId: scan.id, trustScore: riskAssessment.trustScore, riskLevel: riskAssessment.riskLevel, confidence: riskAssessment.confidence, evidenceCoverage: riskAssessment.evidenceCoverage, evidence, aiExplanation, recommendations, completedAt: new Date().toISOString() };
  } catch (error) {
    logger.error('Privacy policy analysis failed', { scanId: scan.id, error: error.message });
    await prisma.scan.update({ where: { id: scan.id }, data: { status: 'FAILED' } });
    throw error;
  }
}

function analyzeDataCollection(content) {
  const sensitiveTypes = [];
  for (const [type, pattern] of Object.entries(DATA_COLLECTION_PATTERNS)) {
    if (pattern.test(content)) sensitiveTypes.push(type);
  }
  return { sensitiveTypes };
}

function analyzeThirdPartySharing(content) {
  const extensive = SHARING_PATTERNS.thirdParty.test(content) && SHARING_PATTERNS.advertising.test(content);
  const limited = SHARING_PATTERNS.thirdParty.test(content) && !extensive;
  return { extensive, limited };
}

function analyzeUserRights(content) {
  return {
    deletion: RIGHTS_PATTERNS.deletion.test(content),
    access: RIGHTS_PATTERNS.access.test(content),
    optOut: RIGHTS_PATTERNS.optOut.test(content),
    noDeletion: !RIGHTS_PATTERNS.deletion.test(content),
  };
}

function analyzeRetention(content) {
  const indefinite = /indefinitely|as long as|no fixed period|until you delete/i.test(content);
  const specific = /\d+ (days|months|years)/i.test(content);
  return { indefinite, specific };
}
