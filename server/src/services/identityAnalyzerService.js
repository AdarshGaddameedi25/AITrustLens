/**
 * Digital Identity Analyzer Service
 * Provides comprehensive identity and email domain risk analysis.
 * Deterministic scoring via riskEngine + evidence collection + AI explanation.
 */

import { collectIdentityEvidence } from '../risk/identityEvidenceCollector.js';
import { calculateRiskAssessment } from '../risk/riskEngine.js';
import { generateIdentityAnalysisExplanation, AI_PROMPT_VERSION } from '../providers/openRouterProvider.js';
import { generateIdentityRecommendations } from './recommendationService.js';
import prisma from '../config/database.js';
import logger from '../utils/logger.js';

/**
 * Analyzes an email address for identity exposure and domain security posture.
 * @param {string} email
 * @param {string} userId
 * @returns {Promise<Object>}
 */
export async function analyzeIdentity(email, userId) {
  const normalizedEmail = email.trim().toLowerCase();

  const scan = await prisma.scan.create({
    data: { userId, scanType: 'DIGITAL_IDENTITY', status: 'PROCESSING' },
  });

  await prisma.scanInput.create({
    data: {
      scanId: scan.id,
      rawInput: normalizedEmail,
      normalizedInput: normalizedEmail,
    },
  });

  try {
    // 1. Collect identity & domain evidence
    const evidenceCollection = await collectIdentityEvidence(normalizedEmail);

    // 2. Deterministic mathematical risk assessment
    const riskAssessment = calculateRiskAssessment(evidenceCollection, 'DIGITAL_IDENTITY');

    // 3. AI-generated plain language summary and explanation
    let aiExplanation = {
      summary: `Email identity analysis for ${normalizedEmail} completed with Trust Score ${riskAssessment.trustScore}/100.`,
      riskExplanation: `Domain ${evidenceCollection.domain} evaluated across MX routing, SPF authentication, DMARC policies, and disposable domain databases.`,
      keyIndicators: riskAssessment.indicators.filter((i) => i.isAvailable).map((i) => `${i.name}: ${i.riskValue === 0 ? 'Passed' : 'Flagged'}`),
      recommendations: ['Enforce multi-factor authentication on all sensitive services.'],
      limitations: ['Dark-web breach monitoring for custom domains requires specialized corporate subscriptions.'],
      confidence: riskAssessment.confidence,
    };

    try {
      const generatedAi = await generateIdentityAnalysisExplanation(evidenceCollection, riskAssessment);
      if (generatedAi) {
        aiExplanation = generatedAi;
      }
    } catch (aiErr) {
      logger.warn('AI explanation generation failed for identity, using deterministic summary', { error: aiErr.message });
    }

    // 4. Actionable recommendations
    const recommendations = generateIdentityRecommendations(evidenceCollection, riskAssessment);

    // 5. Persist ScanResult
    await prisma.scanResult.create({
      data: {
        scanId: scan.id,
        trustScore: riskAssessment.trustScore,
        riskLevel: riskAssessment.riskLevel,
        confidence: riskAssessment.confidence,
        evidenceCoverage: riskAssessment.evidenceCoverage,
        ruleSetVersion: riskAssessment.ruleSetVersion,
        aiModel: 'openrouter/claude',
        aiPromptVersion: AI_PROMPT_VERSION,
        aiSummary: aiExplanation.summary,
        aiExplanation,
        keyIndicators: riskAssessment.indicators,
        limitations: aiExplanation.limitations || [],
        rawApiResponses: evidenceCollection,
      },
    });

    // 6. Persist individual Evidence items
    if (evidenceCollection.items && evidenceCollection.items.length > 0) {
      const evidenceData = evidenceCollection.items.map((item) => {
        let sourceEnum = 'LOCAL_ANALYSIS';
        if (item.source === 'DNS_RESOLVER' || item.source === 'SYNTAX_PARSER') sourceEnum = 'LOCAL_ANALYSIS';
        else if (item.source === 'HIBP_PWNED_API') sourceEnum = 'HIBP_PWNED_PASSWORDS';

        let statusEnum = 'AVAILABLE';
        if (item.status === 'UNAVAILABLE') statusEnum = 'UNAVAILABLE';
        else if (item.status === 'VERIFIED') statusEnum = 'AVAILABLE';

        return {
          scanId: scan.id,
          source: sourceEnum,
          type: item.indicator || 'IDENTITY_INDICATOR',
          indicator: item.indicator || 'GENERIC',
          value: item.value || {},
          status: statusEnum,
          severity: 'INFO',
          confidence: riskAssessment.confidence === 'HIGH' ? 'HIGH' : riskAssessment.confidence === 'MEDIUM' ? 'MEDIUM' : 'LOW',
          interpretation: item.reason || (item.status === 'VERIFIED' ? 'Verified via DNS/local checks' : 'Unavailable'),
        };
      });

      await prisma.evidence.createMany({ data: evidenceData }).catch((err) => {
        logger.warn('Failed to bulk insert evidence items for identity scan', { error: err.message });
      });
    }

    // 7. Persist Recommendations
    if (recommendations.length > 0) {
      const recsData = recommendations.map((rec) => ({
        scanId: scan.id,
        priority: rec.priority || 'MEDIUM',
        category: rec.category || 'IDENTITY',
        title: rec.title,
        detail: rec.detail,
        action: rec.action || null,
        evidenceBasis: rec.evidenceBasis || null,
      }));

      await prisma.recommendation.createMany({ data: recsData }).catch((err) => {
        logger.warn('Failed to bulk insert recommendations for identity scan', { error: err.message });
      });
    }

    // 8. Mark scan COMPLETED
    await prisma.scan.update({
      where: { id: scan.id },
      data: { status: 'COMPLETED', completedAt: new Date() },
    });

    logger.info('Digital identity analysis completed', {
      scanId: scan.id,
      email: normalizedEmail,
      trustScore: riskAssessment.trustScore,
      confidence: riskAssessment.confidence,
    });

    return {
      scanId: scan.id,
      email: normalizedEmail,
      domain: evidenceCollection.domain,
      trustScore: riskAssessment.trustScore,
      riskLevel: riskAssessment.riskLevel,
      confidence: riskAssessment.confidence,
      evidenceCoverage: riskAssessment.evidenceCoverage,
      evidence: evidenceCollection,
      aiExplanation,
      recommendations,
      completedAt: new Date().toISOString(),
    };
  } catch (error) {
    logger.error('Digital identity analysis failed', { scanId: scan.id, error: error.message });
    await prisma.scan.update({ where: { id: scan.id }, data: { status: 'FAILED' } }).catch(() => {});
    throw error;
  }
}
