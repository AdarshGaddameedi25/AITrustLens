/**
 * Claim Verification Service
 */

import { searchFactChecks } from '../providers/factCheckProvider.js';
import { generateClaimVerificationExplanation } from '../providers/openRouterProvider.js';
import prisma from '../config/database.js';
import logger from '../utils/logger.js';

const VERDICT_SCORES = {
  'True': 90,
  'Mostly True': 80,
  'Half True': 60,
  'Mostly False': 30,
  'False': 10,
  'Pants on Fire': 5,
  'Misleading': 35,
  'Correct': 90,
  'Incorrect': 10,
};

function normalizeVerdict(textualRating) {
  if (!textualRating) return 'UNVERIFIED';
  const rating = textualRating.toLowerCase();
  if (rating.includes('true') || rating.includes('correct') || rating.includes('accurate')) return 'VERIFIED';
  if (rating.includes('false') || rating.includes('incorrect') || rating.includes('wrong')) return 'FALSE';
  if (rating.includes('mislead') || rating.includes('distort')) return 'MISLEADING';
  if (rating.includes('mix') || rating.includes('half') || rating.includes('partial')) return 'MIXED';
  return 'UNVERIFIED';
}

/**
 * Verifies a claim using Google Fact Check API.
 */
export async function verifyClaim(claim, languageCode, userId) {
  const scan = await prisma.scan.create({
    data: { userId, scanType: 'CLAIM_VERIFICATION', status: 'PROCESSING' },
  });

  await prisma.scanInput.create({
    data: { scanId: scan.id, rawInput: claim },
  });

  try {
    const factCheckResult = await searchFactChecks(claim, languageCode);
    const hasResults = factCheckResult.status === 'AVAILABLE' && factCheckResult.claims?.length > 0;

    let verdict = 'UNVERIFIED';
    let trustScore = 50;
    let confidence = 'LOW';

    if (hasResults) {
      const allReviews = factCheckResult.claims.flatMap((c) => c.reviews || []);
      const ratings = allReviews.map((r) => r.textualRating).filter(Boolean);
      const verdicts = ratings.map(normalizeVerdict);

      // Majority vote
      const verdictCounts = {};
      for (const v of verdicts) verdictCounts[v] = (verdictCounts[v] || 0) + 1;
      const topVerdict = Object.entries(verdictCounts).sort((a, b) => b[1] - a[1])[0];
      verdict = topVerdict?.[0] || 'UNVERIFIED';

      // Score based on ratings
      const numericRatings = ratings.map((r) => {
        for (const [key, val] of Object.entries(VERDICT_SCORES)) {
          if (r.toLowerCase().includes(key.toLowerCase())) return val;
        }
        return 50;
      });

      if (numericRatings.length > 0) {
        trustScore = Math.round(numericRatings.reduce((a, b) => a + b, 0) / numericRatings.length);
      }

      confidence = allReviews.length >= 3 ? 'HIGH' : allReviews.length >= 1 ? 'MEDIUM' : 'LOW';
    }

    const riskLevel = trustScore < 30 ? 'CRITICAL' : trustScore < 50 ? 'HIGH' : trustScore < 70 ? 'MODERATE' : 'LOW';

    const evidence = { factCheckResult, verdict, claim, hasResults };
    const aiExplanation = await generateClaimVerificationExplanation(evidence, { verdict, trustScore });

    await prisma.scanResult.create({
      data: { scanId: scan.id, trustScore, riskLevel, confidence, evidenceCoverage: hasResults ? 70 : 20, aiSummary: aiExplanation.summary, aiExplanation, rawApiResponses: evidence },
    });

    await prisma.scan.update({ where: { id: scan.id }, data: { status: 'COMPLETED', completedAt: new Date() } });

    return { scanId: scan.id, claim, verdict, trustScore, riskLevel, confidence, evidenceCoverage: hasResults ? 70 : 20, factCheckResult, aiExplanation, note: !hasResults ? 'No existing fact checks found. This does not mean the claim is true or false.' : null, completedAt: new Date().toISOString() };
  } catch (error) {
    logger.error('Claim verification failed', { scanId: scan.id, error: error.message });
    await prisma.scan.update({ where: { id: scan.id }, data: { status: 'FAILED' } });
    throw error;
  }
}
