/**
 * Scam Message Detector Service
 */

import { generateScamAnalysisExplanation } from '../providers/openRouterProvider.js';
import { calculateRiskAssessment } from '../risk/riskEngine.js';
import prisma from '../config/database.js';
import logger from '../utils/logger.js';

const SCAM_PATTERNS = [
  // Payment scams
  { id: 'PAYMENT_REQUEST', pattern: /pay|transfer|send money|wire|western union|moneygram/i, severity: 60, category: 'PAYMENT_SCAM' },
  { id: 'CRYPTOCURRENCY', pattern: /bitcoin|ethereum|crypto|usdt|binance/i, severity: 70, category: 'CRYPTO_SCAM' },
  // Job scams
  { id: 'JOB_OFFER', pattern: /work from home|earn \$|per week|hiring now|no experience needed/i, severity: 65, category: 'JOB_SCAM' },
  // Prize/lottery
  { id: 'LOTTERY_WIN', pattern: /won|winner|prize|lottery|lucky draw|claim your/i, severity: 80, category: 'PRIZE_SCAM' },
  // Investment
  { id: 'INVESTMENT', pattern: /invest|guaranteed return|profit|roi|trading/i, severity: 70, category: 'INVESTMENT_SCAM' },
  // OTP/Credential theft
  { id: 'OTP_REQUEST', pattern: /otp|one.time.password|pin|verification code/i, severity: 90, category: 'OTP_SCAM' },
  // Impersonation
  { id: 'BANK_IMPERSONATION', pattern: /your bank|reserve bank|account blocked|frozen/i, severity: 85, category: 'IMPERSONATION' },
  { id: 'GOV_IMPERSONATION', pattern: /income tax|irs|police|government|official notice/i, severity: 80, category: 'IMPERSONATION' },
  // Urgency
  { id: 'URGENCY', pattern: /urgent|immediately|within 24|action required|last chance/i, severity: 40, category: 'SOCIAL_ENGINEERING' },
  // Romance
  { id: 'ROMANCE', pattern: /i love you|soulmate|relationship|meet you|beautiful lady/i, severity: 50, category: 'ROMANCE_SCAM' },
  // Links
  { id: 'SHORT_URL', pattern: /bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly/i, severity: 30, category: 'SUSPICIOUS_LINK' },
];

/**
 * Analyzes a message for scam indicators.
 * @param {string} message
 * @param {string} userId
 */
export async function analyzeScamMessage(message, userId) {
  const scan = await prisma.scan.create({
    data: { userId, scanType: 'SCAM_MESSAGE', status: 'PROCESSING' },
  });

  await prisma.scanInput.create({
    data: { scanId: scan.id, rawInput: message.substring(0, 5000) },
  });

  try {
    const scamPatterns = detectScamPatterns(message);
    const financialRequest = { detected: /pay|transfer|send|money|bank/i.test(message) };
    const credentialRequest = { detected: /otp|password|pin|code|verify/i.test(message) };
    const detectedCategories = [...new Set(scamPatterns.map((p) => p.category))];

    const evidence = {
      scamPatterns,
      financialRequest,
      credentialRequest,
      detectedCategories,
      messageLength: message.length,
      hasUrls: /https?:\/\//i.test(message),
      hasPhonenumber: /\+?\d[\d\s\-]{8,}/i.test(message),
    };

    const riskAssessment = calculateRiskAssessment(evidence, 'SCAM_MESSAGE');
    const aiExplanation = await generateScamAnalysisExplanation(evidence, riskAssessment);

    const recommendations = [];
    if (riskAssessment.trustScore < 50) {
      recommendations.push({ priority: 'CRITICAL', category: 'SCAM', title: 'Potential Scam Detected', detail: 'This message shows multiple scam indicators.', action: 'Do not respond. Block and report the sender.', evidenceBasis: `Scam patterns: ${detectedCategories.join(', ')}` });
    }
    if (credentialRequest.detected) {
      recommendations.push({ priority: 'CRITICAL', category: 'CREDENTIALS', title: 'Credential/OTP Request Detected', detail: 'This message is asking for your OTP or password.', action: 'Never share OTPs or passwords via any message. Legitimate services never ask for these.', evidenceBasis: 'OTP/credential request pattern detected' });
    }

    await prisma.scanResult.create({
      data: { scanId: scan.id, trustScore: riskAssessment.trustScore, riskLevel: riskAssessment.riskLevel, confidence: riskAssessment.confidence, evidenceCoverage: riskAssessment.evidenceCoverage, aiSummary: aiExplanation.summary, aiExplanation, keyIndicators: riskAssessment.indicators, rawApiResponses: evidence },
    });

    await prisma.scan.update({ where: { id: scan.id }, data: { status: 'COMPLETED', completedAt: new Date() } });

    return { scanId: scan.id, trustScore: riskAssessment.trustScore, riskLevel: riskAssessment.riskLevel, confidence: riskAssessment.confidence, evidenceCoverage: riskAssessment.evidenceCoverage, evidence, aiExplanation, recommendations, completedAt: new Date().toISOString() };
  } catch (error) {
    logger.error('Scam analysis failed', { scanId: scan.id, error: error.message });
    await prisma.scan.update({ where: { id: scan.id }, data: { status: 'FAILED' } });
    throw error;
  }
}

function detectScamPatterns(message) {
  return SCAM_PATTERNS
    .filter(({ pattern }) => pattern.test(message))
    .map(({ id, severity, category }) => ({ id, severity, category }));
}
