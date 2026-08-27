/**
 * Email Phishing Analyzer Service
 */

import { generateEmailAnalysisExplanation } from '../providers/openRouterProvider.js';
import { calculateRiskAssessment } from '../risk/riskEngine.js';
import { collectEmailEvidence } from '../risk/evidenceCollector.js';
import { generateEmailRecommendations } from './recommendationService.js';
import prisma from '../config/database.js';
import logger from '../utils/logger.js';

// Common phishing keywords with severity weighting
const PHISHING_KEYWORDS = [
  { term: 'verify your account', score: 3 },
  { term: 'click here immediately', score: 3 },
  { term: 'your account has been suspended', score: 4 },
  { term: 'confirm your identity', score: 3 },
  { term: 'update your payment', score: 4 },
  { term: 'unusual activity', score: 2 },
  { term: 'action required', score: 2 },
  { term: 'unauthorized access', score: 2 },
  { term: 'your password', score: 2 },
  { term: 'one-time password', score: 3 },
  { term: 'otp', score: 3 },
  { term: 'limited time', score: 2 },
  { term: 'expires in', score: 2 },
  { term: 'win a prize', score: 4 },
  { term: 'claim your reward', score: 4 },
  { term: 'credit card details', score: 5 },
  { term: 'bank account', score: 3 },
];

// URL extraction regex
const URL_REGEX = /https?:\/\/[^\s<>"']+/gi;

// Common free email providers used in spoofing
const FREE_EMAIL_PROVIDERS = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'protonmail.com'];

/**
 * Analyzes an email for phishing indicators.
 * @param {string} emailContent - Raw email content
 * @param {string} userId
 * @returns {Promise<Object>}
 */
export async function analyzeEmail(emailContent, userId) {
  const scan = await prisma.scan.create({
    data: { userId, scanType: 'EMAIL', status: 'PROCESSING' },
  });

  await prisma.scanInput.create({
    data: {
      scanId: scan.id,
      rawInput: emailContent.substring(0, 10000), // Store up to 10KB
    },
  });

  try {
    // Extract components
    const extracted = extractEmailComponents(emailContent);

    // Check URLs in email
    const urlEvidence = extracted.urls.length > 0
      ? await collectEmailEvidence(extracted.urls)
      : [];

    // Build evidence object
    const evidence = {
      senderAnalysis: analyzeSender(extracted.sender),
      phishingKeywords: detectPhishingKeywords(emailContent),
      urgencyIndicators: detectUrgencyIndicators(emailContent),
      credentialRequest: detectCredentialRequest(emailContent),
      financialRequest: detectFinancialRequest(emailContent),
      urlAnalysis: { results: urlEvidence, count: urlEvidence.length },
      urlsFound: extracted.urls,
      subject: extracted.subject,
      sender: extracted.sender,
    };

    const riskAssessment = calculateRiskAssessment(evidence, 'EMAIL');
    const aiExplanation = await generateEmailAnalysisExplanation(evidence, riskAssessment);
    const recommendations = generateEmailRecommendations(evidence, riskAssessment);

    await prisma.scanResult.create({
      data: {
        scanId: scan.id,
        trustScore: riskAssessment.trustScore,
        riskLevel: riskAssessment.riskLevel,
        confidence: riskAssessment.confidence,
        evidenceCoverage: riskAssessment.evidenceCoverage,
        aiSummary: aiExplanation.summary,
        aiExplanation,
        keyIndicators: riskAssessment.indicators,
        rawApiResponses: evidence,
      },
    });

    await prisma.scan.update({
      where: { id: scan.id },
      data: { status: 'COMPLETED', completedAt: new Date() },
    });

    return {
      scanId: scan.id,
      trustScore: riskAssessment.trustScore,
      riskLevel: riskAssessment.riskLevel,
      confidence: riskAssessment.confidence,
      evidenceCoverage: riskAssessment.evidenceCoverage,
      evidence,
      aiExplanation,
      recommendations,
      completedAt: new Date().toISOString(),
    };
  } catch (error) {
    logger.error('Email analysis failed', { scanId: scan.id, error: error.message });
    await prisma.scan.update({ where: { id: scan.id }, data: { status: 'FAILED' } });
    throw error;
  }
}

function extractEmailComponents(content) {
  const lines = content.split('\n');
  let sender = '';
  let subject = '';

  for (const line of lines.slice(0, 20)) {
    if (line.toLowerCase().startsWith('from:')) sender = line.substring(5).trim();
    if (line.toLowerCase().startsWith('subject:')) subject = line.substring(8).trim();
  }

  const urls = [...new Set(content.match(URL_REGEX) || [])].slice(0, 10);
  return { sender, subject, urls };
}

function analyzeSender(sender) {
  const flags = [];
  if (!sender) return { flags, domain: null };

  const domain = sender.match(/@([^\s>]+)/)?.[1]?.toLowerCase();

  // Check for spoofed display name
  if (sender.includes('<') && sender.includes('>')) {
    const displayName = sender.substring(0, sender.indexOf('<')).toLowerCase();
    if (displayName.includes('paypal') || displayName.includes('amazon') || displayName.includes('apple')) {
      if (domain && !domain.includes('paypal.com') && !domain.includes('amazon.com') && !domain.includes('apple.com')) {
        flags.push('DOMAIN_MISMATCH');
      }
    }
  }

  return { flags, domain };
}

function detectPhishingKeywords(content) {
  const lower = content.toLowerCase();
  const matches = [];
  let count = 0;

  for (const { term, score } of PHISHING_KEYWORDS) {
    if (lower.includes(term)) {
      matches.push({ term, score });
      count += score;
    }
  }

  return { count, matches };
}

function detectUrgencyIndicators(content) {
  const lower = content.toLowerCase();
  const urgencyWords = ['urgent', 'immediately', 'asap', 'today only', '24 hours', 'expires', 'deadline'];
  let score = 0;
  const found = [];

  for (const word of urgencyWords) {
    if (lower.includes(word)) { score++; found.push(word); }
  }

  return { score, found };
}

function detectCredentialRequest(content) {
  const lower = content.toLowerCase();
  const credentialTerms = ['enter your password', 'provide your password', 'enter otp', 'enter your pin', 'verify with otp'];
  const detected = credentialTerms.some((t) => lower.includes(t));
  return { detected };
}

function detectFinancialRequest(content) {
  const lower = content.toLowerCase();
  const financialTerms = ['credit card', 'debit card', 'bank transfer', 'wire transfer', 'bitcoin', 'payment details'];
  const detected = financialTerms.some((t) => lower.includes(t));
  return { detected };
}
