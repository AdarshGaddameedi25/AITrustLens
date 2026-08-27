/**
 * Password Breach Service
 */

import { checkPasswordBreach } from '../providers/pwnedPasswordsProvider.js';
import { generatePasswordRecommendations } from './recommendationService.js';
import prisma from '../config/database.js';
import logger from '../utils/logger.js';

// Password strength evaluation (local only)
function evaluatePasswordStrength(password) {
  let score = 0;
  const feedback = [];

  if (password.length >= 12) score += 2; else if (password.length >= 8) score += 1; else feedback.push('Use at least 12 characters');
  if (/[A-Z]/.test(password)) score += 1; else feedback.push('Add uppercase letters');
  if (/[a-z]/.test(password)) score += 1; else feedback.push('Add lowercase letters');
  if (/[0-9]/.test(password)) score += 1; else feedback.push('Add numbers');
  if (/[^A-Za-z0-9]/.test(password)) score += 2; else feedback.push('Add special characters (!@#$...)');

  const strengthMap = { 0: 'VERY_WEAK', 1: 'WEAK', 2: 'WEAK', 3: 'MODERATE', 4: 'MODERATE', 5: 'STRONG', 6: 'STRONG', 7: 'VERY_STRONG' };

  return { score, strength: strengthMap[Math.min(score, 7)], feedback };
}

/**
 * Checks password breach status and evaluates strength.
 * SECURITY: Password is processed in memory only, never stored or logged.
 * @param {string} password - Raw password (never stored)
 * @param {string} userId
 */
export async function checkPassword(password, userId) {
  const scan = await prisma.scan.create({
    data: { userId, scanType: 'PASSWORD_BREACH', status: 'PROCESSING' },
  });

  // Store only metadata — NEVER the password
  await prisma.scanInput.create({
    data: {
      scanId: scan.id,
      rawInput: '[PASSWORD REDACTED FOR SECURITY]',
      metadata: { passwordLength: password.length, checkedAt: new Date().toISOString() },
    },
  });

  try {
    const [breachResult, strengthResult] = await Promise.allSettled([
      checkPasswordBreach(password),
      Promise.resolve(evaluatePasswordStrength(password)),
    ]);

    const breach = breachResult.status === 'fulfilled' ? breachResult.value : { status: 'UNAVAILABLE' };
    const strength = strengthResult.status === 'fulfilled' ? strengthResult.value : { strength: 'UNKNOWN', score: 0, feedback: [] };

    const recommendations = generatePasswordRecommendations(breach);

    // Trust score: exposed = critical, strength-based otherwise
    let trustScore = 70;
    if (breach.status === 'EXPOSED') trustScore = Math.max(0, 20 - Math.min(20, Math.floor(Math.log10(breach.breachCount + 1) * 5)));
    else if (breach.status === 'NOT_FOUND') trustScore = Math.min(90, 50 + strength.score * 5);

    await prisma.scanResult.create({
      data: {
        scanId: scan.id,
        trustScore,
        riskLevel: trustScore < 30 ? 'CRITICAL' : trustScore < 50 ? 'HIGH' : trustScore < 70 ? 'MODERATE' : 'LOW',
        confidence: breach.status === 'AVAILABLE' || breach.status === 'EXPOSED' || breach.status === 'NOT_FOUND' ? 'HIGH' : 'LOW',
        evidenceCoverage: breach.status !== 'UNAVAILABLE' ? 80 : 20,
        aiSummary: breach.status === 'EXPOSED' ? `Password found in ${breach.breachCount?.toLocaleString()} breaches.` : breach.status === 'NOT_FOUND' ? 'Password not found in known breach databases.' : 'Unable to verify breach status.',
        rawApiResponses: { breachStatus: breach.status, breachCount: breach.breachCount, strength: strength.strength },
      },
    });

    await prisma.scan.update({ where: { id: scan.id }, data: { status: 'COMPLETED', completedAt: new Date() } });

    return {
      scanId: scan.id,
      breachStatus: breach.status,
      breachCount: breach.breachCount,
      passwordStrength: strength.strength,
      strengthScore: strength.score,
      strengthFeedback: strength.feedback,
      trustScore,
      recommendations,
      note: breach.note || null,
      completedAt: new Date().toISOString(),
    };
  } catch (error) {
    logger.error('Password breach check failed', { scanId: scan.id, error: error.message });
    await prisma.scan.update({ where: { id: scan.id }, data: { status: 'FAILED' } });
    throw error;
  }
}
