/**
 * URL Analyzer Service — Async Architecture (Phase 7)
 *
 * Dispatches scan jobs to the BullMQ queue and returns immediately.
 * The BullMQ worker (`scanWorker.js`) processes the job in the background.
 *
 * Flow (Redis available):
 * 1. Validate & SSRF-check URL
 * 2. Check Redis cache for duplicate recent scan
 * 3. Create Prisma scan record with status=PENDING
 * 4. Enqueue job in BullMQ → return { scanId, status: 'QUEUED' } immediately
 *
 * Flow (Redis unavailable — local dev fallback):
 * 1. Validate & SSRF-check URL
 * 2. Create Prisma scan record with status=PENDING
 * 3. Run the full analysis pipeline synchronously
 * 4. Persist results and return { scanId, status: 'COMPLETED', result }
 */

import { normalizeUrl } from '../utils/urlNormalizer.js';
import { validateSsrfSafeUrl } from '../utils/ssrfChecker.js';
import { getCachedScan, acquireScanLock } from './scanCacheService.js';
import { isRedisAvailable } from '../config/redis.js';
import { enqueueUrlScan, getJobStatus } from '../queue/scanQueue.js';
import { collectUrlEvidence } from '../risk/evidenceCollector.js';
import { calculateRiskAssessment, generateRiskFactorBreakdown } from '../risk/riskEngine.js';
import { generateUrlAnalysisExplanation, AI_PROMPT_VERSION } from '../providers/openRouterProvider.js';
import { generateUrlRecommendations } from './recommendationService.js';
import prisma from '../config/database.js';
import logger from '../utils/logger.js';

/**
 * Runs the full URL scan pipeline synchronously (no Redis/BullMQ required).
 * Used as a fallback in development when Redis is offline.
 */
async function runSyncUrlScan(scanId, normalizedUrl, rawUrl, userId, options) {
  logger.info('URL scan running synchronously (Redis unavailable)', { scanId, url: normalizedUrl });

  await prisma.scan.update({ where: { id: scanId }, data: { status: 'PROCESSING' } });

  const evidence = await collectUrlEvidence(normalizedUrl, options);
  const riskAssessment = calculateRiskAssessment(evidence, 'URL');
  const riskFactors = generateRiskFactorBreakdown(riskAssessment.indicators);
  const aiExplanation = await generateUrlAnalysisExplanation(evidence, riskAssessment);
  const recommendations = generateUrlRecommendations(evidence, riskAssessment);

  // Strip any non-serializable properties (e.g. functions) from the evidence object
  const serializableEvidence = JSON.parse(JSON.stringify(evidence));

  await prisma.scanResult.create({
    data: {
      scanId,
      trustScore: riskAssessment.trustScore,
      riskLevel: riskAssessment.riskLevel,
      confidence: riskAssessment.confidence,
      evidenceCoverage: riskAssessment.evidenceCoverage,
      ruleSetVersion: riskAssessment.ruleSetVersion,
      aiPromptVersion: AI_PROMPT_VERSION,
      aiSummary: aiExplanation.summary,
      aiExplanation,
      keyIndicators: riskFactors,
      limitations: aiExplanation.limitations,
      rawApiResponses: serializableEvidence,
    },
  });

  await prisma.riskAssessment.create({
    data: {
      scanId,
      ruleSetVersion: riskAssessment.ruleSetVersion,
      rawScore: riskAssessment.rawRiskScore,
      normalizedScore: riskAssessment.trustScore,
      weightedFactors: riskAssessment.indicators,
      riskIndicators: riskFactors,
      calculationMeta: {
        availableIndicators: riskAssessment.availableIndicators,
        unavailableIndicators: riskAssessment.unavailableIndicators,
        calculatedAt: riskAssessment.calculatedAt,
        conflicts: riskAssessment.conflicts,
      },
    },
  });

  if (recommendations.length > 0) {
    await prisma.recommendation.createMany({
      data: recommendations.map((rec) => ({
        scanId,
        priority: rec.priority,
        category: rec.category,
        title: rec.title,
        detail: rec.detail,
        action: rec.action,
        evidenceBasis: rec.evidenceBasis,
      })),
    });
  }

  await prisma.scan.update({
    where: { id: scanId },
    data: { status: 'COMPLETED', completedAt: new Date() },
  });

  const result = {
    scanId,
    url: normalizedUrl,
    trustScore: riskAssessment.trustScore,
    riskLevel: riskAssessment.riskLevel,
    confidence: riskAssessment.confidence,
    evidenceCoverage: riskAssessment.evidenceCoverage,
    evidence,
    riskFactors,
    aiExplanation,
    recommendations,
    sourceStatus: evidence.sourceStatus,
    completedAt: new Date().toISOString(),
  };

  logger.info('URL sync scan complete', { scanId, trustScore: riskAssessment.trustScore, riskLevel: riskAssessment.riskLevel });
  return result;
}

/**
 * Initiates a URL scan.
 * - If Redis is available: creates DB record, enqueues BullMQ job, returns immediately.
 * - If Redis is unavailable: runs synchronously, returns full result.
 *
 * @param {string} rawUrl
 * @param {string} userId
 * @param {Object} [options]
 * @returns {Promise<{ scanId: string, status: string, cached?: boolean, result?: Object }>}
 */
export async function analyzeUrl(rawUrl, userId, options = {}) {
  // 1. Validate and normalize
  const normalizedUrl = normalizeUrl(rawUrl);
  await validateSsrfSafeUrl(normalizedUrl); // Throws SSRF_BLOCKED if unsafe

  // 2. Check cache — return immediately if we've analyzed this URL recently
  const cached = await getCachedScan(normalizedUrl);
  if (cached) {
    logger.info('Returning cached scan', { url: normalizedUrl });
    return { ...cached, cached: true };
  }

  // 3. Create scan record in DB (status=PENDING until processed)
  const scan = await prisma.scan.create({
    data: {
      userId,
      scanType: options.scanType || 'URL',
      status: 'PENDING',
    },
  });

  await prisma.scanInput.create({
    data: {
      scanId: scan.id,
      rawInput: rawUrl,
      normalizedInput: normalizedUrl,
      metadata: options.metadata || null,
    },
  });

  // 4. Choose async (Redis) or sync (fallback) path
  if (!isRedisAvailable()) {
    // Sync fallback — runs the full pipeline immediately (local dev without Redis)
    const result = await runSyncUrlScan(scan.id, normalizedUrl, rawUrl, userId, options);
    return { scanId: scan.id, status: 'COMPLETED', cached: false, result };
  }

  // 5. Acquire distributed lock (prevents identical concurrent scans)
  const lockAcquired = await acquireScanLock(normalizedUrl);
  if (!lockAcquired) {
    logger.info('Scan already in progress for URL', { url: normalizedUrl });
  }

  // 6. Enqueue background job
  await enqueueUrlScan({
    scanId: scan.id,
    url: normalizedUrl,
    userId,
    options,
  });

  logger.info('URL scan queued', { scanId: scan.id, url: normalizedUrl });

  return {
    scanId: scan.id,
    status: 'QUEUED',
    cached: false,
  };
}

/**
 * Retrieves the current status and result of a scan.
 * Used by the polling endpoint.
 *
 * @param {string} scanId
 * @param {string} userId
 * @returns {Promise<Object>}
 */
export async function getScanStatus(scanId, userId) {
  // Fetch scan record
  const scan = await prisma.scan.findFirst({
    where: { id: scanId, userId },
    include: {
      result: true,
      riskAssessment: true,
      recommendations: true,
      input: true,
    },
  });

  if (!scan) return null;

  if (scan.status === 'COMPLETED' && scan.result) {
    return {
      scanId,
      status: 'COMPLETED',
      progress: 100,
      trustScore: scan.result.trustScore,
      riskLevel: scan.result.riskLevel,
      confidence: scan.result.confidence,
      evidenceCoverage: scan.result.evidenceCoverage,
      riskFactors: scan.result.keyIndicators,
      aiExplanation: scan.result.aiExplanation,
      recommendations: scan.recommendations,
      completedAt: scan.completedAt,
    };
  }

  if (scan.status === 'FAILED') {
    return { scanId, status: 'FAILED', progress: 0 };
  }

  // For PENDING or PROCESSING, get BullMQ progress if Redis is available
  if (!isRedisAvailable()) {
    return { scanId, status: scan.status, progress: 0 };
  }

  const jobStatus = await getJobStatus(scanId).catch(() => ({ state: 'unknown', progress: 0 }));

  return {
    scanId,
    status: scan.status,
    progress: jobStatus.progress || 0,
    queueState: jobStatus.state,
  };
}
