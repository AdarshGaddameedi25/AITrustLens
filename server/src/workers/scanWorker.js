/**
 * Scan Worker (BullMQ)
 *
 * Picks up scan jobs from the queue and executes the full analysis pipeline.
 * Runs in the same process as the app (for simplicity) but isolated enough
 * to be extracted to a separate process in production.
 *
 * Pipeline per job:
 * 1. Update scan status → PROCESSING
 * 2. Collect evidence concurrently
 * 3. Calculate risk (deterministic engine)
 * 4. Generate AI explanation (OpenRouter)
 * 5. Build recommendations
 * 6. Persist results to DB
 * 7. Cache result in Redis
 * 8. Update scan status → COMPLETED
 */

import { Worker } from 'bullmq';
import { getRedisClient } from '../config/redis.js';
import { SCAN_QUEUE_NAME } from '../queue/scanQueue.js';
import { collectUrlEvidence } from '../risk/evidenceCollector.js';
import { calculateRiskAssessment, generateRiskFactorBreakdown } from '../risk/riskEngine.js';
import { generateUrlAnalysisExplanation, AI_PROMPT_VERSION } from '../providers/openRouterProvider.js';
import { generateUrlRecommendations } from '../services/recommendationService.js';
import { cacheScanResult, releaseScanLock } from '../services/scanCacheService.js';
import { pushSseEvent, closeSseClient } from '../utils/sseManager.js';
import prisma from '../config/database.js';
import logger from '../utils/logger.js';

/**
 * Processes a URL scan job from the queue.
 * @param {import('bullmq').Job} job
 */
async function processUrlScan(job) {
  const { scanId, url, userId, options = {} } = job.data;

  logger.info('Worker: starting URL scan job', { jobId: job.id, scanId, userId, url });

  await job.updateProgress(5);

  // Mark the scan as PROCESSING in DB
  await prisma.scan.update({
    where: { id: scanId },
    data: { status: 'PROCESSING' },
  });

  await job.updateProgress(10);

  // ─── Step 1: Collect Evidence ──────────────────────────────────────────────
  pushSseEvent(scanId, 'progress', {
    stage: 'EVIDENCE_COLLECTION',
    progress: 15,
    message: 'Querying VirusTotal, Safe Browsing, RDAP & URLScan...',
  });
  const evidence = await collectUrlEvidence(url, options);
  await job.updateProgress(45);

  // ─── Step 2: Calculate Risk (Deterministic) ────────────────────────────────
  pushSseEvent(scanId, 'progress', {
    stage: 'RISK_ENGINE',
    progress: 55,
    message: 'Running deterministic risk engine...',
  });
  const riskAssessment = calculateRiskAssessment(evidence, 'URL');
  const riskFactors = generateRiskFactorBreakdown(riskAssessment.indicators);
  await job.updateProgress(55);

  // ─── Step 3: AI Explanation ────────────────────────────────────────────────
  logger.info('Worker: generating AI explanation', { scanId });
  pushSseEvent(scanId, 'progress', {
    stage: 'AI_EXPLANATION',
    progress: 70,
    message: 'Generating AI explanation from evidence...',
  });
  const aiExplanation = await generateUrlAnalysisExplanation(evidence, riskAssessment);
  await job.updateProgress(75);

  // ─── Step 4: Recommendations ───────────────────────────────────────────────
  const recommendations = generateUrlRecommendations(evidence, riskAssessment);
  await job.updateProgress(80);

  // ─── Step 5: Persist Results ───────────────────────────────────────────────
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

  await job.updateProgress(90);

  // ─── Step 6: Mark Scan Complete ────────────────────────────────────────────
  await prisma.scan.update({
    where: { id: scanId },
    data: { status: 'COMPLETED', completedAt: new Date() },
  });

  // ─── Step 7: Cache & Release Lock ─────────────────────────────────────────
  const result = {
    scanId,
    url,
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

  await cacheScanResult(url, result);
  await releaseScanLock(url);

  await job.updateProgress(100);

  logger.info('Worker: URL scan complete', {
    scanId,
    trustScore: riskAssessment.trustScore,
    riskLevel: riskAssessment.riskLevel,
  });

  // ─── Step 8: Push COMPLETE event via SSE ───────────────────────────────────
  pushSseEvent(scanId, 'complete', {
    stage: 'COMPLETE',
    progress: 100,
    result,
  });
  closeSseClient(scanId);

  return result;
}

/**
 * Starts the scan worker.
 * Call this once from server startup.
 */
export function startScanWorker() {
  const connection = getRedisClient();

  const worker = new Worker(
    SCAN_QUEUE_NAME,
    async (job) => {
      if (job.name === 'url_scan') {
        return processUrlScan(job);
      }
      logger.warn('Worker: unknown job type', { jobName: job.name });
    },
    {
      connection,
      concurrency: 3, // Process up to 3 scans simultaneously
      limiter: {
        max: 10,
        duration: 60000, // Max 10 jobs/min to protect external API quotas
      },
    }
  );

  worker.on('completed', (job) => {
    logger.info('Worker: job completed', { jobId: job.id });
  });

  worker.on('failed', async (job, err) => {
    logger.error('Worker: job failed', { jobId: job?.id, scanId: job?.data?.scanId, error: err.message });

    if (job?.data?.scanId) {
      // Push FAILED event via SSE before updating DB
      pushSseEvent(job.data.scanId, 'failed', {
        stage: 'FAILED',
        progress: 0,
        error: 'The scan failed due to an internal error. Please try again.',
      });
      closeSseClient(job.data.scanId);

      try {
        await prisma.scan.update({
          where: { id: job.data.scanId },
          data: { status: 'FAILED' },
        });
        await releaseScanLock(job.data.url);
      } catch (dbErr) {
        logger.error('Worker: failed to update scan status', { error: dbErr.message });
      }
    }
  });

  worker.on('error', (err) => {
    if (err.message && err.message.includes('Connection is closed.')) {
      // Ignore to prevent terminal spam when Redis is intentionally offline
      return;
    }
    logger.error('Worker error', { error: err.message });
  });

  logger.info('Scan worker started', { concurrency: 3 });
  return worker;
}
