/**
 * Scan Queue (BullMQ)
 *
 * Manages asynchronous scan jobs. The HTTP endpoint enqueues a job
 * and returns immediately with a scanId. A background worker processes it.
 */

import { Queue } from 'bullmq';
import { getRedisClient } from '../config/redis.js';
import logger from '../utils/logger.js';

export const SCAN_QUEUE_NAME = 'aitrustlens-scans';

let scanQueue = null;

/**
 * Returns the singleton scan queue.
 * Creates it on first call.
 * @returns {Queue}
 */
export function getScanQueue() {
  if (scanQueue) return scanQueue;

  const connection = getRedisClient();

  scanQueue = new Queue(SCAN_QUEUE_NAME, {
    connection,
    defaultJobOptions: {
      attempts: 2,
      backoff: { type: 'exponential', delay: 3000 },
      removeOnComplete: { count: 500 }, // Keep last 500 completed jobs
      removeOnFail: { count: 200 },
    },
  });

  scanQueue.on('error', (err) => {
    logger.error('Scan queue error', { error: err.message });
  });

  logger.info('Scan queue initialized');
  return scanQueue;
}

/**
 * Enqueues a URL scan job.
 * @param {Object} jobData
 * @param {string} jobData.scanId  - Prisma scan record ID (already created)
 * @param {string} jobData.url
 * @param {string} jobData.userId
 * @param {Object} [jobData.options]
 * @returns {Promise<Job>}
 */
export async function enqueueUrlScan(jobData) {
  const queue = getScanQueue();
  const job = await queue.add('url_scan', jobData, {
    jobId: jobData.scanId, // Use Prisma scanId as the BullMQ job ID for easy status lookups
  });
  logger.info('URL scan job enqueued', { scanId: jobData.scanId, jobId: job.id });
  return job;
}

/**
 * Gets the current status of a scan job by its Prisma scanId.
 * @param {string} scanId
 * @returns {Promise<{state: string, progress: number, result?: Object}>}
 */
export async function getJobStatus(scanId) {
  const queue = getScanQueue();
  const job = await queue.getJob(scanId);
  if (!job) return { state: 'NOT_FOUND' };

  const state = await job.getState();
  return {
    state,
    progress: job.progress || 0,
    failedReason: job.failedReason || null,
  };
}
