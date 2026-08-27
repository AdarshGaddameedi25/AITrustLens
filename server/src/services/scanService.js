/**
 * Scan History Service
 */

import prisma from '../config/database.js';

/**
 * Gets paginated scan history for a user.
 */
export async function getUserScans(userId, page = 1, limit = 20, scanType = null) {
  const skip = (page - 1) * limit;
  const where = { userId, ...(scanType ? { scanType } : {}) };

  const [scans, total] = await Promise.all([
    prisma.scan.findMany({
      where,
      skip,
      take: limit,
      orderBy: { createdAt: 'desc' },
      include: {
        input: { select: { normalizedInput: true, rawInput: true } },
        result: { select: { trustScore: true, riskLevel: true, confidence: true, evidenceCoverage: true, aiSummary: true } },
      },
    }),
    prisma.scan.count({ where }),
  ]);

  return { scans, total, page, limit };
}

/**
 * Gets a specific scan with full results.
 * Enforces ownership — users can only see their own scans.
 */
export async function getScanById(scanId, userId) {
  const scan = await prisma.scan.findFirst({
    where: { id: scanId, userId }, // Always enforce userId
    include: {
      input: true,
      result: true,
      evidences: true,
      riskAssessment: true,
      recommendations: { orderBy: { priority: 'asc' } },
    },
  });

  if (!scan) {
    const error = new Error('Scan not found or access denied.');
    error.statusCode = 404;
    throw error;
  }

  return scan;
}

/**
 * Gets dashboard statistics for a user.
 */
export async function getDashboardStats(userId) {
  const [totalScans, recentScans, scanTypeCounts] = await Promise.all([
    prisma.scan.count({ where: { userId } }),
    prisma.scan.findMany({
      where: { userId, status: 'COMPLETED' },
      orderBy: { createdAt: 'desc' },
      take: 5,
      include: {
        input: { select: { normalizedInput: true, rawInput: true } },
        result: { select: { trustScore: true, riskLevel: true, aiSummary: true } },
      },
    }),
    prisma.scan.groupBy({
      by: ['scanType'],
      where: { userId },
      _count: { scanType: true },
    }),
  ]);

  // Risk distribution
  const riskDistribution = await prisma.scanResult.groupBy({
    by: ['riskLevel'],
    where: { scan: { userId } },
    _count: { riskLevel: true },
  });

  return { totalScans, recentScans, scanTypeCounts, riskDistribution };
}

/**
 * Deletes a scan (user can delete their own scans).
 */
export async function deleteScan(scanId, userId) {
  const scan = await prisma.scan.findFirst({ where: { id: scanId, userId } });
  if (!scan) {
    const error = new Error('Scan not found or access denied.');
    error.statusCode = 404;
    throw error;
  }
  await prisma.scan.delete({ where: { id: scanId } });
  return true;
}
