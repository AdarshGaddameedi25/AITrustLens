/**
 * Admin Service — Phase 6
 * Provides paginated scan listing and audit log queries for admin dashboard.
 */
import prisma from '../config/database.js';

const PAGE_SIZE = 20;

/**
 * Returns a paginated list of all scans across all users.
 */
export async function getAllScans({ page = 1, status, userId } = {}) {
  const where = {};
  if (status) where.status = status;
  if (userId) where.userId = userId;

  const [total, scans] = await Promise.all([
    prisma.scan.count({ where }),
    prisma.scan.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      skip: (page - 1) * PAGE_SIZE,
      take: PAGE_SIZE,
      select: {
        id: true, url: true, status: true, createdAt: true, completedAt: true,
        userId: true,
        result: {
          select: { trustScore: true, riskLevel: true, confidence: true },
        },
        user: { select: { email: true } },
      },
    }),
  ]);

  return { total, page, pageSize: PAGE_SIZE, scans };
}

/**
 * Returns aggregate stats: total scans, scans by status, avg trust score.
 */
export async function getDashboardStats() {
  const [total, byStatus, avgScore] = await Promise.all([
    prisma.scan.count(),
    prisma.scan.groupBy({ by: ['status'], _count: { id: true } }),
    prisma.scanResult.aggregate({ _avg: { trustScore: true } }),
  ]);

  return {
    totalScans: total,
    byStatus: Object.fromEntries(byStatus.map(s => [s.status, s._count.id])),
    averageTrustScore: Math.round(avgScore._avg.trustScore ?? 0),
  };
}
