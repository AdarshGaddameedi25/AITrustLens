import express from 'express';
import { PrismaClient } from '@prisma/client';
import { successResponse, errorResponse } from '../utils/responseFormatter.js';
import { env } from '../config/env.js';

const router = express.Router();
const prisma = new PrismaClient();

// In-memory cache for public stats to prevent database overload
let cachedStats = null;
let lastFetchTime = 0;
const CACHE_TTL_MS = 60000; // 1 minute

// GET /api/public/stats
router.get('/stats', async (req, res) => {
  try {
    const now = Date.now();
    if (cachedStats && (now - lastFetchTime) < CACHE_TTL_MS) {
      return res.json(successResponse(cachedStats));
    }

    // Run aggregate queries concurrently
    const [totalScans, threatsBlocked, totalUsers] = await Promise.all([
      prisma.scan.count(),
      prisma.scanResult.count({
        where: {
          riskLevel: {
            in: ['HIGH', 'CRITICAL']
          }
        }
      }),
      prisma.user.count()
    ]);

    cachedStats = {
      totalScans: totalScans,
      threatsBlocked: threatsBlocked,
      activeUsers: totalUsers,
    };
    lastFetchTime = now;

    res.json(successResponse(cachedStats));
  } catch (error) {
    console.error('Error fetching public stats:', error);
    // Return zeros as fallback
    res.json(successResponse({
      totalScans: 0,
      threatsBlocked: 0,
      activeUsers: 0
    }));
  }
});

export default router;
