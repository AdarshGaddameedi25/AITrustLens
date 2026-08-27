import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { env } from './config/env.js';
import { requestLogger } from './middleware/requestLogger.js';
import { errorHandler, notFoundHandler } from './middleware/errorHandler.js';
import { generalLimiter } from './middleware/rateLimiter.js';
import authRoutes from './routes/auth.js';
import analyzeRoutes from './routes/analyze.js';
import scansRoutes from './routes/scans.js';
import adminRoutes from './routes/admin.js';
import { successResponse } from './utils/responseFormatter.js';
import { getRedisClient, isRedisAvailable } from './config/redis.js';
import prisma from './config/database.js';
import fs from 'fs';
import path from 'path';

const app = express();

// ── Security Headers ─────────────────────────────────────────────────────────
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: 'cross-origin' },
    contentSecurityPolicy: false, // Frontend handles this
  })
);

// ── CORS ─────────────────────────────────────────────────────────────────────
app.use(
  cors({
    origin: env.clientUrl,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

// ── Body Parsing ─────────────────────────────────────────────────────────────
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// ── Cookie Parsing (for httpOnly refresh token cookies) ───────────────────────
app.use(cookieParser());

// ── Request Logging ──────────────────────────────────────────────────────────
app.use(requestLogger);

// ── Rate Limiting ─────────────────────────────────────────────────────────────
app.use('/api/', generalLimiter);

// ── Ensure upload temp directory exists ──────────────────────────────────────
const uploadDir = path.resolve(process.cwd(), env.upload.tempDir);
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// ── Health Check (Phase 8: Production Readiness) ─────────────────────────────
// Returns 200 if all systems go, 503 if any critical dependency is unhealthy.
app.get('/api/health', async (req, res) => {
  const checks = { redis: false, database: false };
  const startedAt = Date.now();

  // Redis check
  try {
    if (isRedisAvailable()) {
      await getRedisClient().ping();
      checks.redis = true;
    } else {
      checks.redis = false;
    }
  } catch {
    checks.redis = false;
  }

  // Database check
  try {
    await prisma.$queryRaw`SELECT 1`;
    checks.database = true;
  } catch {
    checks.database = false;
  }

  const allHealthy = checks.database; // Redis is optional — DB is critical
  const responseTime = Date.now() - startedAt;

  const payload = {
    status: allHealthy ? 'ok' : 'degraded',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    environment: env.nodeEnv,
    responseTimeMs: responseTime,
    services: {
      database: checks.database ? 'healthy' : 'unavailable',
      redis: checks.redis ? 'healthy' : 'unavailable',
    },
  };

  res.status(allHealthy ? 200 : 503).json(
    allHealthy ? successResponse(payload) : { success: false, data: payload }
  );
});

// ── API Routes ───────────────────────────────────────────────────────────────
app.use('/api/auth', authRoutes);
app.use('/api/analyze', analyzeRoutes);
app.use('/api/scans', scansRoutes);
app.use('/api/admin', adminRoutes);

// ── 404 Handler ───────────────────────────────────────────────────────────────
app.use(notFoundHandler);

// ── Global Error Handler ──────────────────────────────────────────────────────
app.use(errorHandler);

export default app;
