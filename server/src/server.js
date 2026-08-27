import app from './app.js';
import { env } from './config/env.js';
import { connectDatabase, disconnectDatabase } from './config/database.js';
import { getRedisClient } from './config/redis.js';
import { startScanWorker } from './workers/scanWorker.js';
import logger from './utils/logger.js';

async function startServer() {
  // Connect to database
  await connectDatabase();

  // Initialize Redis (non-blocking — app degrades gracefully without it)
  const redis = getRedisClient();
  redis.connect().catch((err) => {
    logger.warn('Redis unavailable at startup — caching and async queue disabled', { error: err.message });
  });

  // Start BullMQ background worker
  const worker = startScanWorker();

  const server = app.listen(env.port, () => {
    logger.info(`🚀 AITrustLens server started`, {
      port: env.port,
      environment: env.nodeEnv,
      clientUrl: env.clientUrl,
    });
  });

  // Graceful shutdown
  const gracefulShutdown = async (signal) => {
    logger.info(`${signal} received. Shutting down gracefully...`);

    server.close(async () => {
      // Close worker and queue
      await worker.close();
      logger.info('BullMQ worker closed');

      await disconnectDatabase();
      logger.info('Database disconnected');

      redis.disconnect();
      logger.info('Redis disconnected');

      process.exit(0);
    });

    // Force close after 15s
    setTimeout(() => {
      logger.error('Forced shutdown after timeout');
      process.exit(1);
    }, 15000);
  };

  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));

  process.on('unhandledRejection', (reason) => {
    logger.error('Unhandled Promise Rejection', { reason: String(reason) });
  });

  process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception', { error: error.message, stack: error.stack });
    process.exit(1);
  });
}

startServer();
