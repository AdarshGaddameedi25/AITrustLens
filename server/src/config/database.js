import { PrismaClient } from '@prisma/client';
import { env } from './env.js';

const globalForPrisma = globalThis;

const prisma =
  globalForPrisma.prisma ??
  new PrismaClient({
    log: env.isDev ? ['query', 'info', 'warn', 'error'] : ['error'],
  });

if (env.isDev) {
  globalForPrisma.prisma = prisma;
}

// Verify database connection
export async function connectDatabase() {
  try {
    await prisma.$connect();
    console.log('✅ Database connected successfully');
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
    process.exit(1);
  }
}

export async function disconnectDatabase() {
  await prisma.$disconnect();
}

export default prisma;
