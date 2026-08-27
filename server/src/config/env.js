import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import { z } from 'zod';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load .env from repo root
dotenv.config({ path: path.resolve(__dirname, '../../../.env') });

const envSchema = z.object({
  PORT: z.string().default('5000'),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters'),
  JWT_EXPIRES_IN: z.string().default('7d'),
  OPENROUTER_API_KEY: z.string().optional(),
  VIRUSTOTAL_API_KEY: z.string().optional(),
  GOOGLE_SAFE_BROWSING_API_KEY: z.string().optional(),
  GOOGLE_FACTCHECK_API_KEY: z.string().optional(),
  URLSCAN_API_KEY: z.string().optional(),
  RATE_LIMIT_WINDOW_MS: z.string().default('900000'),
  RATE_LIMIT_MAX_REQUESTS: z.string().default('100'),
  CLIENT_URL: z.string().default('http://localhost:5173'),
  MAX_FILE_SIZE_MB: z.string().default('10'),
  UPLOAD_TEMP_DIR: z.string().default('uploads/temp'),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error('❌ Environment validation failed:');
  console.error(parsed.error.flatten().fieldErrors);
  process.exit(1);
}

export const env = {
  port: parseInt(parsed.data.PORT, 10),
  nodeEnv: parsed.data.NODE_ENV,
  isDev: parsed.data.NODE_ENV === 'development',
  isProd: parsed.data.NODE_ENV === 'production',
  isTest: parsed.data.NODE_ENV === 'test',
  databaseUrl: parsed.data.DATABASE_URL,
  jwt: {
    secret: parsed.data.JWT_SECRET,
    expiresIn: parsed.data.JWT_EXPIRES_IN,
  },
  apis: {
    openRouter: parsed.data.OPENROUTER_API_KEY,
    virusTotal: parsed.data.VIRUSTOTAL_API_KEY,
    safeBrowsing: parsed.data.GOOGLE_SAFE_BROWSING_API_KEY,
    factCheck: parsed.data.GOOGLE_FACTCHECK_API_KEY,
    urlScan: parsed.data.URLSCAN_API_KEY,
  },
  rateLimit: {
    windowMs: parseInt(parsed.data.RATE_LIMIT_WINDOW_MS, 10),
    max: parseInt(parsed.data.RATE_LIMIT_MAX_REQUESTS, 10),
  },
  clientUrl: parsed.data.CLIENT_URL,
  upload: {
    maxFileSizeMb: parseInt(parsed.data.MAX_FILE_SIZE_MB, 10),
    tempDir: parsed.data.UPLOAD_TEMP_DIR,
  },
};

export default env;
