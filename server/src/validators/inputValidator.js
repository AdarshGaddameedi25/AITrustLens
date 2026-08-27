import { z } from 'zod';

// ── URL Validation ──────────────────────────────────────────────────────────

export const urlAnalysisSchema = z.object({
  url: z
    .string()
    .trim()
    .min(1, 'URL is required')
    .max(2048, 'URL is too long')
    .refine(
      (url) => {
        try {
          const normalized = url.startsWith('http') ? url : `https://${url}`;
          new URL(normalized);
          return true;
        } catch {
          return false;
        }
      },
      { message: 'Invalid URL format' }
    ),
  skipUrlScan: z.boolean().optional().default(false),
});

// ── Email Validation ────────────────────────────────────────────────────────

export const emailAnalysisSchema = z.object({
  content: z
    .string()
    .trim()
    .min(10, 'Email content is too short')
    .max(50000, 'Email content is too long'),
});

// ── Scam Message Validation ─────────────────────────────────────────────────

export const scamMessageSchema = z.object({
  message: z
    .string()
    .trim()
    .min(5, 'Message is too short')
    .max(10000, 'Message is too long'),
});

// ── Password Validation ─────────────────────────────────────────────────────

export const passwordBreachSchema = z.object({
  password: z
    .string()
    .min(1, 'Password is required')
    .max(500, 'Password is too long'),
  // Only analyze — never store
});

// ── Privacy Policy Validation ───────────────────────────────────────────────

export const privacyPolicySchema = z.object({
  content: z
    .string()
    .min(50, 'Privacy policy content is too short')
    .max(100000, 'Privacy policy content is too long')
    .optional(),
  url: z
    .string()
    .url('Invalid URL format')
    .optional(),
}).refine(
  (data) => data.content || data.url,
  { message: 'Either content or URL must be provided' }
);

// ── APK Permissions Validation ──────────────────────────────────────────────

export const apkPermissionsSchema = z.object({
  permissions: z
    .array(
      z.string()
        .trim()
        .min(1, 'Permission name cannot be empty')
        .max(200, 'Permission name is too long')
        .regex(/^([a-zA-Z0-9._]+)$/, 'Invalid permission character format')
    )
    .min(1, 'At least one permission is required')
    .max(200, 'Too many permissions'),
  appName: z.string().trim().max(200).optional(),
  packageName: z
    .string()
    .trim()
    .max(200)
    .regex(/^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)+$/, 'Invalid Android package name format')
    .optional(),
  versionName: z.string().trim().max(100).optional(),
});

// ── Claim Verification Validation ───────────────────────────────────────────

export const claimVerificationSchema = z.object({
  claim: z
    .string()
    .min(10, 'Claim is too short')
    .max(1000, 'Claim is too long'),
  languageCode: z.string().length(2).optional().default('en'),
});

// ── Identity Analysis Validation ─────────────────────────────────────────────

export const identityAnalysisSchema = z.object({
  email: z
    .string()
    .email('Invalid email format')
    .max(254),
});

// ── Auth Validation ──────────────────────────────────────────────────────────

export const registerSchema = z.object({
  email: z.string().email('Invalid email format').max(254),
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .max(128, 'Password is too long'),
  name: z.string().min(1).max(100).optional(),
});

export const loginSchema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string().min(1, 'Password is required').max(128),
});

/**
 * Validates request body against a Zod schema.
 * Returns { data, error } — never throws.
 */
export function validate(schema, data) {
  const result = schema.safeParse(data);
  if (!result.success) {
    const issues = result.error.flatten().fieldErrors;
    const message = Object.values(issues).flat()[0] || 'Validation failed';
    return { data: null, error: message };
  }
  return { data: result.data, error: null };
}
