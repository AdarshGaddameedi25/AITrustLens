/**
 * AI Output Schema — Phase 3: Zod Validation
 *
 * All AI responses MUST conform to this schema before being used.
 * If validation fails, the safe fallback is used — AI output never leaks
 * unvalidated data into the application.
 */

import { z } from 'zod';

const CONFIDENCE_LEVELS = ['HIGH', 'MEDIUM', 'LOW'];

export const AiExplanationSchema = z.object({
  summary:         z.string().min(1).max(2000),
  riskExplanation: z.string().min(1).max(5000),
  keyIndicators:   z.array(z.string().max(500)).min(0).max(20),
  recommendations: z.array(z.string().max(500)).min(0).max(20),
  limitations:     z.array(z.string().max(500)).min(0).max(20),
  confidence:      z.enum(CONFIDENCE_LEVELS).default('LOW'),
}).strict(); // No extra fields allowed — prevents data exfiltration via AI

/**
 * Validates a parsed AI response against the Zod schema.
 * @param {unknown} parsed - The parsed JSON from the AI
 * @returns {{ success: boolean, data?: object, error?: string }}
 */
export function validateAiOutput(parsed) {
  const result = AiExplanationSchema.safeParse(parsed);
  if (result.success) {
    return { success: true, data: result.data };
  }
  return {
    success: false,
    error: result.error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join('; '),
  };
}
