/**
 * XSS Sanitizer Utility
 *
 * Wraps DOMPurify to sanitize any AI-generated or user-supplied HTML/text
 * before rendering in the DOM. Prevents XSS from injected AI output.
 *
 * Usage:
 *   import { sanitize, SafeHtml } from '../utils/sanitize';
 *   <SafeHtml html={aiExplanation.summary} />
 *   const clean = sanitize(rawText);
 */

import DOMPurify from 'dompurify';

/**
 * Strict configuration: no HTML at all — plain text only.
 * Use this for fields that should NEVER contain markup.
 */
const TEXT_ONLY_CONFIG = {
  ALLOWED_TAGS: [],
  ALLOWED_ATTR: [],
};

/**
 * Safe-markdown config: allows only basic formatting tags.
 * Use this for AI explanations that may use bold/italic.
 */
const SAFE_MARKDOWN_CONFIG = {
  ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'br', 'p', 'ul', 'ol', 'li'],
  ALLOWED_ATTR: [],
};

/**
 * Sanitizes a string to plain text (no HTML tags).
 * @param {string} dirty
 * @returns {string}
 */
export function sanitize(dirty) {
  if (!dirty) return '';
  return DOMPurify.sanitize(String(dirty), TEXT_ONLY_CONFIG);
}

/**
 * Sanitizes a string allowing only safe markdown-like tags.
 * @param {string} dirty
 * @returns {string}
 */
export function sanitizeMarkdown(dirty) {
  if (!dirty) return '';
  return DOMPurify.sanitize(String(dirty), SAFE_MARKDOWN_CONFIG);
}

/**
 * React component that renders sanitized HTML safely.
 * Replaces all direct dangerouslySetInnerHTML usage.
 *
 * @param {{ html: string, className?: string, as?: string }} props
 */
export function SafeHtml({ html, className, as: Tag = 'div' }) {
  const clean = sanitizeMarkdown(html);
  return <Tag className={className} dangerouslySetInnerHTML={{ __html: clean }} />;
}
