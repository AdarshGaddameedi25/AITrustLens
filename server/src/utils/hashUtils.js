import crypto from 'crypto';

/**
 * Hashes a value with SHA-256.
 * Used for k-anonymity prefix generation (password breach check).
 * @param {string} value
 * @returns {string} uppercase hex hash
 */
export function sha256Hash(value) {
  return crypto.createHash('sha256').update(value).digest('hex').toUpperCase();
}

/**
 * Hashes a value with SHA-1.
 * Used for HIBP Pwned Passwords k-anonymity (uses SHA-1).
 * @param {string} value
 * @returns {string} uppercase hex hash
 */
export function sha1Hash(value) {
  return crypto.createHash('sha1').update(value).digest('hex').toUpperCase();
}

/**
 * Generates a k-anonymity prefix for HIBP password lookup.
 * Returns the first 5 characters of the SHA-1 hash.
 * IMPORTANT: The raw password is never sent to any external service.
 * @param {string} password - plaintext password (never stored, used only in memory)
 * @returns {{ prefix: string, suffix: string }} - prefix for API, suffix for local comparison
 */
export function generateKAnonymityComponents(password) {
  const hash = sha1Hash(password);
  const prefix = hash.substring(0, 5);
  const suffix = hash.substring(5);
  return { prefix, suffix };
}

/**
 * Generates a secure random token.
 * @param {number} bytes
 * @returns {string} hex token
 */
export function generateSecureToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}
