import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { env } from '../config/env.js';
import prisma from '../config/database.js';
import logger from '../utils/logger.js';

const SALT_ROUNDS = 12;
const ACCESS_TOKEN_TTL = '15m';           // Short-lived
const REFRESH_TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days in ms

// ─── Token Generation ─────────────────────────────────────────────────────────

/**
 * Generates a short-lived access token (15 minutes).
 * Includes a `type: "access"` claim so middleware can reject refresh tokens.
 */
function generateAccessToken(user) {
  return jwt.sign(
    {
      type: 'access',
      userId: user.id,
      email: user.email,
      role: user.role,
    },
    env.jwt.secret,
    { expiresIn: ACCESS_TOKEN_TTL }
  );
}

/**
 * Generates a cryptographically random refresh token string (opaque).
 * Returns both the raw token and its SHA-256 hash for storage.
 */
function generateRefreshToken() {
  const raw = crypto.randomBytes(64).toString('hex');
  const hash = crypto.createHash('sha256').update(raw).digest('hex');
  return { raw, hash };
}

/**
 * Creates and persists a new refresh token record.
 * @param {string} userId
 * @param {string} familyId — used for reuse detection / family revocation
 * @param {string} [ipAddress]
 * @param {string} [userAgent]
 */
async function createRefreshToken(userId, familyId, ipAddress, userAgent) {
  const { raw, hash } = generateRefreshToken();
  const expiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_MS);

  await prisma.refreshToken.create({
    data: {
      userId,
      tokenHash: hash,
      familyId,
      expiresAt,
      ipAddress: ipAddress || null,
      userAgent: userAgent || null,
    },
  });

  return raw; // Only the raw token is returned to the client, never stored
}

// ─── Public Service Methods ───────────────────────────────────────────────────

/**
 * Registers a new user and returns tokens.
 */
export async function registerUser(email, password, name, req = {}) {
  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    const error = new Error('An account with this email already exists.');
    error.code = 'EMAIL_ALREADY_EXISTS';
    error.statusCode = 409;
    throw error;
  }

  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

  const user = await prisma.user.create({
    data: { email, passwordHash, name: name || null },
    select: { id: true, email: true, name: true, role: true, createdAt: true },
  });

  logger.info('New user registered', { userId: user.id });

  const accessToken = generateAccessToken(user);
  const familyId = crypto.randomUUID();
  const refreshToken = await createRefreshToken(user.id, familyId, req.ip, req.headers?.['user-agent']);

  return { user, accessToken, refreshToken };
}

/**
 * Authenticates a user and returns tokens.
 */
export async function loginUser(email, password, req = {}) {
  const user = await prisma.user.findUnique({ where: { email } });

  // Constant-time comparison prevents timing attacks
  const passwordHash = user?.passwordHash || '$2a$12$invalidhashforcomparison000000000000000000000000000000';
  const isValid = await bcrypt.compare(password, passwordHash);

  if (!user || !isValid) {
    const error = new Error('Invalid email or password.');
    error.code = 'INVALID_CREDENTIALS';
    error.statusCode = 401;
    throw error;
  }

  logger.info('User logged in', { userId: user.id });

  const safeUser = { id: user.id, email: user.email, name: user.name, role: user.role, createdAt: user.createdAt };
  const accessToken = generateAccessToken(safeUser);
  const familyId = crypto.randomUUID();
  const refreshToken = await createRefreshToken(user.id, familyId, req.ip, req.headers?.['user-agent']);

  return { user: safeUser, accessToken, refreshToken };
}

/**
 * Rotates a refresh token. Implements reuse detection.
 * If a previously revoked token is presented, the entire token family is revoked
 * to protect against token theft.
 *
 * @param {string} rawToken — the raw refresh token from the client
 * @param {object} req — Express request object for IP/UA logging
 * @returns {Promise<{ user, accessToken, refreshToken }>}
 */
export async function rotateRefreshToken(rawToken, req = {}) {
  if (!rawToken) {
    const error = new Error('Refresh token is required.');
    error.code = 'INVALID_REFRESH_TOKEN';
    error.statusCode = 401;
    throw error;
  }

  const hash = crypto.createHash('sha256').update(rawToken).digest('hex');
  const storedToken = await prisma.refreshToken.findUnique({ where: { tokenHash: hash } });

  if (!storedToken) {
    const error = new Error('Invalid refresh token.');
    error.code = 'INVALID_REFRESH_TOKEN';
    error.statusCode = 401;
    throw error;
  }

  // ─── Reuse Detection ────────────────────────────────────────────
  // If this token has already been revoked (replaced by a newer one), it means
  // a previous token was stolen and reused. Revoke the entire token family.
  if (storedToken.revokedAt) {
    logger.warn('Refresh token reuse detected — revoking token family', {
      userId: storedToken.userId,
      familyId: storedToken.familyId,
    });
    await prisma.refreshToken.updateMany({
      where: { familyId: storedToken.familyId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    const error = new Error('Refresh token reuse detected. All sessions have been invalidated for security.');
    error.code = 'REFRESH_TOKEN_REUSE';
    error.statusCode = 401;
    throw error;
  }

  // Check expiry
  if (storedToken.expiresAt < new Date()) {
    const error = new Error('Refresh token has expired. Please log in again.');
    error.code = 'REFRESH_TOKEN_EXPIRED';
    error.statusCode = 401;
    throw error;
  }

  // Fetch user
  const user = await prisma.user.findUnique({
    where: { id: storedToken.userId },
    select: { id: true, email: true, name: true, role: true, createdAt: true },
  });

  if (!user) {
    const error = new Error('User not found.');
    error.code = 'USER_NOT_FOUND';
    error.statusCode = 401;
    throw error;
  }

  // Issue new tokens and revoke old one atomically
  const newAccessToken = generateAccessToken(user);
  const { raw: newRawRefreshToken, hash: newHash } = generateRefreshToken();
  const newExpiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_MS);

  await prisma.$transaction([
    // Revoke old token and record its replacement
    prisma.refreshToken.update({
      where: { id: storedToken.id },
      data: { revokedAt: new Date(), replacedBy: newHash },
    }),
    // Create new rotated token in the same family
    prisma.refreshToken.create({
      data: {
        userId: user.id,
        tokenHash: newHash,
        familyId: storedToken.familyId,
        expiresAt: newExpiresAt,
        ipAddress: req.ip || null,
        userAgent: req.headers?.['user-agent'] || null,
      },
    }),
  ]);

  logger.info('Refresh token rotated successfully', { userId: user.id });

  return { user, accessToken: newAccessToken, refreshToken: newRawRefreshToken };
}

/**
 * Revokes all active refresh tokens for a user (logout).
 * @param {string} userId
 * @param {string} [rawToken] — optionally revoke only the specific token/family
 */
export async function revokeRefreshTokens(userId, rawToken) {
  if (rawToken) {
    const hash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const token = await prisma.refreshToken.findUnique({ where: { tokenHash: hash } });
    if (token && token.userId === userId) {
      // Revoke the entire family of this token
      await prisma.refreshToken.updateMany({
        where: { familyId: token.familyId, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      return;
    }
  }
  // Revoke all active tokens for this user
  await prisma.refreshToken.updateMany({
    where: { userId, revokedAt: null },
    data: { revokedAt: new Date() },
  });
  logger.info('All refresh tokens revoked for user', { userId });
}

/**
 * Gets user profile by ID.
 */
export async function getUserProfile(userId) {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true, email: true, name: true, role: true, createdAt: true,
      _count: { select: { scans: true } },
    },
  });

  if (!user) {
    const error = new Error('User not found.');
    error.statusCode = 404;
    throw error;
  }

  return user;
}
