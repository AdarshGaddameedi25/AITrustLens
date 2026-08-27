import * as authService from '../services/authService.js';
import { validate, registerSchema, loginSchema } from '../validators/inputValidator.js';
import { successResponse, errorResponse } from '../utils/responseFormatter.js';
import { env } from '../config/env.js';

const REFRESH_TOKEN_COOKIE = 'aitrust_refresh';

// ─── Cookie helpers ───────────────────────────────────────────────────────────

function setRefreshCookie(res, token) {
  res.cookie(REFRESH_TOKEN_COOKIE, token, {
    httpOnly: true,
    secure: env.nodeEnv === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: '/api/auth',
  });
}

function clearRefreshCookie(res) {
  res.clearCookie(REFRESH_TOKEN_COOKIE, {
    httpOnly: true,
    secure: env.nodeEnv === 'production',
    sameSite: 'strict',
    path: '/api/auth',
  });
}

// ─── Controllers ──────────────────────────────────────────────────────────────

export async function register(req, res, next) {
  try {
    const { data, error } = validate(registerSchema, req.body);
    if (error) return res.status(400).json(errorResponse('VALIDATION_ERROR', error));

    const { user, accessToken, refreshToken } = await authService.registerUser(data.email, data.password, data.name, req);
    setRefreshCookie(res, refreshToken);
    res.status(201).json(successResponse({ user, token: accessToken }));
  } catch (error) {
    if (error.code === 'EMAIL_ALREADY_EXISTS') {
      return res.status(409).json(errorResponse('EMAIL_ALREADY_EXISTS', error.message));
    }
    next(error);
  }
}

export async function login(req, res, next) {
  try {
    const { data, error } = validate(loginSchema, req.body);
    if (error) return res.status(400).json(errorResponse('VALIDATION_ERROR', error));

    const { user, accessToken, refreshToken } = await authService.loginUser(data.email, data.password, req);
    setRefreshCookie(res, refreshToken);
    res.json(successResponse({ user, token: accessToken }));
  } catch (error) {
    if (error.code === 'INVALID_CREDENTIALS') {
      return res.status(401).json(errorResponse('INVALID_CREDENTIALS', error.message));
    }
    next(error);
  }
}

export async function refresh(req, res, next) {
  try {
    // Read refresh token from httpOnly cookie (preferred) or body (fallback)
    const rawToken = req.cookies?.[REFRESH_TOKEN_COOKIE] || req.body?.refreshToken;

    const { user, accessToken, refreshToken: newRefreshToken } = await authService.rotateRefreshToken(rawToken, req);
    setRefreshCookie(res, newRefreshToken);
    res.json(successResponse({ user, token: accessToken }));
  } catch (error) {
    clearRefreshCookie(res);
    const knownCodes = ['INVALID_REFRESH_TOKEN', 'REFRESH_TOKEN_EXPIRED', 'REFRESH_TOKEN_REUSE', 'USER_NOT_FOUND'];
    if (knownCodes.includes(error.code)) {
      return res.status(401).json(errorResponse(error.code, error.message));
    }
    next(error);
  }
}

export async function logout(req, res, next) {
  try {
    const rawToken = req.cookies?.[REFRESH_TOKEN_COOKIE] || req.body?.refreshToken;
    await authService.revokeRefreshTokens(req.user.id, rawToken);
    clearRefreshCookie(res);
    res.json(successResponse({ message: 'Successfully logged out.' }));
  } catch (error) {
    next(error);
  }
}

export async function getProfile(req, res, next) {
  try {
    const user = await authService.getUserProfile(req.user.id);
    res.json(successResponse({ user }));
  } catch (error) {
    next(error);
  }
}
