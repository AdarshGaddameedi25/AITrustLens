import jwt from 'jsonwebtoken';
import { env } from '../config/env.js';
import { errorResponse } from '../utils/responseFormatter.js';

// ─── Middleware ───────────────────────────────────────────────────────────────

/**
 * JWT Authentication middleware.
 * Verifies the Bearer access token and attaches decoded user to req.user.
 * Short-lived access tokens (15 min). Refresh token logic is handled via /auth/refresh.
 */
export function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json(
      errorResponse('AUTHENTICATION_REQUIRED', 'Authentication is required to access this resource.')
    );
  }

  const token = authHeader.substring(7);

  try {
    const decoded = jwt.verify(token, env.jwt.secret);

    // Only accept access tokens here, not refresh tokens
    if (decoded.type !== 'access') {
      return res.status(401).json(
        errorResponse('INVALID_TOKEN', 'Invalid token type. Please use your access token.')
      );
    }

    // Attach user info from token — never trust user-provided userId
    req.user = {
      id: decoded.userId,
      email: decoded.email,
      role: decoded.role,
    };
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json(
        errorResponse('TOKEN_EXPIRED', 'Your session has expired. Please refresh your token.')
      );
    }
    return res.status(401).json(
      errorResponse('INVALID_TOKEN', 'Invalid authentication token.')
    );
  }
}

/**
 * Optional authentication — attaches user if valid token present, continues if not.
 */
export function optionalAuthenticate(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    req.user = null;
    return next();
  }

  const token = authHeader.substring(7);
  try {
    const decoded = jwt.verify(token, env.jwt.secret);
    if (decoded.type === 'access') {
      req.user = {
        id: decoded.userId,
        email: decoded.email,
        role: decoded.role,
      };
    } else {
      req.user = null;
    }
  } catch {
    req.user = null;
  }
  next();
}

/**
 * Role-based access control middleware.
 * Must be used AFTER authenticate().
 * @param {...string} roles - Allowed roles (e.g. 'ADMIN', 'USER')
 */
export function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json(
        errorResponse('AUTHENTICATION_REQUIRED', 'Authentication is required.')
      );
    }
    if (!roles.includes(req.user.role)) {
      return res.status(403).json(
        errorResponse('FORBIDDEN', `Access requires one of the following roles: ${roles.join(', ')}.`)
      );
    }
    next();
  };
}

/**
 * Admin-only shortcut middleware (must be used after authenticate).
 */
export function requireAdmin(req, res, next) {
  return requireRole('ADMIN')(req, res, next);
}

/**
 * Resource ownership middleware.
 * Ensures the authenticated user owns the resource being requested.
 * The route must pass the owner's userId via req.resourceOwnerId
 * (set by the controller after fetching the resource).
 *
 * Usage: Set req.resourceOwnerId in the controller, then call this middleware,
 * OR use the helper verifyResourceOwnership() directly in controllers.
 */
export function requireOwnership(req, res, next) {
  if (!req.user) {
    return res.status(401).json(
      errorResponse('AUTHENTICATION_REQUIRED', 'Authentication is required.')
    );
  }
  // Admins can access any resource
  if (req.user.role === 'ADMIN') return next();

  if (!req.resourceOwnerId || req.resourceOwnerId !== req.user.id) {
    // Return 404 to prevent leaking resource existence to unauthorized users
    return res.status(404).json(
      errorResponse('NOT_FOUND', 'Resource not found.')
    );
  }
  next();
}

/**
 * Helper function for controllers to verify resource ownership imperatively.
 * Throws a formatted error if the user does not own the resource.
 *
 * @param {object} user - req.user from authenticate middleware
 * @param {string} ownerId - The owner's userId from the database record
 */
export function verifyResourceOwnership(user, ownerId) {
  if (!user) {
    const err = new Error('Authentication required.');
    err.statusCode = 401;
    err.code = 'AUTHENTICATION_REQUIRED';
    throw err;
  }
  if (user.role === 'ADMIN') return; // Admins bypass ownership checks
  if (user.id !== ownerId) {
    const err = new Error('Resource not found.');
    err.statusCode = 404; // Obscure existence
    err.code = 'NOT_FOUND';
    throw err;
  }
}

/**
 * Verifies a raw JWT access token and returns the decoded payload.
 * Used by the SSE route which receives the token via query param
 * (EventSource does not support custom headers).
 *
 * @param {string} token
 * @returns {object} decoded JWT payload
 * @throws if the token is invalid or expired
 */
export function verifyAccessToken(token) {
  const decoded = jwt.verify(token, env.jwt.secret);
  if (decoded.type !== 'access') {
    throw new Error('Invalid token type.');
  }
  return decoded;
}
