import { Router } from 'express';
import * as authController from '../controllers/authController.js';
import { authenticate } from '../middleware/auth.js';
import { authLimiter } from '../middleware/rateLimiter.js';

const router = Router();

// POST /api/auth/register
router.post('/register', authLimiter, authController.register);

// POST /api/auth/login
router.post('/login', authLimiter, authController.login);

// POST /api/auth/refresh  — rotates the refresh token
router.post('/refresh', authLimiter, authController.refresh);

// POST /api/auth/logout  — revokes the refresh token
router.post('/logout', authenticate, authController.logout);

// GET /api/auth/me
router.get('/me', authenticate, authController.getProfile);

export default router;
