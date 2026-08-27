/**
 * Admin Routes — Phase 6
 * Protected by authenticate + requireAdmin middleware.
 * All endpoints return paginated, structured responses.
 */
import { Router } from 'express';
import { authenticate, requireAdmin } from '../middleware/auth.js';
import { getAllScans, getDashboardStats } from '../services/adminService.js';
import { successResponse, errorResponse } from '../utils/responseFormatter.js';
import { authLimiter } from '../middleware/rateLimiter.js';

const router = Router();

// All admin routes require valid JWT AND admin role
router.use(authenticate, requireAdmin);

// GET /api/admin/stats — dashboard summary
router.get('/stats', async (req, res, next) => {
  try {
    const stats = await getDashboardStats();
    res.json(successResponse(stats));
  } catch (err) {
    next(err);
  }
});

// GET /api/admin/scans?page=1&status=COMPLETED&userId=xxx
router.get('/scans', async (req, res, next) => {
  try {
    const { page = '1', status, userId } = req.query;
    const pageNum = Math.max(1, parseInt(page, 10) || 1);
    const result = await getAllScans({ page: pageNum, status, userId });
    res.json(successResponse(result));
  } catch (err) {
    next(err);
  }
});

export default router;
