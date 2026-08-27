import { Router } from 'express';
import * as scanController from '../controllers/scanController.js';
import { getScanStatus } from '../controllers/analyzeController.js';
import { authenticate } from '../middleware/auth.js';
import { registerSseClient } from '../utils/sseManager.js';

const router = Router();

router.use(authenticate);

// GET /api/scans
router.get('/', scanController.getScans);

// GET /api/scans/dashboard
router.get('/dashboard', scanController.getDashboard);

// GET /api/scans/:id/stream — SSE real-time stream for live scan progress (Phase 2)
// EventSource doesn't support custom headers; we accept the JWT via query param for this route only.
router.get('/:id/stream', (req, res, next) => {
  const { id: scanId } = req.params;
  const token = req.query.token;

  // Manually validate token (same logic as authenticate middleware but from query)
  if (!token) {
    res.status(401).end();
    return;
  }

  // Lazily import to avoid circular deps
  import('../middleware/auth.js').then(({ verifyAccessToken }) => {
    try {
      verifyAccessToken(token); // throws if invalid/expired
      registerSseClient(scanId, res);
    } catch {
      res.status(401).end();
    }
  }).catch(next);
});

// GET /api/scans/:id/status — Async polling fallback (kept for backward compatibility)
router.get('/:id/status', getScanStatus);

// GET /api/scans/:id
router.get('/:id', scanController.getScan);

// DELETE /api/scans/:id
router.delete('/:id', scanController.deleteScan);

export default router;
