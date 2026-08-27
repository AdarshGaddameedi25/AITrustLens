import { Router } from 'express';
import * as analyzeController from '../controllers/analyzeController.js';
import { authenticate } from '../middleware/auth.js';
import { scanLimiter, uploadLimiter, burstLimiter, perUserScanLimiter } from '../middleware/rateLimiter.js';
import { uploadImage, uploadApk, handleUploadError } from '../middleware/uploadGuard.js';

const router = Router();
const userScanLimit = perUserScanLimiter(10); // 10 scans/min per authenticated user

// All analyze routes require authentication
router.use(authenticate);

// POST /api/analyze/url
router.post('/url', burstLimiter, scanLimiter, userScanLimit, analyzeController.analyzeUrl);

// POST /api/analyze/qr  (multipart/form-data with image file)
router.post(
  '/qr',
  burstLimiter,
  uploadLimiter,
  (req, res, next) => uploadImage(req, res, (err) => { if (err) return handleUploadError(err, req, res, next); next(); }),
  analyzeController.analyzeQr
);

// POST /api/analyze/email
router.post('/email', burstLimiter, scanLimiter, userScanLimit, analyzeController.analyzeEmail);

// POST /api/analyze/scam
router.post('/scam', burstLimiter, scanLimiter, userScanLimit, analyzeController.analyzeScam);

// POST /api/analyze/password
router.post('/password', burstLimiter, scanLimiter, userScanLimit, analyzeController.checkPassword);

// POST /api/analyze/privacy
router.post('/privacy', burstLimiter, scanLimiter, userScanLimit, analyzeController.analyzePrivacy);

// POST /api/analyze/apk (supports both JSON payload and multipart file upload)
router.post(
  '/apk',
  burstLimiter,
  uploadLimiter,
  (req, res, next) => {
    // If Content-Type is multipart/form-data, process with uploadApk
    const contentType = req.headers['content-type'] || '';
    if (contentType.includes('multipart/form-data')) {
      return uploadApk(req, res, (err) => {
        if (err) return handleUploadError(err, req, res, next);
        next();
      });
    }
    next();
  },
  analyzeController.analyzeApk
);

// POST /api/analyze/apk/upload (explicit multipart route)
router.post(
  '/apk/upload',
  burstLimiter,
  uploadLimiter,
  (req, res, next) => uploadApk(req, res, (err) => { if (err) return handleUploadError(err, req, res, next); next(); }),
  analyzeController.analyzeApk
);

// POST /api/analyze/identity
router.post('/identity', burstLimiter, scanLimiter, userScanLimit, analyzeController.analyzeIdentity);

// POST /api/analyze/claim
router.post('/claim', burstLimiter, scanLimiter, userScanLimit, analyzeController.verifyClaim);

export default router;
