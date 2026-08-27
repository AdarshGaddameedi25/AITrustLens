import * as urlService from '../services/urlAnalyzerService.js';
import * as qrService from '../services/qrAnalyzerService.js';
import * as emailService from '../services/emailAnalyzerService.js';
import * as scamService from '../services/scamDetectorService.js';
import * as passwordService from '../services/passwordBreachService.js';
import * as privacyService from '../services/privacyAnalyzerService.js';
import * as apkService from '../services/apkAnalyzerService.js';
import * as claimService from '../services/claimVerificationService.js';
import * as identityService from '../services/identityAnalyzerService.js';
import {
  validate,
  urlAnalysisSchema,
  emailAnalysisSchema,
  scamMessageSchema,
  passwordBreachSchema,
  privacyPolicySchema,
  apkPermissionsSchema,
  claimVerificationSchema,
  identityAnalysisSchema,
} from '../validators/inputValidator.js';
import { successResponse, errorResponse } from '../utils/responseFormatter.js';
import logger from '../utils/logger.js';
import fs from 'fs';

export async function analyzeUrl(req, res, next) {
  try {
    const { data, error } = validate(urlAnalysisSchema, req.body);
    if (error) return res.status(400).json(errorResponse('VALIDATION_ERROR', error));

    const result = await urlService.analyzeUrl(data.url, req.user.id, { skipUrlScan: data.skipUrlScan });

    // Cached result — return immediately with 200
    if (result.cached) {
      return res.json(successResponse({ ...result, fromCache: true }));
    }

    // Synchronous result (Redis unavailable) — scan already completed, return full result
    if (result.status === 'COMPLETED' && result.result) {
      return res.json(successResponse({ ...result.result, fromCache: false }));
    }

    // Async path — job was queued in BullMQ; client should poll for results
    return res.status(202).json(successResponse({
      scanId: result.scanId,
      status: 'QUEUED',
      message: 'Scan queued. Poll /api/scans/:id/status for results.',
    }));
  } catch (error) {
    if (error.code === 'SSRF_BLOCKED') {
      return res.status(400).json(errorResponse('SSRF_BLOCKED', 'The provided URL targets a disallowed address.'));
    }
    next(error);
  }
}

export async function getScanStatus(req, res, next) {
  try {
    const { id } = req.params;
    const result = await urlService.getScanStatus(id, req.user.id);
    if (!result) return res.status(404).json(errorResponse('NOT_FOUND', 'Scan not found.'));
    res.json(successResponse(result));
  } catch (error) {
    next(error);
  }
}

export async function analyzeQr(req, res, next) {
  try {
    if (!req.file) {
      return res.status(400).json(errorResponse('FILE_REQUIRED', 'A QR code image file is required.'));
    }

    const result = await qrService.analyzeQrCode(req.file.path, req.user.id);

    // Clean up temp file
    fs.unlink(req.file.path, (err) => {
      if (err) logger.warn('Failed to delete temp QR file', { path: req.file.path });
    });

    res.json(successResponse(result));
  } catch (error) {
    if (req.file?.path) {
      fs.unlink(req.file.path, () => {});
    }
    if (error.statusCode === 400 || error.code === 'QR_NOT_DETECTED') {
      return res.status(400).json(errorResponse(error.code || 'QR_PROCESSING_ERROR', error.message));
    }
    next(error);
  }
}

export async function analyzeEmail(req, res, next) {
  try {
    const { data, error } = validate(emailAnalysisSchema, req.body);
    if (error) return res.status(400).json(errorResponse('VALIDATION_ERROR', error));

    const result = await emailService.analyzeEmail(data.content, req.user.id);
    res.json(successResponse(result));
  } catch (error) {
    next(error);
  }
}

export async function analyzeScam(req, res, next) {
  try {
    const { data, error } = validate(scamMessageSchema, req.body);
    if (error) return res.status(400).json(errorResponse('VALIDATION_ERROR', error));

    const result = await scamService.analyzeScamMessage(data.message, req.user.id);
    res.json(successResponse(result));
  } catch (error) {
    next(error);
  }
}

export async function checkPassword(req, res, next) {
  try {
    const { data, error } = validate(passwordBreachSchema, req.body);
    if (error) return res.status(400).json(errorResponse('VALIDATION_ERROR', error));

    // Password is consumed directly — never passed through to logs
    const result = await passwordService.checkPassword(data.password, req.user.id);
    res.json(successResponse(result));
  } catch (error) {
    next(error);
  }
}

export async function analyzePrivacy(req, res, next) {
  try {
    const { data, error } = validate(privacyPolicySchema, req.body);
    if (error) return res.status(400).json(errorResponse('VALIDATION_ERROR', error));

    const content = data.content || await fetchUrlContent(data.url);
    const result = await privacyService.analyzePrivacyPolicy(content, req.user.id);
    res.json(successResponse(result));
  } catch (error) {
    next(error);
  }
}

export async function analyzeApk(req, res, next) {
  try {
    // If multipart APK file is uploaded
    if (req.file) {
      try {
        const result = await apkService.analyzeApkFile(req.file.path, req.user.id);
        fs.unlink(req.file.path, (err) => {
          if (err) logger.warn('Failed to delete temp APK file', { path: req.file.path });
        });
        return res.json(successResponse(result));
      } catch (fileErr) {
        if (req.file?.path) {
          fs.unlink(req.file.path, () => {});
        }
        if (fileErr.statusCode === 400 || fileErr.code === 'INVALID_APK_ARCHIVE' || fileErr.code === 'MANIFEST_NOT_FOUND') {
          return res.status(400).json(errorResponse(fileErr.code || 'APK_PARSING_ERROR', fileErr.message));
        }
        throw fileErr;
      }
    }

    // JSON permissions payload
    const { data, error } = validate(apkPermissionsSchema, req.body);
    if (error) return res.status(400).json(errorResponse('VALIDATION_ERROR', error));

    const result = await apkService.analyzeApkPermissions(
      data.permissions,
      { appName: data.appName, packageName: data.packageName, versionName: data.versionName },
      req.user.id
    );
    res.json(successResponse(result));
  } catch (error) {
    next(error);
  }
}

export async function verifyClaim(req, res, next) {
  try {
    const { data, error } = validate(claimVerificationSchema, req.body);
    if (error) return res.status(400).json(errorResponse('VALIDATION_ERROR', error));

    const result = await claimService.verifyClaim(data.claim, data.languageCode, req.user.id);
    res.json(successResponse(result));
  } catch (error) {
    next(error);
  }
}

export async function analyzeIdentity(req, res, next) {
  try {
    const { data, error } = validate(identityAnalysisSchema, req.body);
    if (error) return res.status(400).json(errorResponse('VALIDATION_ERROR', error));

    const result = await identityService.analyzeIdentity(data.email, req.user.id);
    res.json(successResponse(result));
  } catch (error) {
    next(error);
  }
}

async function fetchUrlContent(url) {
  // Simple fetch for privacy policy URLs — with SSRF protection
  const { validateSsrfSafeUrl } = await import('../utils/ssrfChecker.js');
  validateSsrfSafeUrl(url);

  const response = await fetch(url, { signal: AbortSignal.timeout(10000) });
  if (!response.ok) throw new Error(`Failed to fetch URL: ${response.status}`);
  const text = await response.text();
  return text.substring(0, 100000);
}
