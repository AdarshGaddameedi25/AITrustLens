import * as urlService from '../services/urlAnalyzerService.js';
import * as qrService from '../services/qrAnalyzerService.js';
import * as emailService from '../services/emailAnalyzerService.js';
import * as scamService from '../services/scamDetectorService.js';
import * as passwordService from '../services/passwordBreachService.js';
import * as privacyService from '../services/privacyAnalyzerService.js';
import * as apkService from '../services/apkAnalyzerService.js';
import * as claimService from '../services/claimVerificationService.js';
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

    // Identity analysis: currently checks password breach for the email domain
    // No HIBP email API (paid) — use available free evidence
    const domain = data.email.split('@')[1];

    const result = {
      email: data.email,
      domain,
      analysisNote: 'Digital identity exposure analysis uses available free sources. For comprehensive dark-web monitoring, specialized services are required.',
      recommendations: [
        { priority: 'HIGH', category: 'IDENTITY', title: 'Enable MFA on All Accounts', detail: 'Use authenticator app-based multi-factor authentication on all important accounts.', action: 'Enable MFA immediately on email, banking, and social media accounts.' },
        { priority: 'MEDIUM', category: 'IDENTITY', title: 'Use Unique Passwords', detail: 'Each online service should have a different, strong password.', action: 'Use a password manager (Bitwarden, 1Password) to manage unique passwords.' },
        { priority: 'INFO', category: 'MONITORING', title: 'Monitor for Breaches', detail: 'Register with haveibeenpwned.com to receive notifications if your email appears in future breaches.', action: 'Visit haveibeenpwned.com and sign up for notifications.' },
      ],
      sources: [{ name: 'HIBP Email Breach API', status: 'UNAVAILABLE', reason: 'Requires paid subscription. Free k-anonymity password check available separately.' }],
      trustScore: 70,
      confidence: 'LOW',
      evidenceCoverage: 20,
    };

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
