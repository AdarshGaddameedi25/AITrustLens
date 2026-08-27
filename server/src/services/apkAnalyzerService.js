/**
 * APK Permission Analyzer Service
 */

import { callOpenRouter } from '../providers/openRouterProvider.js';
import { validateAiOutput } from '../utils/aiOutputSchema.js';
import { generateApkRecommendations } from './recommendationService.js';
import prisma from '../config/database.js';
import logger from '../utils/logger.js';

const PERMISSION_DATABASE = {
  // SMS Permissions
  'android.permission.READ_SMS': { level: 'CRITICAL', category: 'SMS', description: 'Read your SMS messages (often used for OTP theft)' },
  'android.permission.RECEIVE_SMS': { level: 'CRITICAL', category: 'SMS', description: 'Receive incoming SMS messages (high risk of OTP intercept)' },
  'android.permission.SEND_SMS': { level: 'CRITICAL', category: 'SMS', description: 'Send SMS messages (can incur premium charge fraud)' },
  'android.permission.RECEIVE_MMS': { level: 'CRITICAL', category: 'SMS', description: 'Receive MMS messages' },

  // Contacts & Calendar
  'android.permission.READ_CONTACTS': { level: 'HIGH', category: 'CONTACTS', description: 'Read details about your contacts list' },
  'android.permission.WRITE_CONTACTS': { level: 'HIGH', category: 'CONTACTS', description: 'Modify or create contacts' },
  'android.permission.GET_ACCOUNTS': { level: 'HIGH', category: 'ACCOUNTS', description: 'Access lists of accounts registered on the device' },
  'android.permission.READ_CALENDAR': { level: 'MEDIUM', category: 'CALENDAR', description: 'Read calendar events' },
  'android.permission.WRITE_CALENDAR': { level: 'MEDIUM', category: 'CALENDAR', description: 'Modify or create calendar events' },

  // Media & Sensors
  'android.permission.RECORD_AUDIO': { level: 'HIGH', category: 'MICROPHONE', description: 'Record audio via device microphone (potential eavesdropping)' },
  'android.permission.CAMERA': { level: 'HIGH', category: 'CAMERA', description: 'Take photos or videos' },
  'android.permission.BODY_SENSORS': { level: 'MEDIUM', category: 'SENSORS', description: 'Access heart rate or other biological sensors' },

  // Location
  'android.permission.ACCESS_FINE_LOCATION': { level: 'HIGH', category: 'LOCATION', description: 'Access precise GPS location' },
  'android.permission.ACCESS_COARSE_LOCATION': { level: 'MEDIUM', category: 'LOCATION', description: 'Access coarse location based on cell towers/WiFi' },
  'android.permission.ACCESS_BACKGROUND_LOCATION': { level: 'HIGH', category: 'LOCATION', description: 'Access location in the background' },

  // Device & Calls
  'android.permission.READ_CALL_LOG': { level: 'CRITICAL', category: 'CALL_LOG', description: 'Read call history details' },
  'android.permission.WRITE_CALL_LOG': { level: 'CRITICAL', category: 'CALL_LOG', description: 'Modify call history' },
  'android.permission.PROCESS_OUTGOING_CALLS': { level: 'CRITICAL', category: 'CALLS', description: 'Intercept and redirect outgoing calls' },
  'android.permission.READ_PHONE_STATE': { level: 'HIGH', category: 'PHONE', description: 'Read phone status (IMEI, carrier, active calls)' },
  'android.permission.CALL_PHONE': { level: 'HIGH', category: 'CALLS', description: 'Initiate phone calls without user interaction' },

  // System & Elevated Risk
  'android.permission.BIND_ACCESSIBILITY_SERVICE': { level: 'CRITICAL', category: 'SYSTEM', description: 'Bind to Accessibility service (can view/simulate all user interactions)' },
  'android.permission.BIND_DEVICE_ADMIN': { level: 'CRITICAL', category: 'SYSTEM', description: 'Bind to device administrator (can wipe device, lock screen, set policies)' },
  'android.permission.REQUEST_INSTALL_PACKAGES': { level: 'CRITICAL', category: 'SYSTEM', description: 'Request package installations (used to sideload malware)' },
  'android.permission.SYSTEM_ALERT_WINDOW': { level: 'HIGH', category: 'SYSTEM', description: 'Display draw-over overlays (often used for phishing fake logins)' },
  'android.permission.WRITE_SETTINGS': { level: 'HIGH', category: 'SYSTEM', description: 'Read or write system settings' },
  'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE': { level: 'HIGH', category: 'SYSTEM', description: 'Read and intercept notifications (including OTPs)' },
  'android.permission.RECEIVE_BOOT_COMPLETED': { level: 'MEDIUM', category: 'SYSTEM', description: 'Automatically start running on device bootup' },
  'android.permission.KILL_BACKGROUND_PROCESSES': { level: 'MEDIUM', category: 'SYSTEM', description: 'Kill other background applications' },

  // Network & Basic
  'android.permission.INTERNET': { level: 'LOW', category: 'NETWORK', description: 'Establish network connections to the internet' },
  'android.permission.ACCESS_NETWORK_STATE': { level: 'LOW', category: 'NETWORK', description: 'Verify network signal or connection state' },
  'android.permission.ACCESS_WIFI_STATE': { level: 'LOW', category: 'NETWORK', description: 'Verify WiFi configuration state' },
  'android.permission.VIBRATE': { level: 'LOW', category: 'HARDWARE', description: 'Trigger hardware vibration' },
  'android.permission.WAKE_LOCK': { level: 'LOW', category: 'SYSTEM', description: 'Keep the processor or screen from sleeping' },

  // Storage
  'android.permission.WRITE_EXTERNAL_STORAGE': { level: 'MEDIUM', category: 'STORAGE', description: 'Write or delete files on external storage' },
  'android.permission.READ_EXTERNAL_STORAGE': { level: 'MEDIUM', category: 'STORAGE', description: 'Read files on external storage' },
  'android.permission.MANAGE_EXTERNAL_STORAGE': { level: 'HIGH', category: 'STORAGE', description: 'Access all shared storage folders' },
};

const RISK_LEVEL_SCORE = { LOW: 1, MEDIUM: 3, HIGH: 7, CRITICAL: 15 };

export async function analyzeApkPermissions(permissions, appInfo, userId) {
  const scan = await prisma.scan.create({
    data: { userId, scanType: 'APK_PERMISSIONS', status: 'PROCESSING' },
  });

  await prisma.scanInput.create({
    data: { scanId: scan.id, rawInput: JSON.stringify(permissions), metadata: appInfo },
  });

  try {
    const analyzedPermissions = permissions.map((perm) => {
      const info = PERMISSION_DATABASE[perm] || {
        level: 'MEDIUM',
        category: 'UNKNOWN',
        description: `Unknown custom permission: ${perm}`,
      };
      return { name: perm, ...info, riskScore: RISK_LEVEL_SCORE[info.level] || 3 };
    });

    // Score calculation: Add up points for triggered permissions
    const criticalCount = analyzedPermissions.filter((p) => p.level === 'CRITICAL').length;
    const highCount = analyzedPermissions.filter((p) => p.level === 'HIGH').length;
    const mediumCount = analyzedPermissions.filter((p) => p.level === 'MEDIUM').length;

    const penaltyScore = Math.min(100, criticalCount * 25 + highCount * 12 + mediumCount * 4);
    const trustScore = Math.max(0, 100 - penaltyScore);
    const riskLevel = trustScore < 30 ? 'CRITICAL' : trustScore < 50 ? 'HIGH' : trustScore < 70 ? 'MODERATE' : 'LOW';

    const recommendations = generateApkRecommendations(analyzedPermissions, { trustScore });

    const aiPrompt = `Analyze these Android app permissions for security risk:\n${JSON.stringify(analyzedPermissions, null, 2)}\n\nApp Info: ${JSON.stringify(appInfo)}`;
    const rawAi = await callOpenRouter(
      `You are a mobile security analyst. Analyze Android permissions and explain the privacy/security risks in plain language. Respond with JSON: {"summary":"...","riskExplanation":"...","keyIndicators":[],"recommendations":[],"limitations":[],"confidence":"HIGH|MEDIUM|LOW"}`,
      aiPrompt
    );
    // Phase 7: Validate AI output against strict Zod schema
    const { success, data: validAi, error: zodError } = validateAiOutput(rawAi);
    if (!success) {
      logger.warn('APK AI output failed Zod validation, using fallback', { error: zodError });
    }
    const aiExplanation = success ? validAi : {
      summary: 'AI explanation unavailable. See permission breakdown for details.',
      riskExplanation: 'Deterministic permission analysis complete.',
      keyIndicators: [], recommendations: [], limitations: ['AI validation failed.'], confidence: 'LOW',
    };

    await prisma.scanResult.create({
      data: {
        scanId: scan.id,
        trustScore,
        riskLevel,
        confidence: 'HIGH',
        evidenceCoverage: 95,
        aiSummary: aiExplanation.summary,
        aiExplanation,
        keyIndicators: analyzedPermissions,
        rawApiResponses: { permissions: analyzedPermissions, appInfo },
      },
    });

    await prisma.scan.update({ where: { id: scan.id }, data: { status: 'COMPLETED', completedAt: new Date() } });

    return {
      scanId: scan.id,
      trustScore,
      riskLevel,
      confidence: 'HIGH',
      evidenceCoverage: 95,
      permissions: analyzedPermissions,
      aiExplanation,
      recommendations,
      appInfo,
      completedAt: new Date().toISOString(),
    };
  } catch (error) {
    logger.error('APK analysis failed', { scanId: scan.id, error: error.message });
    await prisma.scan.update({ where: { id: scan.id }, data: { status: 'FAILED' } });
    throw error;
  }
}
