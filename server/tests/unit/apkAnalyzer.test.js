/**
 * APK Manifest Parser & Security Analyzer Unit Tests
 */

import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import AdmZip from 'adm-zip';
import { parseApkManifest, parseManifestBuffer } from '../../src/utils/apkParser.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const FIXTURES_DIR = path.resolve(__dirname, '../fixtures/apk');

describe('APK Manifest Extraction & Parsing', () => {
  test('Parses Safe App Manifest Fixture with accurate metadata and low risk', () => {
    const xmlContent = fs.readFileSync(path.join(FIXTURES_DIR, 'safe_app_manifest.xml'));
    const result = parseManifestBuffer(xmlContent);

    expect(result.packageName).toBe('com.example.calculator');
    expect(result.versionName).toBe('1.0.0');
    expect(result.permissions).toContain('android.permission.INTERNET');
    expect(result.permissions).toContain('android.permission.ACCESS_NETWORK_STATE');
    expect(result.permissions).toContain('android.permission.VIBRATE');
    expect(result.permissions.length).toBe(3);
    expect(result.dangerousFlags).toEqual([]);
  });

  test('Parses Suspicious App Manifest Fixture with excessive dangerous permissions', () => {
    const xmlContent = fs.readFileSync(path.join(FIXTURES_DIR, 'suspicious_app_manifest.xml'));
    const result = parseManifestBuffer(xmlContent);

    expect(result.packageName).toBe('com.suspicious.flashlight');
    expect(result.versionName).toBe('2.1.0');
    expect(result.permissions).toContain('android.permission.READ_SMS');
    expect(result.permissions).toContain('android.permission.READ_CONTACTS');
    expect(result.permissions).toContain('android.permission.CAMERA');
    expect(result.permissions).toContain('android.permission.RECORD_AUDIO');
    expect(result.permissions).toContain('android.permission.ACCESS_FINE_LOCATION');
    expect(result.activities).toContain('.FlashlightActivity');
    expect(result.services).toContain('.BackgroundSyncService');
  });

  test('Parses Critical Banking Trojan Manifest Fixture with elevated service bindings', () => {
    const xmlContent = fs.readFileSync(path.join(FIXTURES_DIR, 'critical_malware_manifest.xml'));
    const result = parseManifestBuffer(xmlContent);

    expect(result.packageName).toBe('com.trojan.bankstealer');
    expect(result.versionName).toBe('3.0.0');
    expect(result.permissions).toContain('android.permission.BIND_ACCESSIBILITY_SERVICE');
    expect(result.permissions).toContain('android.permission.BIND_DEVICE_ADMIN');
    expect(result.permissions).toContain('android.permission.REQUEST_INSTALL_PACKAGES');
    expect(result.permissions).toContain('android.permission.SYSTEM_ALERT_WINDOW');
    expect(result.permissions).toContain('android.permission.READ_SMS');
    expect(result.permissions).toContain('android.permission.RECEIVE_SMS');
    expect(result.permissions).toContain('android.permission.SEND_SMS');

    expect(result.dangerousFlags).toContain('ACCESSIBILITY_SERVICE_BINDING');
    expect(result.dangerousFlags).toContain('DEVICE_ADMIN_BINDING');
    expect(result.dangerousFlags).toContain('PACKAGE_INSTALL_REQUESTER');
  });

  test('Extracts AndroidManifest.xml from a binary .apk zip archive', async () => {
    // Construct an in-memory realistic .apk archive containing AndroidManifest.xml
    const zip = new AdmZip();
    const manifestData = fs.readFileSync(path.join(FIXTURES_DIR, 'safe_app_manifest.xml'));
    zip.addFile('AndroidManifest.xml', manifestData);
    zip.addFile('classes.dex', Buffer.from('dex\n035\0testdexbytes'));
    zip.addFile('resources.arsc', Buffer.from('dummy resource table'));

    const apkBuffer = zip.toBuffer();
    const result = await parseApkManifest(apkBuffer);

    expect(result.packageName).toBe('com.example.calculator');
    expect(result.permissions).toContain('android.permission.INTERNET');
  });

  test('Throws MANIFEST_NOT_FOUND when APK archive lacks AndroidManifest.xml', async () => {
    const zip = new AdmZip();
    zip.addFile('classes.dex', Buffer.from('dex\n035\0test'));
    const apkBuffer = zip.toBuffer();

    await expect(parseApkManifest(apkBuffer)).rejects.toThrow('AndroidManifest.xml not found inside APK package.');
  });

  test('Throws INVALID_APK_ARCHIVE when file is not a valid zip archive', async () => {
    const invalidBuffer = Buffer.from('This is not a zip or apk file.');

    await expect(parseApkManifest(invalidBuffer)).rejects.toThrow('Invalid APK file archive');
  });
});
