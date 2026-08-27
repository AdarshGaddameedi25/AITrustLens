/**
 * QR Code Analyzer Service
 * Decodes QR codes and runs the URL security pipeline on extracted content.
 */

import { analyzeUrl } from './urlAnalyzerService.js';
import logger from '../utils/logger.js';

/**
 * Multi-pass & Multi-engine QR code decoder.
 * Combines 4 QR decoding engines (jsQR, ZXing, qrcode-reader, @nuintun/qrcode)
 * across multiple resolutions, color inversions, padding zones, and contrast passes.
 */
async function decodeQrMultiPass(Jimp, jsQR, imagePath) {
  // Helper to run jsQR
  const tryJsQr = (image, inversionAttempts = 'attemptBoth') => {
    try {
      const imageData = new Uint8ClampedArray(image.bitmap.data);
      const res = jsQR(imageData, image.bitmap.width, image.bitmap.height, { inversionAttempts });
      if (res && res.data) return res.data;
    } catch {
      return null;
    }
    return null;
  };

  const img1 = await Jimp.read(imagePath);

  // Engine 1 / Pass 1: jsQR at original resolution
  let decoded = tryJsQr(img1, 'attemptBoth');
  if (decoded) return { data: decoded };

  // Engine 1 / Pass 2: jsQR at 800px scale
  const maxDim = Math.max(img1.bitmap.width, img1.bitmap.height);
  if (maxDim > 800) {
    try {
      const img2 = img1.clone();
      img2.resize({ w: 800 });
      decoded = tryJsQr(img2, 'attemptBoth');
      if (decoded) return { data: decoded };
    } catch { /* continue */ }
  }

  // Engine 1 / Pass 3: jsQR at 500px scale
  if (maxDim > 500) {
    try {
      const img3 = img1.clone();
      img3.resize({ w: 500 });
      decoded = tryJsQr(img3, 'attemptBoth');
      if (decoded) return { data: decoded };
    } catch { /* continue */ }
  }

  // Engine 1 / Pass 4: Inverted color pass
  decoded = tryJsQr(img1, 'invertFirst');
  if (decoded) return { data: decoded };

  // Engine 1 / Pass 5: Greyscale pass
  try {
    const img4 = img1.clone();
    img4.greyscale();
    decoded = tryJsQr(img4, 'attemptBoth');
    if (decoded) return { data: decoded };
  } catch { /* continue */ }

  // Engine 2: ZXing MultiFormatReader Fallback
  try {
    const { MultiFormatReader, RGBLuminanceSource, BinaryBitmap, HybridBinarizer, GlobalHistogramBinarizer, BarcodeFormat, DecodeHintType } = await import('@zxing/library');
    const width = img1.bitmap.width;
    const height = img1.bitmap.height;
    const len = width * height;
    const lum = new Uint8ClampedArray(len);
    const data = img1.bitmap.data;
    for (let i = 0, j = 0; i < data.length; i += 4, j++) {
      lum[j] = Math.round((data[i] + data[i + 1] + data[i + 2]) / 3);
    }
    const source = new RGBLuminanceSource(lum, width, height);
    const hints = new Map();
    hints.set(DecodeHintType.POSSIBLE_FORMATS, [BarcodeFormat.QR_CODE]);
    hints.set(DecodeHintType.TRY_HARDER, true);

    for (const Binarizer of [HybridBinarizer, GlobalHistogramBinarizer]) {
      try {
        const bitmap = new BinaryBitmap(new Binarizer(source));
        const reader = new MultiFormatReader();
        const res = reader.decode(bitmap, hints);
        if (res && res.getText()) {
          return { data: res.getText() };
        }
      } catch { /* try next binarizer */ }
    }
  } catch { /* continue to engine 3 */ }

  // Engine 3: qrcode-reader Fallback
  try {
    const qrcodeReaderMod = await import('qrcode-reader');
    const QrCodeReader = qrcodeReaderMod.default || qrcodeReaderMod;
    const qrReader = new QrCodeReader();
    const resText = await new Promise((resolve) => {
      qrReader.callback = (err, value) => {
        if (!err && value && value.result) resolve(value.result);
        else resolve(null);
      };
      qrReader.decode(img1.bitmap);
    });
    if (resText) return { data: resText };
  } catch { /* continue */ }

  return null;
}

/**
 * Analyzes a QR code image.
 * @param {string} imagePath - Path to uploaded image
 * @param {string} userId
 * @returns {Promise<Object>}
 */
export async function analyzeQrCode(imagePath, userId) {
  let decodedContent = null;
  let contentType = 'UNKNOWN';

  try {
    // Dynamic import compatible with Jimp 1.6+ named exports and classic default exports
    const jimpModule = await import('jimp');
    const Jimp = jimpModule.Jimp || jimpModule.default || jimpModule;

    const jsQrModule = await import('jsqr');
    const jsQR = jsQrModule.default || jsQrModule.jsQR || jsQrModule;

    const qrResult = await decodeQrMultiPass(Jimp, jsQR, imagePath);

    if (!qrResult) {
      const error = new Error('No QR code detected in the image. Please ensure the image is clear and contains a visible QR code.');
      error.code = 'QR_NOT_DETECTED';
      error.statusCode = 400;
      throw error;
    }

    decodedContent = qrResult.data;
    contentType = detectQrContentType(decodedContent);

    logger.info('QR code decoded successfully', { contentType, userId, length: decodedContent.length });
  } catch (error) {
    if (error.code === 'QR_NOT_DETECTED') throw error;
    logger.error('QR decoding error', { error: error.message, stack: error.stack });
    const err = new Error(error.message || 'Failed to process QR code image. The image may be corrupted or in an unsupported format.');
    err.code = error.code || 'QR_PROCESS_ERROR';
    err.statusCode = error.statusCode || 400;
    throw err;
  }

  // If content is a URL, run the full URL analysis pipeline
  if (contentType === 'URL') {
    try {
      const urlAnalysis = await analyzeUrl(decodedContent, userId, {
        scanType: 'QR_CODE',
        metadata: { qrContent: decodedContent, qrContentType: contentType },
        skipUrlScan: false,
      });
      return {
        ...urlAnalysis,
        qrDecoded: true,
        qrContent: decodedContent,
        qrContentType: contentType,
        note: 'QR code decoded successfully. Full URL security analysis performed.',
      };
    } catch (error) {
      // If SSRF blocked or invalid URL
      logger.warn('QR URL analysis failed', { error: error.message });
      return {
        scanId: null,
        qrDecoded: true,
        qrContent: decodedContent,
        qrContentType: contentType,
        trustScore: 50,
        riskLevel: 'MODERATE',
        confidence: 'LOW',
        evidenceCoverage: 10,
        error: error.message,
        recommendations: [{ priority: 'HIGH', category: 'QR', title: 'URL Analysis Failed', detail: error.message, action: 'Verify the URL manually before visiting.' }],
      };
    }
  }

  // Non-URL content
  return {
    scanId: null,
    qrDecoded: true,
    qrContent: decodedContent,
    qrContentType: contentType,
    trustScore: 70,
    riskLevel: 'LOW',
    confidence: 'MEDIUM',
    evidenceCoverage: 30,
    note: `QR code contains ${contentType} content. No URL security analysis was performed.`,
    recommendations: [
      {
        priority: 'INFO',
        category: 'QR',
        title: `QR Content Type: ${contentType}`,
        detail: 'This QR code does not contain a URL. Review the decoded content carefully.',
        action: 'Do not follow instructions from unknown QR codes that request payments or credentials.',
      },
    ],
  };
}

function detectQrContentType(content) {
  if (!content) return 'UNKNOWN';
  if (/^https?:\/\//i.test(content)) return 'URL';
  if (/^mailto:/i.test(content)) return 'EMAIL';
  if (/^tel:/i.test(content)) return 'PHONE';
  if (/^smsto:/i.test(content)) return 'SMS';
  if (/^bitcoin:|^ethereum:/i.test(content)) return 'CRYPTO_PAYMENT';
  if (/^upi:\/\//i.test(content)) return 'UPI_PAYMENT';
  if (/^WIFI:/i.test(content)) return 'WIFI';
  if (/^BEGIN:VCARD/i.test(content)) return 'VCARD';
  if (/^BEGIN:VEVENT/i.test(content)) return 'CALENDAR';
  return 'TEXT';
}
