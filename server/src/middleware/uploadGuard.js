import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { v4 as uuidv4 } from 'uuid';
import { env } from '../config/env.js';
import { errorResponse } from '../utils/responseFormatter.js';

// Allowed MIME types per category
const ALLOWED_IMAGE_TYPES = new Set(['image/jpeg', 'image/png', 'image/gif', 'image/webp']);
const ALLOWED_DOCUMENT_TYPES = new Set(['text/plain', 'application/pdf', 'text/html']);
const ALLOWED_APK_TYPES = new Set(['application/vnd.android.package-archive', 'application/octet-stream']);
const ALLOWED_EMAIL_TYPES = new Set(['text/plain', 'message/rfc822']);

// Allowed extensions
const ALLOWED_IMAGE_EXTENSIONS = new Set(['.jpg', '.jpeg', '.png', '.gif', '.webp']);
const ALLOWED_DOCUMENT_EXTENSIONS = new Set(['.txt', '.pdf', '.html']);
const ALLOWED_APK_EXTENSIONS = new Set(['.apk']);
const ALLOWED_EMAIL_EXTENSIONS = new Set(['.txt', '.eml']);

const MAX_SIZE_BYTES = env.upload.maxFileSizeMb * 1024 * 1024;

const getUploadDir = () => {
  const dir = path.resolve(process.cwd(), env.upload.tempDir);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  return dir;
};

/**
 * Creates multer storage with sanitized random filenames.
 */
function createStorage() {
  return multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, getUploadDir());
    },
    filename: (req, file, cb) => {
      // Random UUID filename — never use original filename
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, `${uuidv4()}${ext}`);
    },
  });
}

/**
 * Creates a multer upload middleware for a specific file category.
 */
function createUploader(allowedMimes, allowedExts, fieldName = 'file') {
  return multer({
    storage: createStorage(),
    limits: { fileSize: MAX_SIZE_BYTES },
    fileFilter: (req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      const mime = file.mimetype;

      if (!allowedMimes.has(mime) && !allowedExts.has(ext)) {
        const error = new Error(`File type not allowed: ${mime}`);
        error.code = 'INVALID_FILE_TYPE';
        error.statusCode = 400;
        return cb(error, false);
      }
      cb(null, true);
    },
  }).single(fieldName);
}

// Specific upload handlers
export const uploadImage = createUploader(ALLOWED_IMAGE_TYPES, ALLOWED_IMAGE_EXTENSIONS);
export const uploadDocument = createUploader(ALLOWED_DOCUMENT_TYPES, ALLOWED_DOCUMENT_EXTENSIONS);
export const uploadApk = createUploader(ALLOWED_APK_TYPES, ALLOWED_APK_EXTENSIONS);
export const uploadEmail = createUploader(ALLOWED_EMAIL_TYPES, ALLOWED_EMAIL_EXTENSIONS);

/**
 * Multer error handler middleware.
 */
export function handleUploadError(err, req, res, next) {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json(
        errorResponse('FILE_TOO_LARGE', `File exceeds the maximum size of ${env.upload.maxFileSizeMb}MB.`)
      );
    }
    return res.status(400).json(errorResponse('UPLOAD_ERROR', err.message));
  }
  if (err?.code === 'INVALID_FILE_TYPE') {
    return res.status(400).json(errorResponse('INVALID_FILE_TYPE', err.message));
  }
  next(err);
}
