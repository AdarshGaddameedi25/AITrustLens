/**
 * Scan Stream — Phase 2: Real-time SSE Utility
 *
 * A clean wrapper around the native browser EventSource API.
 * Opens a single long-lived SSE connection to /api/scans/:id/stream,
 * and calls the appropriate callback on each named event.
 *
 * Usage:
 *   const close = openScanStream(scanId, token, {
 *     onProgress: ({ stage, progress, message }) => ...,
 *     onComplete: ({ result }) => ...,
 *     onError: (errorMessage) => ...,
 *   });
 *   // Call close() to manually terminate the stream
 */

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000/api';

/**
 * Opens an SSE stream for the given scan and wires up event handlers.
 *
 * @param {string} scanId
 * @param {string} token - JWT access token for the Authorization header
 * @param {object} handlers
 * @param {function} handlers.onProgress - Called with { stage, progress, message }
 * @param {function} handlers.onComplete - Called with { result }
 * @param {function} handlers.onError   - Called with an error message string
 * @returns {function} close - Call this to close the stream manually
 */
export function openScanStream(scanId, token, { onProgress, onComplete, onError }) {
  // NOTE: EventSource doesn't support custom headers in all browsers.
  // We pass the token as a query param for SSE routes only.
  // The server must validate this token on the SSE route.
  const url = `${API_URL}/scans/${scanId}/stream?token=${encodeURIComponent(token)}`;
  const source = new EventSource(url);
  let isFinished = false;

  source.addEventListener('progress', (e) => {
    if (isFinished) return;
    try {
      const data = JSON.parse(e.data);
      onProgress?.(data);
    } catch {
      // Ignore malformed events
    }
  });

  source.addEventListener('complete', (e) => {
    isFinished = true;
    try {
      const data = JSON.parse(e.data);
      onComplete?.(data);
    } catch {
      onError?.('Received malformed complete event.');
    } finally {
      source.close();
    }
  });

  source.addEventListener('failed', (e) => {
    isFinished = true;
    try {
      const data = JSON.parse(e.data);
      onError?.(data.error || 'Scan failed. Please try again.');
    } catch {
      onError?.('Scan failed.');
    } finally {
      source.close();
    }
  });

  source.addEventListener('timeout', (e) => {
    isFinished = true;
    try {
      const data = JSON.parse(e.data);
      onError?.(data.message || 'Scan timed out.');
    } catch {
      onError?.('Scan timed out.');
    } finally {
      source.close();
    }
  });

  source.onerror = () => {
    if (isFinished) return;
    // EventSource auto-reconnects on error — we want to prevent that for scan streams
    source.close();
    onError?.('Connection to scan stream lost. Please check your network and try again.');
  };

  return () => {
    isFinished = true;
    source.close();
  };
}
