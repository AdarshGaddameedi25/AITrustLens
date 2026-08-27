/**
 * SSE Manager — Phase 2: Real-time Scan Progress
 *
 * A singleton in-memory registry that maps scanId → active SSE response streams.
 * The scan worker pushes progress events into this registry, and the SSE endpoint
 * relays them to the browser in real-time over a single long-lived HTTP connection.
 *
 * Architecture:
 *   ScanWorker → pushSseEvent(scanId, event) → sseManager → res.write() → Browser
 *
 * Safety:
 * - Each connection auto-evicts after MAX_LIFETIME_MS (5 min) to prevent leaks.
 * - Duplicate registrations for the same scanId are safely overwritten.
 * - All pushes are no-ops if no client is listening (scanId not registered).
 */

import logger from './logger.js';

// Maximum time to keep an SSE connection open (5 minutes)
const MAX_LIFETIME_MS = 5 * 60 * 1000;

// Map: scanId (string) → { res: Response, timer: NodeJS.Timeout }
const registry = new Map();

/**
 * Registers an SSE client connection for the given scan.
 * Sets the required SSE headers and keeps the connection alive with a heartbeat.
 *
 * @param {string} scanId
 * @param {import('express').Response} res
 */
export function registerSseClient(scanId, res) {
  // Clean up any stale connection for this scanId first
  if (registry.has(scanId)) {
    closeSseClient(scanId);
  }

  // Set SSE headers
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no'); // Disable Nginx proxy buffering
  res.flushHeaders();

  // Send a comment line immediately to confirm the stream is open
  res.write(': connected\n\n');

  // Heartbeat every 20 seconds to prevent proxy/load-balancer timeouts
  const heartbeat = setInterval(() => {
    if (!res.writableEnded) {
      res.write(': heartbeat\n\n');
    }
  }, 20000);

  // Auto-evict after MAX_LIFETIME_MS
  const evictTimer = setTimeout(() => {
    logger.warn('SSE: connection timed out, closing', { scanId });
    pushSseEvent(scanId, 'timeout', { message: 'Scan timed out. Please try again.' });
    closeSseClient(scanId);
  }, MAX_LIFETIME_MS);

  registry.set(scanId, { res, heartbeat, evictTimer });

  logger.info('SSE: client registered', { scanId, totalClients: registry.size });

  // Clean up when the client disconnects (browser closed tab, etc.)
  res.on('close', () => {
    logger.info('SSE: client disconnected', { scanId });
    _cleanupTimers(scanId);
    registry.delete(scanId);
  });
}

/**
 * Pushes a named SSE event to the registered client for the given scanId.
 * Safe to call even if no client is registered (no-op).
 *
 * @param {string} scanId
 * @param {string} eventName - e.g. 'progress', 'complete', 'failed'
 * @param {object} data
 */
export function pushSseEvent(scanId, eventName, data) {
  const client = registry.get(scanId);
  if (!client || client.res.writableEnded) {
    // No client listening — safe no-op
    return;
  }

  try {
    const payload = JSON.stringify(data);
    client.res.write(`event: ${eventName}\n`);
    client.res.write(`data: ${payload}\n\n`);
  } catch (err) {
    logger.warn('SSE: failed to push event', { scanId, eventName, error: err.message });
    closeSseClient(scanId);
  }
}

/**
 * Closes and removes an SSE client connection.
 *
 * @param {string} scanId
 */
export function closeSseClient(scanId) {
  const client = registry.get(scanId);
  if (!client) return;

  _cleanupTimers(scanId);

  // We remove it from the registry immediately so no new events are pushed.
  registry.delete(scanId);

  // Delay closing the socket by 5 seconds.
  // This allows the final 'complete' or 'failed' event to flush through Nginx/Vite proxies
  // and gives the browser EventSource time to call .close() gracefully, avoiding 'onerror' race conditions.
  setTimeout(() => {
    if (!client.res.writableEnded) {
      client.res.end();
    }
  }, 5000);

  logger.info('SSE: client marked for closing', { scanId, remainingClients: registry.size });
}

/**
 * Returns the number of active SSE connections (for monitoring/health checks).
 */
export function getSseClientCount() {
  return registry.size;
}

function _cleanupTimers(scanId) {
  const client = registry.get(scanId);
  if (!client) return;
  clearInterval(client.heartbeat);
  clearTimeout(client.evictTimer);
}
