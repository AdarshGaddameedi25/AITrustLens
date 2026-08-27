/**
 * TLS Inspector Provider
 * Inspects TLS/SSL certificate details for a given hostname.
 * Uses Node.js built-in tls module.
 *
 * NOTE: A valid TLS certificate does NOT mean a website is legitimate.
 * This is a security indicator only.
 */

import tls from 'tls';
import logger from '../utils/logger.js';

const TIMEOUT_MS = 10000;

/**
 * @typedef {Object} TLSResult
 * @property {string} status - 'AVAILABLE' | 'UNAVAILABLE' | 'ERROR'
 * @property {boolean|null} valid
 * @property {boolean|null} expired
 * @property {string|null} subject
 * @property {string|null} issuer
 * @property {string|null} validFrom
 * @property {string|null} validTo
 * @property {number|null} daysUntilExpiry
 * @property {boolean|null} selfSigned
 * @property {string|null} protocol
 */

/**
 * Inspects TLS certificate for a hostname.
 * @param {string} hostname
 * @param {number} [port=443]
 * @returns {Promise<TLSResult>}
 */
export async function inspectTlsCertificate(hostname, port = 443) {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      socket.destroy();
      resolve({ status: 'UNAVAILABLE', error: 'TLS inspection timed out' });
    }, TIMEOUT_MS);

    let socket;
    try {
      socket = tls.connect(
        {
          host: hostname,
          port,
          servername: hostname,
          rejectUnauthorized: false, // We inspect regardless, then report validity
          timeout: TIMEOUT_MS,
        },
        () => {
          clearTimeout(timeout);
          try {
            const cert = socket.getPeerCertificate(true);
            const authorized = socket.authorized;
            const authorizationError = socket.authorizationError;

            if (!cert || Object.keys(cert).length === 0) {
              socket.destroy();
              return resolve({ status: 'UNAVAILABLE', error: 'No certificate returned' });
            }

            const validFrom = cert.valid_from ? new Date(cert.valid_from) : null;
            const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
            const now = new Date();

            const expired = validTo ? validTo < now : null;
            const daysUntilExpiry = validTo
              ? Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24))
              : null;

            // Self-signed if issuer === subject
            const subjectCN = cert.subject?.CN || '';
            const issuerCN = cert.issuer?.CN || '';
            const selfSigned = subjectCN === issuerCN;

            socket.destroy();
            resolve({
              status: 'AVAILABLE',
              valid: authorized && !expired,
              authorized,
              authorizationError: authorizationError || null,
              expired,
              subject: cert.subject
                ? `CN=${cert.subject.CN || ''}, O=${cert.subject.O || ''}`
                : null,
              issuer: cert.issuer
                ? `CN=${cert.issuer.CN || ''}, O=${cert.issuer.O || ''}`
                : null,
              validFrom: validFrom?.toISOString() || null,
              validTo: validTo?.toISOString() || null,
              daysUntilExpiry,
              selfSigned,
              protocol: socket.getProtocol?.() || null,
              fingerprint: cert.fingerprint || null,
              error: null,
            });
          } catch (innerError) {
            socket.destroy();
            resolve({ status: 'ERROR', error: innerError.message });
          }
        }
      );

      socket.on('error', (error) => {
        clearTimeout(timeout);
        logger.debug('TLS inspection error', { hostname, error: error.message });
        resolve({ status: 'UNAVAILABLE', error: error.message });
      });
    } catch (error) {
      clearTimeout(timeout);
      logger.debug('TLS connect error', { hostname, error: error.message });
      resolve({ status: 'ERROR', error: error.message });
    }
  });
}
