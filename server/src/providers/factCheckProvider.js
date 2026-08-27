/**
 * Google Fact Check Tools Provider
 * Retrieves existing fact checks for a given claim.
 *
 * IMPORTANT: The platform never claims a statement is true or false
 * solely because an AI model says so. Fact checks must come from
 * verified publishers via this API.
 */

import axios from 'axios';
import { env } from '../config/env.js';
import logger from '../utils/logger.js';

const FACTCHECK_BASE_URL = 'https://factchecktools.googleapis.com/v1alpha1/claims:search';
const TIMEOUT_MS = 15000;

/**
 * @typedef {Object} FactCheckResult
 * @property {string} status - 'AVAILABLE' | 'UNAVAILABLE' | 'ERROR' | 'NO_RESULTS'
 * @property {Array} claims
 * @property {string|null} error
 */

/**
 * Searches for fact checks related to a claim.
 * @param {string} query
 * @param {string} [languageCode='en']
 * @returns {Promise<FactCheckResult>}
 */
export async function searchFactChecks(query, languageCode = 'en') {
  if (!env.apis.factCheck) {
    logger.warn('Google Fact Check API key not configured');
    return { status: 'UNAVAILABLE', claims: [], error: 'API key not configured' };
  }

  try {
    const response = await axios.get(FACTCHECK_BASE_URL, {
      params: {
        key: env.apis.factCheck,
        query: query.substring(0, 500), // API limit
        languageCode,
        pageSize: 10,
      },
      timeout: TIMEOUT_MS,
    });

    const rawClaims = response.data?.claims || [];

    if (rawClaims.length === 0) {
      return {
        status: 'NO_RESULTS',
        claims: [],
        note: 'No existing fact checks found for this claim.',
        error: null,
      };
    }

    const claims = rawClaims.map((claim) => ({
      text: claim.text,
      claimant: claim.claimant || null,
      claimDate: claim.claimDate || null,
      reviews: (claim.claimReview || []).map((review) => ({
        publisher: review.publisher?.name || 'Unknown',
        publisherSite: review.publisher?.site || null,
        url: review.url || null,
        title: review.title || null,
        reviewDate: review.reviewDate || null,
        textualRating: review.textualRating || null,
        languageCode: review.languageCode || null,
      })),
    }));

    return {
      status: 'AVAILABLE',
      claims,
      total: claims.length,
      error: null,
    };
  } catch (error) {
    if (error.response?.status === 403) {
      logger.error('Google Fact Check API quota exceeded or invalid key');
      return { status: 'ERROR', claims: [], error: 'API authentication failed or quota exceeded' };
    }
    logger.error('Google Fact Check error', { error: error.message });
    return { status: 'ERROR', claims: [], error: error.message };
  }
}
