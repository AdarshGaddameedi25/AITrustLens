/**
 * Risk Assessment Engine — Mathematical Formalization (Phase 0)
 *
 * Core Principle: Deterministic, explainable risk scoring engine.
 * AI is NEVER used to compute or influence the numeric Trust Score.
 *
 * --- FORMAL MATHEMATICAL DEFINITION ---
 * 1. Penalty Range: Each rule outputs a risk penalty strictly between [0, 100].
 *    - 0 = Safe/Benign
 *    - 100 = Maximum Risk/Malicious
 * 2. Weight Range: Each rule has a predefined weight between (0.0, 1.0].
 *    - The sum of all theoretical rule weights in a ruleset is 1.0.
 * 3. Normalization Method:
 *    - Since APIs can fail, we cannot guarantee all evidence is collected.
 *    - Raw Risk = Sum(Penalty_i * Weight_i) / Sum(Weight_i_available)
 *    - This bounds the Raw Risk strictly to [0, 100] regardless of missing data.
 * 4. Trust Score:
 *    - TrustScore = 100 - Raw Risk
 *    - TrustScore is strictly bounded to [0, 100]. (100 = Safe, 0 = Malicious)
 * 5. Duplicate Evidence:
 *    - Handled implicitly by the EvidenceCollection model. A rule operates on a 
 *      consolidated indicator (e.g., VT_MALICIOUS_COUNT). If multiple identical
 *      indicators exist, the collection normalizes them before the rule engine sees them.
 * 6. Conflicting Evidence:
 *    - Detected mathematically: if Rule A (weight >= 0.1) outputs >= 80 penalty,
 *      and Rule B (weight >= 0.1) outputs <= 20 penalty, a formal Conflict is registered.
 *      Conflicts do NOT alter the Trust Score (it remains a weighted average), 
 *      but they drop the Confidence Level and are surfaced to the user.
 */

import { RISK_RULES, EMAIL_RISK_RULES, SCAM_RISK_RULES, PRIVACY_RISK_RULES, getRiskLevel, RISK_ENGINE_VERSION } from './riskRules.js';
import logger from '../utils/logger.js';

const ENGINE_VERSION = 'ENGINE_V1';

export function calculateRiskAssessment(evidenceCollection, scanType = 'URL') {
  const rules = getRulesForScanType(scanType);

  const indicators = [];
  let totalWeight = 0;
  let weightedRiskSum = 0;
  let availableIndicators = 0;
  let unavailableIndicators = 0;

  for (const rule of Object.values(rules)) {
    let riskValue = null;
    let error = null;

    try {
      riskValue = rule.calculate(evidenceCollection);
    } catch (e) {
      error = e.message;
      logger.warn(`Risk rule calculation failed: ${rule.id}`, { error: e.message });
    }

    // Enforce Penalty Range [0, 100]
    if (riskValue !== null && !error) {
      riskValue = Math.max(0, Math.min(100, riskValue));
    }

    const isAvailable = riskValue !== null && !error;

    if (isAvailable) {
      availableIndicators++;
      totalWeight += rule.weight;
      weightedRiskSum += riskValue * rule.weight;
    } else {
      unavailableIndicators++;
    }

    indicators.push({
      id: rule.id,
      name: rule.name,
      source: rule.source || 'ANALYSIS',
      weight: rule.weight,
      riskValue: riskValue ?? null,
      isAvailable,
      contribution: isAvailable ? riskValue * rule.weight : null,
      error: error || null,
    });
  }

  // Conflict Detection: High penalty vs Low penalty among high-weight rules
  const highRiskFlags = indicators.filter(i => i.isAvailable && i.weight >= 0.1 && i.riskValue >= 80);
  const lowRiskFlags = indicators.filter(i => i.isAvailable && i.weight >= 0.1 && i.riskValue <= 20);
  const conflicts = evidenceCollection.conflicts || [];
  
  if (highRiskFlags.length > 0 && lowRiskFlags.length > 0) {
    conflicts.push({
      type: 'MATHEMATICAL_CONFLICT',
      description: `Conflict detected: ${highRiskFlags[0].name} flagged high risk, while ${lowRiskFlags[0].name} flagged low risk.`,
      entities: [highRiskFlags[0].source, lowRiskFlags[0].source]
    });
  }

  // Normalization: rawRiskScore = Sum(weighted penalties) / Sum(available weights)
  // Fallback to 50 (moderate risk) if absolutely NO evidence is available.
  const rawRiskScore = totalWeight > 0 ? weightedRiskSum / totalWeight : 50;

  // Trust Score = 100 - rawRiskScore
  const trustScore = Math.round(100 - rawRiskScore);

  // Evidence Coverage = (Sum of available weights / Total possible weights) * 100
  // Instead of passing a blind number, calculate strictly mathematically.
  const totalTheoreticalWeight = Object.values(rules).reduce((acc, r) => acc + r.weight, 0);
  const evidenceCoverage = totalTheoreticalWeight > 0 
    ? Math.round((totalWeight / totalTheoreticalWeight) * 100) 
    : 0;

  const confidence = calculateConfidence(evidenceCoverage, availableIndicators, conflicts.length > 0);
  const riskLevel = getRiskLevel(trustScore);

  return {
    engineVersion: ENGINE_VERSION,
    ruleSetVersion: RISK_ENGINE_VERSION,
    trustScore,
    riskLevel,
    confidence,
    evidenceCoverage,
    rawRiskScore: Math.round(rawRiskScore),
    indicators,
    conflicts,
    availableIndicators,
    unavailableIndicators,
    calculationMeta: {
      totalWeight,
      weightedRiskSum,
      formula: "TrustScore = 100 - (Sum(Penalty * Weight) / Sum(AvailableWeights))",
    },
    calculatedAt: new Date().toISOString(),
  };
}

function getRulesForScanType(scanType) {
  switch (scanType) {
    case 'EMAIL': return EMAIL_RISK_RULES;
    case 'SCAM_MESSAGE': return SCAM_RISK_RULES;
    case 'PRIVACY_POLICY': return PRIVACY_RISK_RULES;
    case 'URL':
    case 'QR_CODE':
    default:
      return RISK_RULES;
  }
}

function calculateConfidence(coveragePercent, availableCount, hasConflicts) {
  if (availableCount < 2) return 'INSUFFICIENT';
  if (hasConflicts) return 'LOW'; // Conflicts inherently drop confidence
  if (coveragePercent >= 75) return 'HIGH';
  if (coveragePercent >= 50) return 'MEDIUM';
  if (coveragePercent >= 25) return 'LOW';
  return 'INSUFFICIENT';
}

export function generateRiskFactorBreakdown(indicators) {
  return indicators
    .filter((i) => i.isAvailable && i.riskValue !== null)
    .sort((a, b) => (b.contribution ?? 0) - (a.contribution ?? 0))
    .map((i) => ({
      name: i.name,
      source: i.source,
      riskScore: i.riskValue,
      contribution: Math.round((i.contribution ?? 0) * 100) / 100,
      severity: getRiskLevel(100 - (i.riskValue ?? 0)),
    }));
}
