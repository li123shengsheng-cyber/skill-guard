/**
 * Scoring: safety score (0-100, higher is safer) and verdicts.
 * Deliberately the inverse of SkillSpector's risk score: this tool
 * answers "how safe is it to install?" with a safety number.
 */

'use strict';

const WEIGHTS = { critical: 60, high: 30, medium: 10, low: 5 };

/** verdict: 'safe' | 'caution' | 'block' */
function verdictFor(score) {
  if (score >= 80) return 'safe';
  if (score >= 50) return 'caution';
  return 'block';
}

const VERDICT_LABEL = {
  safe: { en: 'SAFE', zh: '能装' },
  caution: { en: 'CAUTION', zh: '谨慎' },
  block: { en: 'DO NOT INSTALL', zh: '别装' },
};

function scoreFindings(findings) {
  let score = 100;
  for (const f of findings) {
    score -= WEIGHTS[f.severity] || 0;
  }
  return Math.max(0, Math.min(100, score));
}

module.exports = { WEIGHTS, verdictFor, VERDICT_LABEL, scoreFindings };
