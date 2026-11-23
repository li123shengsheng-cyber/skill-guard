/**
 * skill-guard — public API for tests and embedders.
 */

'use strict';

const { scanSkill, discoverSkills } = require('./scanner');
const { scoreFindings, verdictFor, VERDICT_LABEL } = require('./score');
const { formatReport, jsonReport } = require('./report');
const { addSkill, defaultSkillsDir } = require('./install');
const { CHECKLIST, formatChecklist } = require('./checklist');
const { RULES } = require('./rules');

module.exports = {
  scanSkill,
  discoverSkills,
  scoreFindings,
  verdictFor,
  VERDICT_LABEL,
  formatReport,
  jsonReport,
  addSkill,
  defaultSkillsDir,
  CHECKLIST,
  formatChecklist,
  RULES,
};
