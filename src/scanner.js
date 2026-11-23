/**
 * Scanner: walks a skill directory, applies the rules, and scores it.
 * Zero dependencies — only Node built-ins.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { RULES, hygieneChecks } = require('./rules');
const { scoreFindings, verdictFor } = require('./score');

const SCAN_EXTS = new Set(['.md', '.py', '.js', '.ts', '.sh', '.json', '.yaml', '.yml', '.txt']);
const SKIP_DIRS = new Set(['.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist', 'build', '.idea', '.vscode']);
const MAX_FILE_BYTES = 1 * 1024 * 1024; // 1 MiB per file (like SkillSpector's analysis cap)
const MAX_TOTAL_BYTES = 100 * 1024 * 1024; // 100 MiB per skill
const MAX_FILES = 500;

function isTextFile(rel) {
  return SCAN_EXTS.has(path.extname(rel).toLowerCase());
}

function frontmatterOf(content) {
  if (!content.startsWith('---')) return '';
  const end = content.indexOf('\n---', 3);
  if (end === -1) return '';
  return content.slice(3, end);
}

/** Collect scannable files under dir, relative paths. */
function collectFiles(dir, base = dir, depth = 0, out = []) {
  if (depth > 4 || out.length >= MAX_FILES) return out;
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    if (out.length >= MAX_FILES) break;
    const full = path.join(dir, entry.name);
    const rel = path.relative(base, full);
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name) && !entry.name.startsWith('.git')) {
        collectFiles(full, base, depth + 1, out);
      }
    } else if (entry.isFile() && isTextFile(rel)) {
      out.push({ full, rel });
    }
  }
  return out;
}

/**
 * Scan one skill directory.
 * Returns { name, path, filesScanned, skipped, findings, info, score, verdict, topReasons }
 */
function scanSkill(dirPath) {
  const absDir = path.resolve(dirPath);
  const name = path.basename(absDir);
  const collected = collectFiles(absDir);

  const files = [];
  const findings = [];
  let totalBytes = 0;
  const skipped = [];

  for (const { full, rel } of collected) {
    let stat;
    try {
      stat = fs.statSync(full);
    } catch {
      continue;
    }
    totalBytes += stat.size;
    if (totalBytes > MAX_TOTAL_BYTES) {
      skipped.push({ rel, reason: 'total size cap (100 MiB) reached' });
      break;
    }
    if (stat.size > MAX_FILE_BYTES) {
      skipped.push({ rel, reason: 'file over 1 MiB, skipped' });
      continue;
    }
    let content;
    try {
      content = fs.readFileSync(full, 'utf8');
    } catch {
      skipped.push({ rel, reason: 'unreadable' });
      continue;
    }
    const isSkillMd = path.basename(rel).toLowerCase() === 'skill.md';
    const file = {
      rel,
      ext: path.extname(rel).toLowerCase(),
      content,
      isExecutable: (stat.mode & 0o111) !== 0,
      isSkillMd,
      frontmatter: isSkillMd ? frontmatterOf(content) : '',
    };
    files.push(file);

    const kind =
      file.ext === '.json' || file.ext === '.yaml' || file.ext === '.yml'
        ? 'config'
        : file.ext === '.md'
          ? 'docs'
          : 'scripts';

    for (const rule of RULES) {
      if (rule.appliesTo !== 'all' && rule.appliesTo !== kind) continue;
      let hits;
      try {
        hits = rule.match(file) || [];
      } catch {
        continue;
      }
      for (const hit of hits) {
        findings.push({
          id: rule.id,
          severity: rule.severity,
          category: rule.category,
          title: rule.title,
          titleZh: rule.titleZh,
          explanation: rule.explanation,
          explanationZh: rule.explanationZh,
          file: rel,
          line: hit.line || 0,
          snippet: hit.snippet || '',
        });
      }
    }
  }

  const skill = { name, files };
  const info = hygieneChecks(skill);
  const score = scoreFindings(findings);
  const verdict = verdictFor(score);

  // Top 3 reasons: highest-severity findings, in file order, deduplicated by rule id.
  const severityRank = { critical: 0, high: 1, medium: 2, low: 3 };
  const topReasons = [...findings]
    .sort((a, b) => severityRank[a.severity] - severityRank[b.severity])
    .filter((f, i, arr) => arr.findIndex((x) => x.id === f.id) === i)
    .slice(0, 3);

  return {
    name,
    path: absDir,
    filesScanned: files.length,
    skipped,
    findings,
    info,
    score,
    verdict,
    topReasons,
  };
}

/** Find every skill (directory containing a SKILL.md) under root, depth <= 3. */
function discoverSkills(rootDir) {
  const found = [];
  function walk(dir, depth) {
    if (depth > 3) return;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    const names = entries.map((e) => e.name);
    if (names.some((n) => n.toLowerCase() === 'skill.md')) {
      found.push(dir);
      return; // do not descend into a skill's own sub-skills
    }
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (SKIP_DIRS.has(entry.name)) continue;
      walk(path.join(dir, entry.name), depth + 1);
    }
  }
  walk(path.resolve(rootDir), 0);
  return found;
}

module.exports = { scanSkill, discoverSkills, MAX_FILE_BYTES, MAX_TOTAL_BYTES };
