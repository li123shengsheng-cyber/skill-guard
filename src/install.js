/**
 * Install flow: fetch a skill (git clone or local path), scan it,
 * and copy it into the skills directory only when the verdict allows.
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { scanSkill, discoverSkills } = require('./scanner');

function defaultSkillsDir() {
  return path.join(os.homedir(), '.claude', 'skills');
}

function isGitHubSpec(spec) {
  return /^[\w.-]+\/[\w.-]+$/.test(spec) || /^https?:\/\/github\.com\//.test(spec);
}

function repoUrlFor(spec) {
  if (/^https?:\/\/github\.com\//.test(spec)) {
    return spec.replace(/\.git$/, '') + '.git';
  }
  return `https://github.com/${spec}.git`;
}

/** Fetch the source into a temp dir. Returns { dir, cleanup }. */
function fetchSource(spec) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'skill-guard-'));
  const cleanup = () => {
    try {
      fs.rmSync(tmp, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  };

  if (fs.existsSync(spec) && fs.statSync(spec).isDirectory()) {
    // Local path: copy into temp, keeping the original folder name
    // (the folder name is the skill name).
    const base = path.basename(path.resolve(spec)) || 'skill';
    const dest = path.join(tmp, base);
    fs.cpSync(path.resolve(spec), dest, { recursive: true });
    return { dir: dest, cleanup };
  }

  if (isGitHubSpec(spec)) {
    const url = repoUrlFor(spec);
    const repoName = url.split('/').pop().replace(/\.git$/, '') || 'skill';
    const dest = path.join(tmp, repoName);
    try {
      execFileSync('git', ['clone', '--depth', '1', '--single-branch', url, dest], {
        stdio: 'pipe',
        timeout: 120000,
      });
    } catch (err) {
      cleanup();
      const detail = err.stderr ? err.stderr.toString().trim().split('\n').pop() : err.message;
      throw new Error(`克隆失败 / clone failed (${url}): ${detail}`);
    }
    return { dir: dest, cleanup };
  }

  cleanup();
  throw new Error(
    `无法识别的来源 / unrecognized source: ${spec}\n用法 / usage: skill-guard add <owner/repo | https://github.com/owner/repo | 本地路径 / local-path>`
  );
}

/**
 * Scan + (maybe) install.
 * Returns { results, installed, refused, reason }.
 * - installed: [{ name, dest }] when installed
 * - refused: true when nothing was installed
 */
function addSkill(spec, { targetDir, force }) {
  const target = targetDir ? path.resolve(targetDir) : defaultSkillsDir();
  const { dir, cleanup } = fetchSource(spec);
  try {
    const skillDirs = discoverSkills(dir);
    if (skillDirs.length === 0) {
      return { results: [], installed: [], refused: true, reason: 'no-skill' };
    }
    const results = skillDirs.map((d) => scanSkill(d));

    const worst = results.some((r) => r.verdict === 'block')
      ? 'block'
      : results.some((r) => r.verdict === 'caution')
        ? 'caution'
        : 'safe';

    if (worst === 'block') {
      return { results, installed: [], refused: true, reason: 'blocked' };
    }
    if (worst === 'caution' && !force) {
      return { results, installed: [], refused: true, reason: 'needs-force' };
    }

    const installed = [];
    for (const result of results) {
      const srcDir = result.path;
      const dest = path.join(target, result.name);
      if (fs.existsSync(dest) && !force) {
        return {
          results,
          installed,
          refused: true,
          reason: 'exists',
          existing: dest,
        };
      }
      fs.mkdirSync(target, { recursive: true });
      if (fs.existsSync(dest)) fs.rmSync(dest, { recursive: true, force: true });
      fs.cpSync(srcDir, dest, { recursive: true });
      installed.push({ name: result.name, dest });
    }
    return { results, installed, refused: false, reason: 'ok' };
  } finally {
    cleanup();
  }
}

module.exports = { addSkill, defaultSkillsDir, isGitHubSpec, repoUrlFor };
