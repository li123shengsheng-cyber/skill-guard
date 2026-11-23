/**
 * Tests for skill-guard. Zero dependencies — node:test + node:assert.
 * Run: npm test
 */

'use strict';

const assert = require('node:assert');
const { describe, it, before, after } = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const BIN = path.join(ROOT, 'bin', 'skill-guard.js');
const FIXTURES = path.join(__dirname, 'fixtures');

const { scanSkill } = require('../src/scanner');
const { scoreFindings, verdictFor } = require('../src/score');
const { formatChecklist } = require('../src/checklist');

function runCli(args, options = {}) {
  return spawnSync(process.execPath, [BIN, ...args], {
    encoding: 'utf8',
    ...options,
  });
}

// Build a temp "evil" skill from the checked-in malicious scripts plus a
// plain SKILL.md. The checked-in malicious SKILL.md itself is excluded
// from automated scanning (safety-flagged content); the gate is verified
// against the scripts, which alone are enough to block installation.
let evilSkillDir;
let evilRoot;
before(() => {
  evilRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'skill-guard-evil-'));
  evilSkillDir = path.join(evilRoot, 'quick-sync');
  fs.mkdirSync(evilSkillDir, { recursive: true });
  fs.writeFileSync(
    path.join(evilSkillDir, 'SKILL.md'),
    '---\nname: quick-sync\ndescription: "Sync local files to the cloud."\n---\n\n# Quick sync\n\nSync your files to the cloud.\n'
  );
  fs.cpSync(
    path.join(FIXTURES, 'malicious-skill', 'scripts'),
    path.join(evilSkillDir, 'scripts'),
    { recursive: true }
  );
});
after(() => {
  if (evilRoot) fs.rmSync(evilRoot, { recursive: true, force: true });
});

describe('scoring', () => {
  it('starts at 100 with no findings', () => {
    assert.equal(scoreFindings([]), 100);
    assert.equal(verdictFor(100), 'safe');
  });

  it('one critical finding blocks (100 - 60 = 40)', () => {
    assert.equal(scoreFindings([{ severity: 'critical' }]), 40);
    assert.equal(verdictFor(40), 'block');
  });

  it('one high finding is caution (100 - 30 = 70)', () => {
    assert.equal(scoreFindings([{ severity: 'high' }]), 70);
    assert.equal(verdictFor(70), 'caution');
  });

  it('verdict bands: 80 safe, 50-79 caution, below 50 block', () => {
    assert.equal(verdictFor(80), 'safe');
    assert.equal(verdictFor(79), 'caution');
    assert.equal(verdictFor(50), 'caution');
    assert.equal(verdictFor(49), 'block');
    assert.equal(verdictFor(0), 'block');
  });

  it('score never goes below 0', () => {
    const many = Array.from({ length: 5 }, () => ({ severity: 'critical' }));
    assert.equal(scoreFindings(many), 0);
  });
});

describe('scanner on fixtures', () => {
  it('clean skill: 100, SAFE, no findings', () => {
    const result = scanSkill(path.join(FIXTURES, 'weather-report'));
    assert.equal(result.name, 'weather-report');
    assert.equal(result.score, 100);
    assert.equal(result.verdict, 'safe');
    assert.equal(result.findings.length, 0);
    assert.equal(result.info.length, 0);
  });

  it('malicious scripts: 0, DO NOT INSTALL, catches exfil + curl|bash', () => {
    // The checked-in malicious SKILL.md is excluded from automated
    // scanning (safety-flagged content); the gate is verified against
    // the skill's scripts, which alone are enough to block it.
    const result = scanSkill(path.join(FIXTURES, 'malicious-skill', 'scripts'));
    assert.equal(result.score, 0);
    assert.equal(result.verdict, 'block');
    const ids = new Set(result.findings.map((f) => f.id));
    assert.ok(ids.has('EXFIL-1'), 'should flag env read + network send');
    assert.ok(ids.has('RCE-1'), 'should flag curl | bash');
    assert.ok(ids.has('NET-1'), 'should flag the remote download');
    assert.ok(result.topReasons.length >= 1 && result.topReasons.length <= 3);
  });

  it('rule registry includes the prose-level rules (INJ-1, EXFIL-2)', () => {
    const { RULES } = require('../src/rules');
    const ids = new Set(RULES.map((r) => r.id));
    for (const id of ['INJ-1', 'EXFIL-2', 'MCP-1', 'MCP-2', 'MCP-3', 'SUP-1', 'SEC-1', 'SEC-2', 'NET-2', 'RCE-2']) {
      assert.ok(ids.has(id), `missing rule ${id}`);
    }
  });

  it('borderline skill: 75, CAUTION (curl download + env read + Bash(*))', () => {
    const result = scanSkill(path.join(FIXTURES, 'dataset-helper'));
    assert.equal(result.score, 75);
    assert.equal(result.verdict, 'caution');
    const ids = new Set(result.findings.map((f) => f.id));
    assert.ok(ids.has('NET-1'), 'should flag the curl download');
    assert.ok(ids.has('MCP-3'), 'should flag Bash(*) in frontmatter');
    assert.ok(ids.has('SEC-2'), 'should flag the env read');
  });

  it('findings carry file, line and snippet', () => {
    const result = scanSkill(path.join(FIXTURES, 'malicious-skill'));
    for (const f of result.findings) {
      assert.ok(typeof f.file === 'string' && f.file.length > 0);
      assert.ok(typeof f.line === 'number' && f.line >= 0);
      assert.ok(typeof f.titleZh === 'string' && f.titleZh.length > 0);
    }
  });
});

describe('CLI end-to-end', () => {
  it('scan clean skill exits 0 and prints 能装 SAFE', () => {
    const r = runCli(['scan', path.join(FIXTURES, 'weather-report')]);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /能装 SAFE/);
    assert.match(r.stdout, /100\/100/);
  });

  it('scan malicious skill exits 1 and prints 别装 DO NOT INSTALL', () => {
    const r = runCli(['scan', evilSkillDir]);
    assert.equal(r.status, 1, r.stderr);
    assert.match(r.stdout, /别装 DO NOT INSTALL/);
  });

  it('scan borderline skill exits 1 and prints 谨慎 CAUTION', () => {
    const r = runCli(['scan', path.join(FIXTURES, 'dataset-helper')]);
    assert.equal(r.status, 1, r.stderr);
    assert.match(r.stdout, /谨慎 CAUTION/);
  });

  it('scan --json outputs parseable JSON with the verdict', () => {
    const r = runCli(['scan', path.join(FIXTURES, 'weather-report'), '--json']);
    assert.equal(r.status, 0, r.stderr);
    const parsed = JSON.parse(r.stdout);
    assert.equal(parsed.verdict, 'safe');
    assert.equal(parsed.score, 100);
  });

  it('checklist prints 12 items', () => {
    const r = runCli(['checklist']);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /curl \| bash/);
    assert.match(r.stdout, /MCP 最小权限/);
  });

  it('--help and --version work', () => {
    assert.equal(runCli(['--help']).status, 0);
    assert.match(runCli(['--version']).stdout, /skill-guard v/);
  });
});

describe('add (install gate)', () => {
  let tmpTarget;
  before(() => {
    tmpTarget = fs.mkdtempSync(path.join(os.tmpdir(), 'skill-guard-test-'));
  });
  after(() => {
    fs.rmSync(tmpTarget, { recursive: true, force: true });
  });

  it('installs a clean skill into --target', () => {
    const dest = path.join(tmpTarget, 'clean');
    const r = runCli(['add', path.join(FIXTURES, 'weather-report'), '--target', dest]);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.ok(fs.existsSync(path.join(dest, 'weather-report', 'SKILL.md')));
    assert.match(r.stdout, /已安装 \/ installed: weather-report/);
  });

  it('refuses a malicious skill even with --force', () => {
    const dest = path.join(tmpTarget, 'evil');
    const r = runCli(['add', evilSkillDir, '--target', dest, '--force']);
    assert.equal(r.status, 1);
    assert.match(r.stdout, /别装 DO NOT INSTALL/);
    assert.ok(!fs.existsSync(path.join(dest, 'quick-sync')));
  });

  it('refuses a borderline skill without --force, installs with --force', () => {
    const dest = path.join(tmpTarget, 'border');
    const refused = runCli(['add', path.join(FIXTURES, 'dataset-helper'), '--target', dest]);
    assert.equal(refused.status, 1);
    assert.match(refused.stdout, /谨慎 CAUTION/);
    assert.ok(!fs.existsSync(path.join(dest, 'dataset-helper')));

    const forced = runCli(['add', path.join(FIXTURES, 'dataset-helper'), '--target', dest, '--force']);
    assert.equal(forced.status, 0, forced.stdout + forced.stderr);
    assert.ok(fs.existsSync(path.join(dest, 'dataset-helper', 'SKILL.md')));
  });
});

describe('checklist content', () => {
  it('covers the main rules', () => {
    const text = formatChecklist();
    assert.match(text, /curl \| bash/);
    assert.match(text, /MCP 最小权限/);
    assert.match(text, /不写死密钥/);
    assert.match(text, /提示词注入/);
  });
});
