#!/usr/bin/env node
/**
 * skill-guard CLI — scan an agent skill before you install it.
 *
 *   skill-guard scan <path>            scan only, print the report
 *   skill-guard add <repo|path>         scan, then install if it passes
 *   skill-guard checklist               print the secure-skill checklist
 *
 * Exit codes: 0 = safe / done, 1 = caution or blocked (or install refused),
 *               2 = usage error.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { scanSkill, discoverSkills } = require('../src/scanner');
const { formatReport, jsonReport } = require('../src/report');
const { addSkill, defaultSkillsDir } = require('../src/install');
const { formatChecklist } = require('../src/checklist');

const VERSION = '0.1.0';

function printHelp() {
  console.log(`
skill-guard v${VERSION} — 装 skill 之前先安检 / scan an agent skill before you install it

用法 / Usage:
  skill-guard scan <path> [--json]
      只扫描，不安装。打印中文+英文报告。
      Scan only. Prints a bilingual report.
      退出码 / exit code: 0 能装 SAFE, 1 谨慎 CAUTION / 别装 DO NOT INSTALL

  skill-guard add <owner/repo | https://github.com/owner/repo | 本地路径>
      [--target <目录>] [--force] [--json]
      先克隆/复制到临时目录并扫描，通过才装进 skills 目录
      （默认 ~/.claude/skills/）。谨慎需要 --force；别装一律拒绝。
      Clone/copy to a temp dir, scan, install only if it passes.
      CAUTION needs --force; DO NOT INSTALL is always refused.

  skill-guard checklist
      打印写安全 skill 的检查清单 / print the secure-skill checklist

  skill-guard --help | --version

示例 / Examples:
  skill-guard scan ./my-skill
  skill-guard add obra/superpowers
  skill-guard add ./my-skill --target /tmp/skills-test
`);
}

function parseFlags(args) {
  const flags = { json: false, force: false, target: null, positional: [] };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--json') flags.json = true;
    else if (a === '--force') flags.force = true;
    else if (a === '--target') {
      flags.target = args[++i];
      if (!flags.target) throw new Error('--target 需要一个目录 / --target needs a directory');
    } else if (a.startsWith('--target=')) flags.target = a.slice('--target='.length);
    else if (a === '--help' || a === '-h') flags.help = true;
    else if (a === '--version' || a === '-V') flags.version = true;
    else if (a.startsWith('-')) throw new Error(`未知选项 / unknown option: ${a}`);
    else flags.positional.push(a);
  }
  return flags;
}

function printResult(result, asJson) {
  if (asJson) console.log(jsonReport(result));
  else console.log(formatReport(result));
}

function cmdScan(target, flags) {
  if (!target) throw new Error('scan 需要一个路径 / scan needs a path');
  if (!fs.existsSync(target)) throw new Error(`路径不存在 / path not found: ${target}`);
  const stat = fs.statSync(target);
  const skillDirs = stat.isDirectory()
    ? discoverSkills(target)
    : [path.dirname(path.resolve(target))];
  if (skillDirs.length === 0) {
    console.log(`没有找到技能 / no skill found in: ${target}`);
    console.log('技能目录里应包含 SKILL.md / a skill directory contains a SKILL.md file.');
    return 1;
  }
  let code = 0;
  for (const dir of skillDirs) {
    const result = scanSkill(dir);
    printResult(result, flags.json);
    if (result.verdict !== 'safe') code = 1;
  }
  return code;
}

function cmdAdd(spec, flags) {
  if (!spec) throw new Error('add 需要一个仓库或路径 / add needs a repo or path');
  const { results, installed, refused, reason, existing } = addSkill(spec, {
    targetDir: flags.target,
    force: flags.force,
  });

  if (results.length === 0) {
    console.log(`没有找到技能 / no skill found in: ${spec}`);
    console.log('仓库里应包含 SKILL.md / the repo should contain a SKILL.md file.');
    return 1;
  }
  for (const result of results) printResult(result, flags.json);

  if (refused) {
    if (reason === 'blocked') {
      console.log('已拒绝安装 / install refused: 发现严重风险（别装 DO NOT INSTALL），即使 --force 也不装。');
    } else if (reason === 'needs-force') {
      console.log('已拒绝安装 / install refused: 结论是谨慎 CAUTION。确认了解风险后，用 --force 重新安装。');
    } else if (reason === 'exists') {
      console.log(`已拒绝安装 / install refused: 目标已存在 ${existing}，用 --force 覆盖。`);
    }
    return 1;
  }
  for (const item of installed) {
    console.log(`已安装 / installed: ${item.name} → ${item.dest}`);
  }
  return 0;
}

function main(argv) {
  const [cmd, ...rest] = argv;
  if (!cmd || cmd === '--help' || cmd === '-h') {
    printHelp();
    return 0;
  }
  if (cmd === '--version' || cmd === '-V') {
    console.log(`skill-guard v${VERSION}`);
    return 0;
  }
  if (cmd === 'checklist') {
    console.log(formatChecklist());
    return 0;
  }
  if (cmd === 'scan') {
    const flags = parseFlags(rest);
    return cmdScan(flags.positional[0], flags);
  }
  if (cmd === 'add') {
    const flags = parseFlags(rest);
    return cmdAdd(flags.positional[0], flags);
  }
  throw new Error(`未知命令 / unknown command: ${cmd}\n试试 / try: skill-guard --help`);
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (err) {
  console.error(`错误 / error: ${err.message}`);
  process.exitCode = 2;
}
