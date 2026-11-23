/**
 * Report formatting: human-readable terminal output (Chinese + English)
 * and machine-readable JSON.
 */

'use strict';

const { VERDICT_LABEL } = require('./score');

const SEVERITY_LABEL = {
  critical: 'CRITICAL 严重',
  high: 'HIGH 高危',
  medium: 'MEDIUM 中危',
  low: 'LOW 低危',
  info: 'INFO 提示',
};

function verdictLine(result) {
  const label = VERDICT_LABEL[result.verdict];
  return `结论 / Verdict: ${label.zh} ${label.en}   安全分 / Safety score: ${result.score}/100`;
}

function formatReport(result) {
  const lines = [];
  lines.push('');
  lines.push(`  skill-guard 扫描报告 / Scan report — ${result.name}`);
  lines.push(`  ${'-'.repeat(56)}`);
  lines.push(`  ${verdictLine(result)}`);
  lines.push(`  扫描文件 / Files scanned: ${result.filesScanned}`);
  if (result.skipped.length > 0) {
    lines.push(`  跳过 / Skipped: ${result.skipped.map((s) => `${s.rel} (${s.reason})`).join('; ')}`);
  }
  lines.push('');

  if (result.topReasons.length > 0) {
    lines.push('  主要原因 / Top reasons:');
    result.topReasons.forEach((f, i) => {
      lines.push(`    ${i + 1}. [${SEVERITY_LABEL[f.severity]}] ${f.titleZh} / ${f.title}`);
      lines.push(`       ${f.file}${f.line ? ':' + f.line : ''}`);
      if (f.snippet) lines.push(`       > ${f.snippet}`);
    });
    lines.push('');
  }

  if (result.findings.length > 0) {
    const counts = {};
    for (const f of result.findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
    lines.push(
      `  全部发现 / All findings (${result.findings.length}): ` +
        Object.entries(counts)
          .map(([sev, n]) => `${SEVERITY_LABEL[sev]} × ${n}`)
          .join(', ')
    );
    for (const f of result.findings) {
      lines.push(`    [${f.id}] [${SEVERITY_LABEL[f.severity]}] ${f.titleZh}`);
      lines.push(`        ${f.file}${f.line ? ':' + f.line : ''}`);
      if (f.snippet) lines.push(`        > ${f.snippet}`);
      lines.push(`        ${f.explanationZh}`);
    }
    lines.push('');
  } else {
    lines.push('  未发现问题 / No issues found.');
    lines.push('');
  }

  if (result.info.length > 0) {
    lines.push('  提示 / Notes (不影响评分):');
    for (const f of result.info) {
      lines.push(`    [${f.id}] ${f.titleZh} — ${f.file}`);
      lines.push(`        ${f.explanationZh}`);
    }
    lines.push('');
  }

  if (result.verdict === 'safe') {
    lines.push('  可以安装 / Safe to install.');
  } else if (result.verdict === 'caution') {
    lines.push('  谨慎：发现了一些风险。确认了解风险后，用 --force 安装。');
    lines.push('  Caution: some risks found. Install with --force only if you accept them.');
  } else {
    lines.push('  别装：发现了严重风险，skill-guard 拒绝安装。');
    lines.push('  Do not install: serious risks found; skill-guard refuses to install.');
  }
  lines.push('');
  return lines.join('\n');
}

function jsonReport(result) {
  return JSON.stringify(
    {
      tool: 'skill-guard',
      skill: result.name,
      path: result.path,
      score: result.score,
      verdict: result.verdict,
      verdictZh: VERDICT_LABEL[result.verdict].zh,
      verdictEn: VERDICT_LABEL[result.verdict].en,
      filesScanned: result.filesScanned,
      skipped: result.skipped,
      findings: result.findings.map((f) => ({
        id: f.id,
        severity: f.severity,
        category: f.category,
        title: f.title,
        titleZh: f.titleZh,
        file: f.file,
        line: f.line,
        snippet: f.snippet,
      })),
      info: result.info,
      topReasons: result.topReasons.map((f) => ({
        id: f.id,
        severity: f.severity,
        titleZh: f.titleZh,
        title: f.title,
        file: f.file,
        line: f.line,
      })),
    },
    null,
    2
  );
}

module.exports = { formatReport, jsonReport, verdictLine };
