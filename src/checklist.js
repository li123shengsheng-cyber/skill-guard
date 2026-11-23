/**
 * The secure-skill authoring checklist, printed by `skill-guard checklist`.
 * Bilingual (Chinese primary, English alongside).
 */

'use strict';

const CHECKLIST = [
  {
    zh: '不藏外泄指令：技能里不要写让智能体向外发送数据、密钥或文件内容的步骤。',
    en: 'No exfiltration instructions: never tell the agent to send data, keys, or file contents anywhere.',
  },
  {
    zh: '不用 curl | bash：下载和运行分开，先下载、验证，再运行。',
    en: 'No curl | bash: download first, verify, then run — never in one pipe.',
  },
  {
    zh: '不碰凭证：不要读环境变量里的密钥、~/.ssh、~/.aws、.env，除非用户明确给了你。',
    en: 'No credential access: do not read keys from env vars, ~/.ssh, ~/.aws, or .env files unless the user explicitly provides them.',
  },
  {
    zh: '没有提示词注入式措辞：不要写 "ignore previous instructions"、"do not tell the user" 这类话。',
    en: 'No prompt-injection phrasing: never write "ignore previous instructions" or "do not tell the user".',
  },
  {
    zh: 'MCP 最小权限：服务配置只给技能真正需要的工具，不用通配符 Bash(*)。',
    en: 'MCP least privilege: grant only the tools the skill needs; no wildcard Bash(*).',
  },
  {
    zh: '不写死密钥：配置文件里不要放真实的 API key、token 或密码，用占位符加说明。',
    en: 'No hardcoded secrets: never put a real API key, token, or password in a config; use a placeholder and explain.',
  },
  {
    zh: '依赖要干净：固定版本号，不要用安装时脚本拉取远程代码，不要用未加限定的 npx -y。',
    en: 'Clean dependencies: pin versions, no install scripts that fetch remote code, no unscoped npx -y.',
  },
  {
    zh: '脚本只做声称的事：不要在后台联网、不要写计划外的文件、不要改用户配置。',
    en: 'Scripts do only what the skill claims: no background network calls, no surprise file writes, no config changes.',
  },
  {
    zh: 'frontmatter 只列必需工具：allowed-tools 写具体命令，不要图省事给 *。',
    en: 'Frontmatter lists only needed tools: allowed-tools names exact commands, never * for convenience.',
  },
  {
    zh: '描述要诚实：description 写技能真实会做的事，行为不要藏在脚本里。',
    en: 'Honest description: the description states what the skill really does; no behaviour hidden in scripts.',
  },
  {
    zh: '不要教智能体绕过安全检查：不要让它关掉确认、跳过审批或忽略警告。',
    en: 'Never teach the agent to bypass safety checks: no disabling confirmations, approvals, or warnings.',
  },
  {
    zh: '发布前自查：先在空白项目里试一遍，再用 skill-guard scan 扫一遍自己的技能。',
    en: 'Self-check before publishing: try it in a scratch project, then scan your own skill with skill-guard scan.',
  },
];

function formatChecklist() {
  const lines = [];
  lines.push('');
  lines.push('  写安全 skill 的检查清单 / Secure-skill authoring checklist');
  lines.push(`  ${'-'.repeat(56)}`);
  CHECKLIST.forEach((item, i) => {
    lines.push(`  ${String(i + 1).padStart(2)}. ${item.zh}`);
    lines.push(`      ${item.en}`);
  });
  lines.push('');
  lines.push('  发布前跑一遍：skill-guard scan <你的技能目录>');
  lines.push('  Scan before you publish: skill-guard scan <your-skill-dir>');
  lines.push('');
  return lines.join('\n');
}

module.exports = { CHECKLIST, formatChecklist };
