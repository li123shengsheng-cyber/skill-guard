/**
 * Detection rules for skill-guard.
 *
 * Original rule set. Pattern *ideas* (secret exfiltration, curl|bash,
 * prompt injection, MCP least privilege) are drawn from publicly
 * documented agent-skill risks, e.g. the categories surveyed by
 * NVIDIA SkillSpector. Every pattern, threshold and message here is
 * written from scratch for this project.
 *
 * Severity weights (applied to the safety score, which starts at 100):
 *   critical -60   high -30   medium -10   low -5
 * Verdict bands (see src/score.js):
 *   80-100 SAFE (能装) | 50-79 CAUTION (谨慎) | 0-49 DO NOT INSTALL (别装)
 */

'use strict';

// ---------------------------------------------------------------------------
// Shared pattern fragments
// ---------------------------------------------------------------------------

/** Regexes that indicate reading secrets / credentials. */
const SECRET_READ = [
  /process\.env\b/,
  /os\.environ\b/,
  /os\.getenv\s*\(/,
  /getenv\s*\(\s*['"][A-Z_]+['"]/,
  /~\s*\/\.ssh\//,
  /~\s*\/\.aws\/credentials/,
  /~\s*\/\.gnupg\//,
  /~\s*\/\.netrc\b/,
  /readFileSync\s*\([^)]*\.env/,
  /open\s*\([^)]*\.env['"]/,
];

/** Regexes that indicate sending data over the network. */
const NETWORK_SEND = [
  /\bfetch\s*\(/,
  /\baxios\.(get|post|put|patch|delete)\s*\(/,
  /\brequests\.(get|post|put|patch)\s*\(/,
  /\burllib\.request\.urlopen\s*\(/,
  /\bhttp\.request\s*\(/,
  /\bhttps\.request\s*\(/,
  /\bcurl\s+[^|\n]*(-d|--data|--upload-file)\b/,
  /\bXMLHttpRequest\b/,
  /\bWebSocket\s*\(/,
];

/** Pipe-to-shell: download something and run it in one breath. */
const PIPE_TO_SHELL = /(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(bash|sh|zsh|dash|powershell|pwsh)\b/;

/** Shell command that executes fetched content. */
const EXEC_FETCHED = /bash\s+-c\s+["'`]\s*\$\(?(curl|wget)\b/;

/** Suspicious URL hosts: shorteners, pastebins, IP literals. */
const SUSPICIOUS_URL = /https?:\/\/(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly|shorturl\.at|pastebin\.com|paste\.ee|0x0\.st|transfer\.sh|anonfiles\.com|file\.io)\b|https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;

/** Prompt-injection phrases (English, case-insensitive). */
const INJECTION_PHRASES = [
  /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i,
  /disregard\s+(your|all|the)\s+(instructions|system\s+prompt|previous\s+instructions)/i,
  /forget\s+(your|all|the)\s+instructions/i,
  /override\s+(your|the)\s+(instructions|system\s+prompt)/i,
  /do\s+not\s+(tell|mention|inform|reveal|disclose|warn)\s+(the\s+)?user/i,
  /never\s+(tell|mention|reveal|disclose)\s+(the\s+)?user/i,
  /do\s+not\s+show\s+this\s+(to\s+)?(the\s+)?user/i,
  /keep\s+this\s+(hidden|secret)\s+from\s+the\s+user/i,
];

/** Dynamic code execution of untrusted content. */
const DYNAMIC_EXEC = [
  /\beval\s*\(/,
  /\bnew\s+Function\s*\(/,
  /os\.system\s*\(/,
  /subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True/,
  /child_process\.(exec|execSync)\s*\(/,
  /exec\s*\(\s*['"`][^'"`]*\$\{/,
];

/** Direct reads of credential files. */
const CREDENTIAL_FILE = [
  /~\s*\/\.ssh\/id_[a-z0-9]+/,
  /~\s*\/\.aws\/credentials/,
  /~\s*\/\.gnupg\//,
  /~\s*\/\.netrc\b/,
  /gpg\s+--export-secret-keys/,
  /security\s+find-generic-password/,
  /keychain/i,
];

/** Hardcoded secret values in JSON/YAML config (placeholders excluded). */
const HARDCODED_SECRET =
  /"(api[_-]?key|apikey|token|secret|password|passwd)"\s*:\s*"([^"]{8,})"/i;

const PLACEHOLDER_VALUE = /your|placeholder|xxx+|example|changeme|<\s*[^>]*\s*>|todo/i;

// ---------------------------------------------------------------------------
// Rule definitions
// Each rule: id, severity, category, title, titleZh, explanation,
// explanationZh, appliesTo ('all' | 'scripts' | 'docs' | 'config'),
// and match(file) -> [{ line, snippet }] (empty = no finding).
// `file` is { rel, ext, content, isExecutable }.
// ---------------------------------------------------------------------------

function lineOf(content, index) {
  return content.slice(0, index).split('\n').length;
}

function snippetOf(content, index, length = 120) {
  const start = content.lastIndexOf('\n', index - 1) + 1;
  const end = content.indexOf('\n', index);
  const line = content.slice(start, end === -1 ? undefined : end).trim();
  return line.length > length ? line.slice(0, length - 3) + '...' : line;
}

function regexHits(content, regexes) {
  const hits = [];
  for (const re of regexes) {
    const flags = re.flags.includes('g') ? re.flags : re.flags + 'g';
    const global = new RegExp(re.source, flags);
    let m;
    while ((m = global.exec(content)) !== null) {
      hits.push({ line: lineOf(content, m.index), snippet: snippetOf(content, m.index) });
      if (m.index === global.lastIndex) global.lastIndex++;
    }
  }
  return hits;
}

const RULES = [
  {
    id: 'EXFIL-1',
    severity: 'critical',
    category: 'exfiltration',
    title: 'Reads secrets and sends data over the network',
    titleZh: '读取密钥并向外网发送数据',
    explanation:
      'The same file reads secrets/credentials (environment variables, SSH keys, cloud credentials) and sends data over the network. Combined, that is the classic shape of credential exfiltration.',
    explanationZh:
      '同一个文件既读取密钥/凭证（环境变量、SSH 密钥、云凭证），又向外网发送数据。两者结合就是典型的凭证外泄形态。',
    appliesTo: 'scripts',
    match(file) {
      const reads = regexHits(file.content, SECRET_READ);
      const sends = regexHits(file.content, NETWORK_SEND);
      if (reads.length === 0 || sends.length === 0) return [];
      return [
        {
          line: reads[0].line,
          snippet: reads[0].snippet + '  →  ' + sends[0].snippet,
        },
      ];
    },
  },
  {
    id: 'EXFIL-2',
    severity: 'high',
    category: 'exfiltration',
    title: 'Instructs the agent to send secrets somewhere',
    titleZh: '指示智能体把密钥发到某处',
    explanation:
      'The skill text tells the agent to send an API key, secret, token, password or environment variable to a destination. A skill should never ask the agent to move credentials.',
    explanationZh:
      '技能文本指示智能体把 API 密钥、secret、token、密码或环境变量发送到某个地方。技能绝不应该要求智能体转移凭证。',
    appliesTo: 'docs',
    match(file) {
      return regexHits(file.content, [
        /(send|post|upload|exfiltrate|transmit|forward)\b[^.\n]{0,80}\b(api[-_ ]?key|secret|token|password|passwd|credentials?|environment\s+variables?)\b/i,
      ]);
    },
  },
  {
    id: 'RCE-1',
    severity: 'critical',
    category: 'remote-code-execution',
    title: 'Pipes a download straight into a shell (curl|bash)',
    titleZh: '下载内容直接管道进 shell（curl|bash）',
    explanation:
      'A command downloads something from the network and pipes it directly into a shell. The code runs before anyone can inspect it. Download first, verify, then run — never in one pipe.',
    explanationZh:
      '命令从网络下载内容并直接管道进 shell 执行，代码在任何人检查之前就跑起来了。正确做法是先下载、验证，再运行，绝不要用一根管道连起来。',
    appliesTo: 'all',
    match(file) {
      return regexHits(file.content, [PIPE_TO_SHELL, EXEC_FETCHED]);
    },
  },
  {
    id: 'RCE-2',
    severity: 'high',
    category: 'remote-code-execution',
    title: 'Executes dynamically built code',
    titleZh: '动态执行拼接出来的代码',
    explanation:
      'The code executes dynamically built strings (eval, Function constructor, os.system, shell=True subprocess, child_process.exec). If any part of that string comes from outside, it is remote code execution.',
    explanationZh:
      '代码动态执行拼接出来的字符串（eval、Function 构造器、os.system、shell=True 的 subprocess、child_process.exec）。其中任何一部分来自外部输入，就是远程代码执行。',
    appliesTo: 'scripts',
    match(file) {
      return regexHits(file.content, DYNAMIC_EXEC);
    },
  },
  {
    id: 'INJ-1',
    severity: 'high',
    category: 'prompt-injection',
    title: 'Prompt-injection phrasing',
    titleZh: '提示词注入式措辞',
    explanation:
      'The skill text contains phrasing used to override the agent’s instructions or hide behaviour from the user ("ignore previous instructions", "do not tell the user", ...). Legitimate skills do not need to say this.',
    explanationZh:
      '技能文本含有用于覆盖智能体指令或向用户隐瞒行为的措辞（"ignore previous instructions"、"do not tell the user" 等）。正经技能不需要这么写。',
    appliesTo: 'docs',
    match(file) {
      return regexHits(file.content, INJECTION_PHRASES);
    },
  },
  {
    id: 'SEC-1',
    severity: 'medium',
    category: 'credential-access',
    title: 'Reads credential files directly',
    titleZh: '直接读取凭证文件',
    explanation:
      'The skill reads credential files such as SSH private keys, AWS credentials, GPG keyrings or the system keychain. A skill almost never needs these.',
    explanationZh:
      '技能直接读取 SSH 私钥、AWS 凭证、GPG 密钥环或系统钥匙串等凭证文件。技能几乎永远不需要这些。',
    appliesTo: 'all',
    match(file) {
      return regexHits(file.content, CREDENTIAL_FILE);
    },
  },
  {
    id: 'SEC-2',
    severity: 'low',
    category: 'credential-access',
    title: 'Reads environment variables',
    titleZh: '读取环境变量',
    explanation:
      'The code reads environment variables. Often harmless (a config path, a home directory), but worth a glance — especially combined with any network use.',
    explanationZh:
      '代码读取环境变量。很多时候无害（配置路径、家目录），但值得看一眼——尤其是在同时有联网行为的情况下。',
    appliesTo: 'scripts',
    match(file) {
      // Skip when EXFIL-1 already fired for this file: the same read is
      // already reported at critical severity. Avoid double-counting.
      const reads = regexHits(file.content, SECRET_READ);
      const sends = regexHits(file.content, NETWORK_SEND);
      if (reads.length > 0 && sends.length > 0) return [];
      return reads.slice(0, 1);
    },
  },
  {
    id: 'NET-1',
    severity: 'medium',
    category: 'supply-chain',
    title: 'Downloads remote content during setup or use',
    titleZh: '在使用或安装时下载远程内容',
    explanation:
      'The skill downloads remote content (curl/wget). It may be a legitimate dataset, but anything fetched at install or run time is a supply-chain surface: check the URL and pin it.',
    explanationZh:
      '技能会下载远程内容（curl/wget）。可能是正当的数据集，但安装或运行时拉取的任何东西都是供应链风险面：核对 URL，最好固定版本。',
    appliesTo: 'all',
    match(file) {
      return regexHits(file.content, [/(curl|wget)\s+[^\n]*https?:\/\/\S+/]);
    },
  },
  {
    id: 'NET-2',
    severity: 'low',
    category: 'supply-chain',
    title: 'Links to a suspicious host',
    titleZh: '链接到可疑域名',
    explanation:
      'A link points at a URL shortener, a pastebin-style host, or a bare IP address. Those hide the real destination.',
    explanationZh:
      '链接指向短链接、pastebin 类站点或裸 IP 地址，这些都会隐藏真实目标。',
    appliesTo: 'all',
    match(file) {
      return regexHits(file.content, [SUSPICIOUS_URL]);
    },
  },
  {
    id: 'MCP-1',
    severity: 'high',
    category: 'mcp-config',
    title: 'MCP/server config runs remote code',
    titleZh: 'MCP/服务配置会运行远程代码',
    explanation:
      'A server or MCP configuration executes a command that fetches remote content (curl/wget piped to a shell, or a remote script as the server command). The config runs with the agent’s privileges.',
    explanationZh:
      '服务或 MCP 配置执行的命令会拉取远程内容（curl/wget 管道进 shell，或把远程脚本当作服务命令）。配置以智能体的权限运行。',
    appliesTo: 'config',
    match(file) {
      return regexHits(file.content, [PIPE_TO_SHELL, EXEC_FETCHED]);
    },
  },
  {
    id: 'MCP-2',
    severity: 'high',
    category: 'mcp-config',
    title: 'Hardcoded secret in a config file',
    titleZh: '配置文件里写死了密钥',
    explanation:
      'A config file contains a literal API key, token, secret or password value. Anyone who installs the skill gets the key — and the key owner never agreed to share it.',
    explanationZh:
      '配置文件里写死了一个真实的 API 密钥、token、secret 或密码值。装了这个技能的人都能拿到这把钥匙，而钥匙的主人并没有同意分享。',
    appliesTo: 'config',
    match(file) {
      const hits = [];
      const re = new RegExp(HARDCODED_SECRET.source, 'gi');
      let m;
      while ((m = re.exec(file.content)) !== null) {
        if (!PLACEHOLDER_VALUE.test(m[2])) {
          hits.push({ line: lineOf(file.content, m.index), snippet: snippetOf(file.content, m.index) });
        }
        if (m.index === re.lastIndex) re.lastIndex++;
      }
      return hits;
    },
  },
  {
    id: 'MCP-3',
    severity: 'medium',
    category: 'mcp-config',
    title: 'Overbroad tool permissions in frontmatter',
    titleZh: 'frontmatter 里给了过宽的工具权限',
    explanation:
      'The SKILL.md frontmatter grants wildcard tool access (Bash(*) or a bare *). Least privilege: list only the exact tools and commands the skill needs.',
    explanationZh:
      'SKILL.md 的 frontmatter 给了通配符工具权限（Bash(*) 或单独的 *）。最小权限原则：只列出技能真正需要的具体工具和命令。',
    appliesTo: 'docs',
    match(file) {
      if (!file.isSkillMd) return [];
      const fm = file.frontmatter || '';
      const m = fm.match(/allowed-tools\s*:\s*(.+)/i);
      if (!m) return [];
      const value = m[1];
      if (/Bash\(\*\)/.test(value) || /(^|\s)\*\s*(,|$)/.test(value)) {
        return [{ line: 1, snippet: 'allowed-tools: ' + value.trim() }];
      }
      return [];
    },
  },
  {
    id: 'SUP-1',
    severity: 'medium',
    category: 'supply-chain',
    title: 'Install script runs on package install',
    titleZh: '安装包时会自动运行脚本',
    explanation:
      'package.json has an install/preinstall/postinstall script, or the skill installs a package straight from a URL. Install-time scripts run with your privileges before you use anything.',
    explanationZh:
      'package.json 含有 install/preinstall/postinstall 脚本，或技能直接从 URL 安装包。安装时脚本会在你使用任何东西之前以你的权限运行。',
    appliesTo: 'all',
    match(file) {
      if (file.rel.endsWith('package.json')) {
        return regexHits(file.content, [/"(preinstall|install|postinstall)"\s*:/]);
      }
      return regexHits(file.content, [/pip\s+install\s+https?:\/\/\S+/, /npm\s+install\s+(git\+)?https?:\/\/\S+/]);
    },
  },
];

// ---------------------------------------------------------------------------
// Hygiene checks (severity "info", never change the score)
// ---------------------------------------------------------------------------

function hygieneChecks(skill) {
  const info = [];
  const skillMd = skill.files.find((f) => f.isSkillMd);
  if (!skillMd) {
    info.push({
      id: 'HYG-0',
      severity: 'info',
      category: 'hygiene',
      title: 'No SKILL.md found',
      titleZh: '没有找到 SKILL.md',
      explanation: 'This directory does not look like a skill: no SKILL.md file was found.',
      explanationZh: '这个目录看起来不像一个技能：没有找到 SKILL.md 文件。',
      file: '(skill root)',
      line: 0,
      snippet: '',
    });
    return info;
  }
  const fm = skillMd.frontmatter || '';
  if (!/^\s*name\s*:/m.test(fm)) {
    info.push({
      id: 'HYG-1', severity: 'info', category: 'hygiene',
      title: 'Frontmatter has no name',
      titleZh: 'frontmatter 缺少 name',
      explanation: 'SKILL.md frontmatter should declare a name (it defaults to the folder name).',
      explanationZh: 'SKILL.md 的 frontmatter 最好声明 name（默认取文件夹名）。',
      file: skillMd.rel, line: 1, snippet: '',
    });
  }
  if (!/^\s*description\s*:/m.test(fm)) {
    info.push({
      id: 'HYG-2', severity: 'info', category: 'hygiene',
      title: 'Frontmatter has no description',
      titleZh: 'frontmatter 缺少 description',
      explanation: 'The description is what the agent uses to decide when to load the skill. Without it the skill may never trigger.',
      explanationZh: 'description 是智能体决定何时加载技能的依据，没有它技能可能永远不会被触发。',
      file: skillMd.rel, line: 1, snippet: '',
    });
  }
  const nameMatch = fm.match(/^\s*name\s*:\s*["']?([A-Za-z0-9-]+)["']?/m);
  if (nameMatch && nameMatch[1] !== skill.name) {
    info.push({
      id: 'HYG-3', severity: 'info', category: 'hygiene',
      title: 'Frontmatter name does not match the folder name',
      titleZh: 'frontmatter 的 name 与文件夹名不一致',
      explanation: `Frontmatter says "${nameMatch[1]}" but the folder is "${skill.name}". The name must match the folder.`,
      explanationZh: `frontmatter 写的是 "${nameMatch[1]}"，文件夹却是 "${skill.name}"。name 必须与文件夹名一致。`,
      file: skillMd.rel, line: 1, snippet: '',
    });
  }
  return info;
}

module.exports = { RULES, hygieneChecks };
