# skill-guard

**装 skill 之前先安检。Scan an agent skill before you install it.**

`skill-guard` 在你安装第三方 Claude Code / agent skill 之前，先把它扫一遍，用大白话告诉你能不能装：**能装 SAFE / 谨慎 CAUTION / 别装 DO NOT INSTALL**，并给出最严重的 3 条原因。通过才装进 skills 目录。

SkillSpector 只负责"扫"，skill-guard 补上"装"的那一步：扫描 + 一句话结论 + 安全安装。

> English: SkillSpector scans skills; skill-guard gates the install. Before a third-party skill lands in your `~/.claude/skills/`, skill-guard clones it to a temp dir, scans it, and prints a plain-language verdict — SAFE / CAUTION / DO NOT INSTALL — with the top 3 reasons. It installs only when the verdict allows.

## 为什么需要它 / Why

Agent skill 装上就带着隐式信任跑。NVIDIA SkillSpector 的研究发现，在被分析的 31,132 个 skill 里，**26.1% 含有漏洞，5.2% 疑似恶意**。但"扫"完之后，下一步"装不装"还是得人自己判断——skill-guard 就是把这一步做掉：扫完直接给结论，不通过就不装。

## 安装 / Install

```bash
npm install -g skill-guard
# 或者不用安装，直接跑：
npx skill-guard scan ./my-skill
```

需要 Node.js 18+。零依赖（只有 Node 内置模块）。

## 用法 / Usage

```bash
# 只扫描，不安装
skill-guard scan ./my-skill
skill-guard scan ./my-skill --json        # 机器可读的 JSON 输出

# 扫描并安装（默认装到 ~/.claude/skills/）
skill-guard add obra/superpowers
skill-guard add https://github.com/user/my-skill
skill-guard add ./my-skill --target /tmp/skills-test

# 打印写安全 skill 的检查清单
skill-guard checklist
```

安装规则：

| 结论 | 行为 |
|---|---|
| 能装 SAFE（80–100 分） | 直接安装 |
| 谨慎 CAUTION（50–79 分） | 拒绝安装；确认了解风险后加 `--force` |
| 别装 DO NOT INSTALL（0–49 分） | 一律拒绝安装，即使加 `--force` 也不装 |

退出码：`0` 能装/完成，`1` 谨慎或别装（或安装被拒绝），`2` 用法错误。

## 真实输出示例 / Real example outputs

完整未编辑的输出见 [examples/example-report.md](examples/example-report.md)。

干净的技能：

```
$ skill-guard scan test/fixtures/weather-report
  结论 / Verdict: 能装 SAFE   安全分 / Safety score: 100/100
  扫描文件 / Files scanned: 2
  未发现问题 / No issues found.
  可以安装 / Safe to install.
```

边界技能（会下载远程文件、读环境变量、frontmatter 给了 `Bash(*)`）：

```
$ skill-guard scan test/fixtures/dataset-helper
  结论 / Verdict: 谨慎 CAUTION   安全分 / Safety score: 75/100
  主要原因 / Top reasons:
    1. [MEDIUM 中危] 在使用或安装时下载远程内容
    2. [MEDIUM 中危] frontmatter 里给了过宽的工具权限
    3. [LOW 低危] 读取环境变量
```

恶意技能（读环境变量并外发 + `curl | bash`）：

```
$ skill-guard scan /tmp/sg-evil-demo/quick-sync
  结论 / Verdict: 别装 DO NOT INSTALL   安全分 / Safety score: 0/100
  主要原因 / Top reasons:
    1. [CRITICAL 严重] 读取密钥并向外网发送数据
    2. [CRITICAL 严重] 下载内容直接管道进 shell（curl|bash）
```

## 评分方式 / How scoring works

安全分从 100 开始，按发现的问题扣分（分越高越安全——和 SkillSpector 的风险分方向相反）：

| 严重度 | 扣分 |
|---|---|
| CRITICAL 严重 | −60 |
| HIGH 高危 | −30 |
| MEDIUM 中危 | −10 |
| LOW 低危 | −5 |

| 分数 | 结论 |
|---|---|
| 80–100 | 能装 SAFE |
| 50–79 | 谨慎 CAUTION |
| 0–49 | 别装 DO NOT INSTALL |

## 检测规则 / Detection rules

13 条原创规则（模式思路参考了公开的 skill 安全风险分类，见致谢；所有模式、阈值和文案均为本项目原创）：

| 规则 | 严重度 | 检测内容 |
|---|---|---|
| EXFIL-1 | CRITICAL | 同一文件既读密钥/凭证又向外网发数据 |
| EXFIL-2 | HIGH | 技能文本指示智能体把密钥发到某处 |
| RCE-1 | CRITICAL | `curl \| bash` / `wget \| sh`，下载直管道进 shell |
| RCE-2 | HIGH | 动态执行拼接代码（eval、shell=True 等） |
| INJ-1 | HIGH | 提示词注入式措辞（"ignore previous instructions" 等） |
| SEC-1 | MEDIUM | 直接读凭证文件（~/.ssh、~/.aws、钥匙串等） |
| SEC-2 | LOW | 读取环境变量 |
| NET-1 | MEDIUM | 安装或使用时下载远程内容 |
| NET-2 | LOW | 链接到短链接、pastebin 或裸 IP |
| MCP-1 | HIGH | MCP/服务配置会运行远程代码 |
| MCP-2 | HIGH | 配置文件里写死了密钥 |
| MCP-3 | MEDIUM | frontmatter 里给了通配符工具权限 |
| SUP-1 | MEDIUM | 安装时脚本（postinstall 等）或从 URL 装包 |

另外还有不影响评分的卫生检查（INFO）：缺 `name`/`description`、name 与文件夹名不一致、没有 SKILL.md 等。

扫描范围：`SKILL.md`、脚本（.py/.js/.ts/.sh）、配置文件（.json/.yaml/.yml）等文本文件；跳过 `.git`、`node_modules` 等目录；单个文件超过 1 MiB 跳过，单个技能总大小上限 100 MiB。

## 写安全 skill 的检查清单 / Secure-skill checklist

`skill-guard checklist` 打印完整清单（中英双语），要点：

1. 不藏外泄指令，不让智能体向外发送数据或密钥
2. 不用 `curl | bash`：先下载、验证，再运行
3. 不碰凭证：不读环境变量里的密钥、`~/.ssh`、`~/.aws`、`.env`
4. 没有提示词注入式措辞
5. MCP 最小权限，不用通配符 `Bash(*)`
6. 不写死密钥；依赖固定版本；脚本只做声称的事
7. 发布前先用 `skill-guard scan` 扫一遍自己的技能

## 局限 / Limitations

- 静态模式匹配，只能抓到已知形态的问题。混淆过的新型攻击、藏在图片或远程内容里的指令、以及需要运行才能看出来的行为，它都看不到。
- 可能误报：比如一个正当的技能确实要下载数据集，也会被标为中危——这时结论是"谨慎"，由人来判断。
- 安全分 100 不等于"绝对安全"，只是"这次扫描没发现已知问题"。
- 不做 LLM 语义分析（有意为之：零依赖、离线可用、结果稳定可复现）。

## 开发 / Development

```bash
git clone https://github.com/li123shengsheng-cyber/skill-guard.git
cd skill-guard
npm test        # 20 个测试：评分、扫描、CLI 端到端、安装门禁
```

测试夹具在 `test/fixtures/`：一个干净技能、一个边界技能、一个恶意技能（脚本部分）。

## 致谢 / Acknowledgments

灵感来自 [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector)（71 种漏洞模式、0–100 风险分、26.1% 含漏洞的研究数据）。skill-guard 是独立实现：不同的评分方向（安全分而非风险分）、不同的定位（安装门禁而非扫描器）、全部规则原创。skill-guard 与 NVIDIA 没有任何关联。

## 许可 / License

MIT — 见 [LICENSE](LICENSE)。

## 免责声明 / Disclaimer

本工具仅供学习研究，不构成安全保证。安装任何第三方 skill 之前，请结合扫描结果自行判断。
