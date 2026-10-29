# 仓库介绍素材（GitHub 用）

> 用途：创建仓库时填 About / Topics，并把 `README` 的开头直接换成下面的内容。
> 项目名：**VulnArena**（本地包名已改为 `vulnarena`）

---

## 1. About（仓库简介，一句话）

**中文（≤350 字，可直接粘贴）**

> 一个可自建、可复现的 AI 攻防靶场：内置一套企业级采购审批系统作为靶标，红队自动渗透、蓝队自动修复，全程可观测、可复盘、可跟练。规则上线前必须通过「召回 100% + 误杀 0%」的确定性闸门。

**English（如果想用英文 About）**

> A self-hostable AI red/blue arena: a realistic procurement backend as the target, an automated attacker and defender, and a deterministic gate that every generated WAF rule must pass before going live.

---

## 2. Topics（仓库标签）

```
cybersecurity  security-tools  penetration-testing  red-team  blue-team
waf  llm  ai-agents  fastapi  python  postgresql  redis  security-education
vulnerability  ethical-hacking  labs  pytest  asyncio
```

（GitHub 最多 20 个标签；上面这串够用，可按需删减。）

---

## 3. README 开头（中文，可直接替换现有第一段）

```markdown
# VulnArena

> 一个能「打」也能「学」的 AI 攻防靶场：企业级业务系统 + 自动红队 + 自动蓝队 +
> 规则闸门 + 跟练与复盘。

**它解决什么问题**：大多数靶场是「一堆预设漏洞」，打完不知道自己在干什么；
而 LLM 生成的安全规则看起来很美，上线却会误杀真实业务。VulnArena 把这两件事接起来——
红队按 kill chain 真打，蓝队给出的每条规则都要过确定性闸门，最后用「攻击全拦 + 正常全放」
双向回归来验收。

## 它长什么样

| 模块 | 说明 |
|---|---|
| **情报台**（Vue 3） | NVD 漏洞同步、检索、详情：知识的入口 |
| **靶场前台**（服务端渲染） | 一套真的能登录、能审批的采购系统，浏览器里就能被攻击 |
| **观战台** | 红蓝时间线、实时 trace、修复 diff、跟练脚本、复盘 |
| **靶场管理台** `/lab` | 靶标清单、关卡进度、段位、一键开演 |
| **AI 红队** | DeepSeek 从动作目录里挑选并排序攻击步骤（可降级为确定性链） |
| **AI 蓝队** | 生成 WAF 规则 → 过闸门 → 立即生效；拦不住的类别明确说「只能改代码」 |

## 三个关键设计

1. **LLM 提议，确定性裁决**：模型只负责提议，规则必须通过 5 项检查
   （可编译、长度、反回溯、攻击召回 100%、正常流量误杀 0%）才会生效。
2. **承认网关的边界**：路径穿越与越权在网关层无法可靠区分（正常备注里也会出现 `../`），
   所以这两类被判定为「只能改代码」，并在修复 diff 里给出对照。
3. **判据是攻击的副作用**：canary 是否泄露、数据库状态是否被改，而不是提交一个 flag 字符串。

## 快速开始

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e '.[dev]'
cp .env.example .env                               # 填数据库/Redis，可选填 DeepSeek Key
uvicorn vulnarena.main:app --host 127.0.0.1 --port 8000
```

打开：

- `/` 情报台　- `/lab` 靶场管理　- `/arena` 观战台　- `/api/procure/ui/login` 靶场前台
- 一条命令跑完整个闭环：`python scripts/arena_demo.py`

## 免责声明

本项目是**教学与自测用的内存沙盒**：所有"漏洞"都在进程内的 SQLite / 虚拟文件系统里，
SSRF 只打进程内虚拟网络，不连接任何外部目标，也不需要授权攻击任何真实系统。
```
```

---

## 4. 建议补充（建仓后）

| 项 | 说明 |
|---|---|
| `LICENSE` | 个人作品集建议 **MIT**；想限制商用可选 **AGPL-3.0** |
| 截图 | `/lab`、`/arena`、`/api/procure/ui/pos` 各一张，放 README 顶部 |
| CI 徽章 | `![CI](https://github.com/<user>/<repo>/actions/workflows/ci.yml/badge.svg)` |
| 演示 | 90 秒录屏（Lab → 开始演练 → 观战 → 跟练 → 靶场前台越权） |
| 文档索引 | `docs/SYSTEM-DESIGN.md`、`docs/RANGE-DESIGN.md` 在 README 里给链接 |

## 5. 提交前自查

- `.env` 与 `.tools/`、`data/`、`verification/` 已在 `.gitignore`
- **DeepSeek Key 只在本地 `.env`，绝不提交**
- CI 里没有 Key，走确定性降级路径，测试照样全绿
