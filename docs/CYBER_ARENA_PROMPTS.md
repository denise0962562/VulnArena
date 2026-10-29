# VulnArena · AI Cyber Arena 提示词套件

> 用途：在你现有 VulnArena 仓库上，分四个里程碑增量构建「企业门户靶场 + 自适应 WAF + LLM 红蓝闭环」。
> 定位：**纯内存、只打自己、产出是检测规则和修复 diff** 的攻防演练场，兼求职作品。

---

## 0. 怎么用（30 秒）

1. 把 **P0** 整段存成仓库根目录的 `AGENTS.md`（DSH / Claude Code / Cursor 都会自动读）。
2. 每个里程碑**开一个新会话**，只贴对应的 **Pn**；AI 会自动带上 P0 的约束。
3. 每个 Pn 结尾都有「验收命令」，**跑绿了再进下一个里程碑**。没绿就贴附录 A 的追问模板。
4. 一次只做一个里程碑。AI 主动想多做，直接回："先只做 Pn 范围内的，其余写进 PLAN.md。"

**为什么这样拆：** 一份 3000 字的巨型提示词会让模型自己挑一半实现、另一半留 TODO，而且失败时你无法定位是理解的错还是实现的错。拆成四个可独立验收的里程碑后，每一步都有确定的"完成"标准。

| 里程碑 | 内容 | 关键交付 | 预估 |
|---|---|---|---|
| **M0** | 企业门户靶场（4 路由 / 5 开关 / canary） | 能 curl 通的业务系统 + 8 个测试 | 1 天 |
| **M1** | WAF 网关 + **确定性**攻击链（不接 AI） | 探测→403→变形→拿到 canary→热规则→重放全 403 / 正常全 200 | 1 个周末 |
| **M2** | DeepSeek 三 Agent 替换确定性脚本 | 真 LLM 驱动，且不 flaky（失败自动降级） | 1 个周末 |
| **M3** | 直播、报告、README、视频 | 面试材料 | 半天 |

**M1 结束就已经可以投简历了。** M2 只是把大脑换掉，不是前提。

---

## 里程碑与验收总览

| | M0 | M1 | M2 | M3 |
|---|---|---|---|---|
| 新增包 | `vulnarena/portal/` | `vulnarena/arena/`（policy/middleware/attacker） | `vulnarena/arena/`（deepseek/agents） | — |
| 新增表 | 无（内存） | 无 | `arena_reports` | — |
| 外部依赖 | 无 | 无 | DeepSeek API | 无 |
| 必须离线可跑 | ✅ | ✅ | ✅（fallback 路径） | ✅ |

---

## P0 · 项目宪法（每次会话必贴 / 存成 `AGENTS.md`）

```text
你是资深 Python 3.12 后端架构师 + 应用安全工程师。我们在既有项目 VulnArena 上做增量开发，
不是重写。先读懂现有代码的约定，再动手。

# 一、现状（我已确认，不要重新猜）
仓库：仓库根目录，包名 vulnarena，Python 3.12。
- config.py   Settings(BaseSettings)，env_prefix="VULNARENA_"，密钥一律 SecretStr，
              有 model_validator 做跨字段校验
- schemas.py  Pydantic v2 契约：AwareDatetime、StrEnum、ConfigDict(from_attributes=True / extra="forbid")
- db.py       SQLAlchemy 2.0 AsyncSession + asyncpg；Base(DeclarativeBase)；
              UTCDateTime(TypeDecorator)；JSONB 列；Database 提供
              initialize/upsert/get/list_from_session/aclose，读用 REPEATABLE READ + READ ONLY
- state.py    TaskStore：Redis Lua 原子租约（全局单键 vulnarena:sync:active），
              create/save/release/get/heartbeat，LeaseLost / TaskBusy 异常
- service.py  SyncService：asyncio.create_task 并发 heartbeat + work，
              asyncio.timeout 包裹，finally 里取消子任务并释放租约
- nvd.py      上游适配器：指数退避 1/2/4s，只对 429/5xx/网络错重试，
              解析 Retry-After 且 >120s 直接失败，transport 可注入以便测试
- main.py     create_app(settings, *, redis=None, nvd=None)，依赖挂 app.state.{db,store,sync}；
              StaticFiles 最后 mount（API 路由必须先注册）
- tests/      pytest-asyncio asyncio_mode=auto；conftest 有 block_network（禁非本机 socket）、
              fakeredis(lua)、httpx.MockTransport、随机 schema 的 PostgreSQL fixture

# 二、工程规范（硬约束）
1. 全量类型注解；ruff，line-length=100，规则集 E,F,I,UP,B,ASYNC；ruff format 通过。
2. 代码内注释与 docstring 用英文短句（与现有文件一致）；README 与 docs 用中文。
3. 零新增第三方依赖。确实需要时先停下来问我，并说明为什么标准库做不到。
4. 新增模块必须可注入：transport / redis / clock / sleep / settings 一律从构造函数传入，
   测试必须能在完全离线（无 Redis、无 DeepSeek、无网络）下跑通。
5. 不得破坏既有契约：vulnerabilities 表结构、/api/sync 语义、vulnarena:sync:active 键、
   现有测试、pyproject 里 80% 覆盖率门禁（不许下调）。
6. 不得使用 eval / exec / os.system / subprocess / pickle / importlib 动态导入；
   不得访问真实文件系统路径、不得发起真实外网请求；所有"敏感数据"必须是 canary 字符串。
7. 不写 TODO、不写空实现、不写"简化版"；禁止裸 except 和 except: pass；
   禁止为了让测试变绿而修改已有断言。

# 三、交互动词
- 第一步永远只输出：变更计划 + 目标文件树 + 接口契约表 + 测试清单，等我确认再写代码。
- 写代码时按"契约 → 实现 → 测试"顺序，一次给一个文件，不要一次吐 2000 行。
- 每个里程碑结束给：`ruff` / `pytest` 的准确命令 + 预期输出（通过的用例数）。
- 做不到的设计，直接回「做不了 + 原因 + 替代方案」，不要静默降级成假实现。

# 四、这个项目是什么
一个纯内存的企业门户靶场 + 可热更新的 WAF + LLM 驱动的红蓝闭环。
被攻击对象只有本项目自己的内存沙盒，没有任何外部目标；
红队的产出用来喂蓝队，蓝队的产出是**可验证的检测规则和修复 diff**。
所有"机密数据"都是 canary 标记，泄露与否可被程序断言。
```

---

## P1 · M0：企业门户靶场

```text
【里程碑 M0】实现企业内部门户靶场，不涉及 AI、不涉及 WAF。做完必须能 curl 通、测试全绿。

# 目标
新建包 vulnarena/portal/，挂载为子应用 /api/portal/*，是一套"看起来很正经"的企业内部系统：
员工登录、工单检索、报表导出、Webhook 连通性测试。
它同时内置 5 个"可开关的脆弱点"，但：每个脆弱点都必须能在"可被利用"和"已修复"两种状态间切换，
且两种状态的所有业务逻辑都能跑通。

# 目录（可按职责合并，但单文件不超过 250 行）
vulnarena/portal/__init__.py     导出 build_portal_app
vulnarena/portal/state.py        PortalState：sqlite 连接、虚拟文件系统、canary、开关字典
vulnarena/portal/seed.py         确定性种子数据（固定随机种子）
vulnarena/portal/auth.py         HMAC 签名 token（issue / verify / jti）
vulnarena/portal/routes.py       4 个业务路由

# 接口契约（响应一律 Pydantic 模型，禁止裸 dict）
POST /api/portal/login
  body: {"username": str, "password": str}
  200: {"token": str, "role": "employee"|"exec", "tenant_id": str, "expires_in": int}
  401: {"detail": "invalid credentials"}

GET /api/portal/tickets?q=&page=1&page_size=10        Authorization: Bearer <token>
  200: {"total": int, "page": int, "page_size": int, "items": [{id, title, status, created_at}]}
  只返回本租户、且本人可见的工单；响应体中不得出现 canary

GET /api/portal/tickets/{ticket_id}
  200: {"id": int, "title": str, "body": str, "owner_id": str, "visibility": "normal"|"exec"}
  404 / 403 按权限语义返回

GET /api/portal/exports?name=<报表文件名>
  200: text/csv（Content-Disposition 带上文件名）
  404: 文件不存在

POST /api/portal/webhooks/test
  body: {"target_url": str}
  200: {"status": int, "elapsed_ms": int, "preview": str[:200]}

# 数据（seed，固定种子，每次启动完全一致）
- 3 个用户：alice(employee, tenant=T1) / bob(employee, T1) / admin(exec, T1)，密码只在内存里哈希比对
- 12 条工单，其中 2 条 visibility="exec"、owner_id="admin"，body 内含 canary_flag
- 隐藏表 flag_vault(secret TEXT)，只应被 UNION 注入读到
- 虚拟文件系统 dict：/etc/portal/secret_key（含 canary）、3 个正常报表 CSV
- 模拟元数据服务：一个独立的内存 ASGI app，GET /latest/meta-data/iam/security-credentials/
  返回含 canary 的 JSON（详见下方"SSRF 红线"）

# 五个脆弱开关（dict[VulnSwitch, bool] + dict[VulnSwitch, bool] patched）
STR 枚举命名：
  SQLI_LOGIN_BYPASS    登录处拼接 SQL        | 修复：参数化绑定
  SQLI_UNION_SEARCH    搜索处拼接 LIKE       | 修复：参数化 + LIKE 转义 + ESCAPE
  IDOR_TICKET_DETAIL   详情不校验 owner      | 修复：WHERE owner_id = ?
  PATH_TRAVERSAL       导出未过滤 ../        | 修复：Path(name).name + 白名单
  SSRF_INTERNAL_PROBE  未校验 host 即发包    | 修复：scheme/host 白名单 + 拒绝 169.254/内网段

两种状态的行为差异必须写进 docstring，例如：
  脆弱：  f"SELECT ... FROM tickets WHERE title LIKE '%{q}%'"
  修复：  "SELECT ... FROM tickets WHERE title LIKE ? ESCAPE '\\'"，参数 (f"%{escaped}%",)
"脆弱"分支只允许拼接进内存 SQLite 的 SQL 字符串，禁止任何 shell / 文件 / 反序列化路径。

# 实现红线
1. SQLite 用 sqlite3.connect(":memory:")，但：
   - 一个 PortalState 持有一个连接，跨请求共享；所有查询用 asyncio.to_thread + 单把 asyncio.Lock 串行化；
   - 禁止在 async 函数里直接同步调用 sqlite3（会阻塞事件循环）；
   - 建表与 seed 在构造函数里一次完成。
2. 路径穿越只针对虚拟文件系统 dict，禁止 import os 后真的 open()。
3. SSRF 出网口必须焊死：portal 内部只有一个 httpx.AsyncClient，
   transport 固定为 ASGITransport(app=metadata_app)，base_url 固定为 http://169.254.169.254；
   调用前校验 target_url 只能是这个 base 下的路径，其余一律拒绝并记录。
   绝不允许把用户传入的 URL 直接交给 httpx 或任何 DNS 解析。
4. token：HMAC-SHA256(secret, payload)，payload 含 sub/role/tenant/jti/exp；
   exp 15 分钟；校验失败统一 401，不区分"过期"和"伪造"。
5. 每次请求的敏感响应必须能自证：命中脆弱点才带 canary，修复态不带。

# 依赖注入
main.py 的 create_app 增加关键字参数 portal=None；为 None 时按 settings 构建；
测试里传自定义 portal 子应用，挂载位置必须在 StaticFiles mount 之前。

# 测试（tests/test_portal.py，必须离线可跑）
1. 正常登录 → 拿 token → 查自己的工单 → 200 且响应不含 canary
2. 错误密码 → 401
3. SQLI_LOGIN_BYPASS 开：' OR '1'='1 拿到 exec token；关：401
4. SQLI_UNION_SEARCH 开：UNION 读到 flag_vault 的 canary；关：查不到 / 语法错误被捕获为 400
   （关的时候不允许抛未捕获的 sqlite3.OperationalError）
5. IDOR 开：bob 读 admin 的 exec 工单 200 + canary；关：403
6. PATH_TRAVERSAL 开：name=../../etc/portal/secret_key 读到 canary；关：400/404
7. SSRF 开：target_url 指向元数据端点拿到含 canary 的 JSON；关：403
8. 五个开关全关时，上述 4 条正常业务流全部 200（防止修复态把业务打死）

# 验收
.\.venv\Scripts\python -m ruff check .
.\.venv\Scripts\python -m ruff format --check .
.\.venv\Scripts\python -m pytest tests/test_portal.py -q
跑完给我 curl 示例，我要能手动复现上面每一条。
```

---

## P2 · M1：WAF 网关 + 确定性攻击链（**不接 AI**）

```text
【里程碑 M1】在 M0 之上加三层：可热更新的 WAF 中间件、规则准入闸门、确定性四步攻击链。
本里程碑禁止调用任何大模型——先让闭环在离线环境下 100% 稳定跑通，AI 是下一阶段的事。

# 目录
vulnarena/arena/__init__.py
vulnarena/arena/policy.py      WafPolicy / WafRule 模型 + PolicyStore（Redis + 进程内缓存）
vulnarena/arena/gate.py        verify_rule：规则准入闸门
vulnarena/arena/corpus.py      attack_corpus / benign_corpus 两组样本
vulnarena/arena/middleware.py  WafMiddleware
vulnarena/arena/attacker.py    DeterministicAttacker：四步攻击链
vulnarena/arena/defender.py    TemplateDefender：从 trace 生成规则与修复 diff
vulnarena/arena/replay.py      回归重放与双向断言

# 1. 数据模型（schemas 放 policy.py，不进全局 schemas.py）
class WafRule(BaseModel):
    id: str                      # "R-<8 hex>"
    regex: str
    targets: set[Literal["query","path","body","header"]]
    rationale: str               # 一句话，给战报用
    source: Literal["llm","template","manual"]
    created_at: AwareDatetime

class WafPolicy(BaseModel):
    session_id: str
    version: int                 # Redis INCR，单调递增
    blocked_patterns: list[WafRule] = []
    revoked_tokens: list[str] = []      # 存 jti，精确匹配，不许用正则
    patch_switches: dict[str, bool] = {}  # 5 个开关的"代码级修复态"
    max_body_bytes: int = 65536

# 2. PolicyStore
- Redis 键：vulnarena:arena:policy:{session_id}（整份 JSON，EX 1h）
- 进程内缓存：{session_id: (policy, monotonic_ts)}，TTL 1.0s；
  命中直接返回，未命中才读 Redis。Redis 挂了必须降级为"最近一次快照"，
  绝不允许 500 或者让靶场整体不可用（可以放行 + 记 warning，但要在响应头 X-Waf-Degraded: 1 标出来）。
- 与 state.py 的 TaskStore 完全隔离：不得复用 vulnarena:sync:active 这个键。

# 3. WafMiddleware（挂在 portal 子应用上，不进 create_app 全局中间件）
处理顺序固定为：
  a. 取 X-Arena-Session 头；缺失 → 400 {"detail":"arena session required"}
  b. 取 policy 快照（走 1s 缓存）
  c. body 超过 max_body_bytes → 413
  d. token 吊销检查：解出 jti，命中 revoked_tokens → 403 {"detail":"token revoked","code":"TOKEN_REVOKED"}
  e. 构造检测用的规范化载荷：
     raw = path + "?" + query + "|" + body 原文
     norm = 二次 URL 解码 → 去 SQL 注释符 → 折叠连续空白 → 小写
     注意：正则同时跑 raw 和 norm，任一命中即拦截（防编码绕过），
     但闸门会保证规则不误伤 benign_corpus，两者必须同时成立。
  f. 逐条 regex.search(targets 范围内的串)；命中 → 403
     {"detail":"blocked by waf","rule_id": rule.id}
  g. 无论放行还是拦截，都往 Redis list vulnarena:arena:events:{session_id} 追加一条 WafEvent
     {ts, path, method, decision, rule_id, payload_preview[:200], client_jti}，LPUSH + LTRIM 200
     —— 这是 Stage 3 蓝队审计的输入，必须是真实抓包，不许事后编造。

# 4. 规则准入闸门 gate.verify_rule(rule) -> GateResult（本项目最核心的一段代码）
五项检查，全部通过才允许写进 Redis：
  1. 可编译：re.compile 不抛异常
  2. 长度：len(regex) <= 300
  3. 反回溯：拒绝嵌套量词形态（如 (a+)+ / (.*)* / (a|a)*），
     并对每个样本在 4KB 输入上跑 re.search，用 asyncio.wait_for(asyncio.to_thread(...), 0.05) 限时
  4. 召回：必须命中 attack_corpus 里该漏洞类别的全部样本（>=3 条）
  5. 误杀：必须不命中 benign_corpus 的任意一条（>=12 条）
返回 GateResult{passed: bool, failed: list[str], recall: float, false_positive: float}

# 5. 语料（corpus.py，硬编码，必须含这些坑）
attack_corpus 每类 >= 3 条，覆盖：单引号闭合、UNION SELECT、注释截断 (-- / #)、大小写混写、
  双重 URL 编码、内联注释 /*!*/、../ 与 ..\ 与 URL 编码的 %2e%2e%2f、169.254.169.254 的十进制/十六进制写法
benign_corpus 12 条，必须包含这些"看起来像攻击"的合法值：
  O'Brien 的工单标题、字段名 "ticket's status"、搜索词 "100%"、"a+b"、文件名 report-2026Q3.csv、
  正常 URL 里带 & 和中文、备注里写 "1=1 这个公式"、正文里的 "select" 英文单词（作为普通名词）
  —— 这些是面试时最有说服力的部分：证明规则不是靠"看到 select 就拦"。

# 6. 确定性攻击链（attacker.py）
四步固定剧本，每步都返回 ProbeTrace（请求摘要、状态码、耗时 ms、命中规则、是否拿到 canary、一句话 reasoning）：
  Step 1 探测：GET /api/portal/tickets?q=test → 200，确认接口存在
  Step 2 朴素攻击：q=' UNION SELECT secret FROM flag_vault-- → 被初始规则 403（记录 rule_id）
  Step 3 变形绕过：同一语义，换大小写 + 内联注释 + 二次编码 → 200 且响应含 canary → BREACH_CONFIRMED
  Step 4 横向：用 bob 的 token 遍历 ticket_id 读到 admin 的 exec 工单 → 200 + canary
若 Step 3 在 3 次变形内仍未成功，返回 BREACH_FAILED 并在报告里如实记录（不许伪造成功）。

# 7. 模板蓝队（defender.py）
输入：四条 trace + 当前 policy。输出 DefensePatch：
  - waf_rule：从漏洞类别选模板（如 SQLi → 匹配 UNION\s+SELECT 与单引号闭合的组合；
    IDOR → 匹配连续数字 id 的异常枚举），交给 gate.verify_rule 校验；
    不通过则缩窄规则重试一次，仍不过就用"该路径 + 该参数名"的保守白名单规则兜底，并把 source 标成 template
  - patch_switches：把对应开关的修复态置 True
  - diff：用 difflib.unified_diff 渲染"脆弱实现 → 修复实现"的真实两段代码
    （两段代码从 templates/ 里取，是真实能跑的 Python，不是伪代码）
  - rationale：一句话说明"为什么这条规则既拦得住又不误杀"

# 8. 回归（replay.py）
- 重放 Step 2/3/4 的原始请求 → 断言全部 403（任何一条 200 即 REGRESSION_FAILED，并指出哪条漏了）
- 重放 benign_corpus 12 条 → 断言全部 200 且响应体不含 canary、不触发 X-Waf-Degraded
- 输出结构化的 RegressionResult{blocked: n, allowed: n, missed: [...], false_positives: [...]}

# 测试（tests/test_arena_policy.py / test_arena_loop.py）
1. verify_rule 拒绝：(a+)+ 回溯型、超长正则、召回不足、误杀 benign 的"select"规则
2. verify_rule 通过：一条精确规则，断言 recall==1.0 且 false_positive==0.0
3. 中间件：无 X-Arena-Session → 400；吊销 token → 403；正常请求放行
4. policy 进程内缓存：连发两次，第二次不得再访问 Redis（用 mock 计数断言）
5. Redis 故障 → 请求仍能完成，且响应头带 X-Waf-Degraded
6. 四步链端到端：Step2 403、Step3 200+canary、Step4 200+canary
7. 完整闭环：attack → patch → replay，断言 blocked==3 且 false_positives==0
8. 失败路径：把 Step 3 的变形全部改成无害 payload，断言结果是 BREACH_FAILED 而不是崩

# 验收
.\.venv\Scripts\python -m pytest tests/test_arena_policy.py tests/test_arena_loop.py -q
并给出一条命令，让我能本地跑完整闭环并打印时间线（scripts/arena_demo.py）。
```

---

## P3 · M2：DeepSeek 三 Agent

```text
【里程碑 M2】把 M1 的确定性攻击/防守替换成 DeepSeek 驱动的三个 Agent。
硬要求：任何失败都必须降级回 M1 的确定性路径，报告里标明 agent_mode = "llm" | "fallback"。
整个测试套件在无 API Key 环境下必须 100% 通过。

# 新增配置（config.py）
deepseek_api_key: SecretStr = SecretStr("")
deepseek_base_url: str = "https://api.deepseek.com"
deepseek_model: str = "deepseek-chat"
arena_timeout: float = Field(default=180.0, gt=10.0, le=600.0)
arena_max_llm_calls: int = Field(default=12, ge=0, le=50)
arena_max_turns: int = Field(default=3, ge=1, le=4)
arena_token_budget: int = Field(default=60000, ge=1000)
在 model_validator 里加：若配置了 key，则 base_url 必须 https。
（注意现有 validator 已校验 nvd_interval / task_ttl / database_url，别破坏它们）

# 1. DeepSeekClient（vulnarena/arena/deepseek.py）
- 参考 nvd.py 的写法：构造函数接收 settings + transport + sleep，重试 429/5xx，
  指数退避 1/2/4s，解析 Retry-After 且 >120s 直接失败，不重试 4xx
- 请求体：{"model":…, "messages":[…], "response_format":{"type":"json_object"},
          "temperature":0.2, "max_tokens":…}
  注意：json_object 模式要求提示词里必须出现 "json" 字样，否则 API 直接报错——
  三个 agent 的 system prompt 里都必须显式写"只输出 json"
- 解析：先 json.loads，再 Model.model_validate；
  校验失败时把 pydantic 的 errors() 摘要回喂给模型，允许重试 1 次；
  二次失败抛 AgentContractError，由上层降级
- 记账：每次调用记录 prompt_tokens / completion_tokens / 耗时 / stage，
  累计超过 arena_max_llm_calls 或 arena_token_budget 立即停止调用并降级
- 禁止把 API Key 写进日志、异常信息或报告

# 2. 三个 Agent 的契约（schemas 放 agents.py，Pydantic v2，extra="forbid"）
ScenarioArchitect：
  输入：可选 cve_id + 真实 CVE 描述（从 db.get 拿，没有就只用类别）
  输出 ArenaBlueprint{business_scene, category: VulnCategory, param_schema: dict,
                     baseline: dict, initial_blacklist: list[str], canary: str, difficulty: Literal["easy","medium","hard"]}
  约束：只允许在 M0 已有的 5 个脆弱点上做组合，不得发明新路由；initial_blacklist 由模型生成但必须过 gate 的"召回"检查

SecurityProber：
  输入：目标接口清单（method/path/参数名/正常值）+ 上一轮 trace 摘要（去掉 canary 明文，用 CANARY_HIT 代替）
  输出 ProbeTurn{reasoning: str, request: HttpSpec, verdict: Literal["blocked","breach","normal","need_more"]}
  HttpSpec{method, path, query: dict[str,str], body: dict|None, headers: dict[str,str]}
  约束：path 必须在 /api/portal/* 白名单内，method 只能是 GET/POST；
        生成后由代码侧校验，越界直接拒绝并记一条 violation（这本身是很好的评测数据）

BlueDefender：
  输入：四条 trace + 命中的规则 + 当前 policy
  输出 DefensePatch{rule: WafRuleSpec|None, fix: FixKind, rationale: str, confidence: float}
  WafRuleSpec{regex, targets}
  FixKind 是枚举（PARAMETERIZED_SQL / OWNER_CHECK / PATH_WHITELIST / SSRF_ALLOWLIST），
  只是一个"选哪个修复模板"的开关——diff 由模板渲染，不让模型自由写代码。
  —— 这条很关键：模型输出的正则必须过 gate，模型选的修复必须是我们预置的真实代码。

# 3. 编排（orchestrator.py）
ArenaStatus 枚举：CREATED → BLUEPRINT_READY → PROBING → BREACH_CONFIRMED | BREACH_FAILED
                  → PATCHING → VERIFYING → VERIFIED | REGRESSION_FAILED
每推进一步：更新 Redis 里的 ArenaSession（vulnarena:arena:session:{id}，EX 1h），
并把该步的 ProbeTrace / DefensePatch 追加进去。前端靠 1s 轮询。
租约：复用 state.py 的 Lua 模式，但键换成 vulnarena:arena:lock，且按 session_id 分锁（允许并发多场演练）。
心跳：照抄 SyncService 的 heartbeat 模式，续租失败即取消并标记 INTERRUPTED。

# 4. 降级矩阵（必须实现）
- 无 key → 全程 fallback（M1 的确定性实现），agent_mode="fallback"
- 首次调用即 401/403 → 立刻 fallback，并记 error_code（不要重试烧钱）
- 连续 2 次 JSON 校验失败 → fallback
- 预算耗尽 → 在当前位置 fallback 继续，不中断整场演练
- Stage 3 的规则被 gate 打回 2 次 → 用模板规则兜底，source="template"
任何 fallback 都要在最终报告的 warnings 里写清原因，禁止静默。

# 5. 测试（tests/test_arena_agents.py，全部用 httpx.MockTransport）
1. 正常 JSON → ArenaBlueprint 解析成功
2. 缺字段 JSON → 触发一次修复重试 → 第二次正常 → 成功（断言共 2 次请求）
3. 连续畸形 JSON → 抛 AgentContractError → 编排降级到 fallback 且最终 VERIFIED
4. 429 响应 → 按 1/2/4s 退避重试（用 mock clock 断言等待序列，参考 test_nvd.py 的 Clock）
5. 返回 500 三次 → 抛上游错误 → 降级
6. 无 key → 断言一次 HTTP 调用都没发生（mock 计数 == 0），闭环仍然跑完
7. prober 返回 path=/admin → 被代码侧拒绝，记 violation，不产生实际请求
8. 预算耗尽 → 后续不再调用模型，但演练走完全程

# 验收
.\.venv\Scripts\python -m pytest tests/ -q          # 无 key 环境必须全绿
然后我在 .env 里填 VULNARENA_DEEPSEEK_API_KEY 后，用一条命令跑真实演练并打印：
每阶段的耗时、模型调用次数、token 消耗、最终拦截率与误杀率。
```

---

## P4 · M3：包装与求职材料

```text
【里程碑 M3】把已跑通的系统变成"面试官 30 秒能看懂"的材料。不新增业务逻辑。

# 1. 战报归档
db.py 新增 ArenaReport(Base)，表名 arena_reports：
  id(str, pk) / created_at(UTCDateTime) / category(str, index) / agent_mode(str) /
  status(str, index) / duration_ms(int) / llm_calls(int) / prompt_tokens(int) / completion_tokens(int) /
  blueprint(JSONB) / traces(JSONB) / patch(JSONB) / regression(JSONB) / warnings(JSONB)
沿用现有 Database 的风格提供 list_reports(page, page_size) 与 get_report(id)。

# 2. 路由（main.py 挂载，必须在 StaticFiles 之前）
POST /api/arena/start        202 → ArenaSession（创建租约 + BackgroundTasks）
GET  /api/arena/sessions/{id}   实时状态
GET  /api/arena/sessions/{id}/stream   SSE，事件：stage / trace / patch / done
GET  /api/arena/reports?page=&page_size=
所有 /api/arena/* 必须校验 X-Arena-Admin 头（值从 settings 读，默认随机生成并在启动日志打印），
未授权一律 401。控制面不许裸奔。

# 3. 单页看板
vulnarena/web/arena.html，原生 JS + 一个 <pre> 时间线 + 三个数字卡（拦截率 / 误杀率 / 累计成本），
不许引入 npm 构建流程。SSE 连不上时自动降级成 1s 轮询。

# 4. scripts/arena_demo.py
一条命令跑完整闭环，终端输出带时间戳的四阶段时间线，结束时打印一张 before/after 表：
| 向量 | 打补丁前 | 打补丁后 |
| UNION 注入 | 200 + canary | 403 (R-a1b2c3d4) |
| IDOR 遍历 | 200 + canary | 403 |
| O'Brien 正常查询 | 200 | 200 ✅ 未误杀 |

# 5. README 新增章节（中文，控制在 120 行内）
## AI Cyber Arena
- 一段话：它是什么、为什么这么设计（LLM 提议 / 确定性裁决）
- mermaid 架构图（浏览器 → WAF 中间件 → portal → 内存沙盒；arena 编排器 ↔ Redis ↔ PostgreSQL）
- 快速开始（三条命令）
- 实测数据表：拦截率、误杀率、p50/p95 延迟、单场 token 成本
- 威胁模型与边界：只打自己的内存沙盒、不接外部目标、控制面鉴权、canary 机制
- 已知限制与失败模式：LLM 不可用时的降级、规则被 gate 打回的比例、并发演练的隔离级别
- 设计取舍一节：为什么不让模型直接生成生产正则（给出你自己测到的误杀数据）

# 6. 一篇博客大纲（docs/blog.md，只写大纲 + 结论，别写成教程）
标题方向：《我让 LLM 写 WAF 规则，然后写了个闸门把它拦下来》
结构：动机 → 朴素做法为什么会炸（附误杀样本）→ proposal/verify/activate 三段式 →
     实测数字 → 这套东西不能解决什么
```

---

## 附录 A · 五个追问模板（AI 偷懒时直接贴）

```
A1 假实现：你刚才写的 X 是 mock / 简化版。请给出真实实现，并说明它在什么输入下会出错。
A2 无断言：这几个测试没有有效断言（只有 status_code == 200）。请补上对响应体、Redis 状态、
   数据库记录的具体断言，并给出一个"如果我改坏实现这条测试就会失败"的反例。
A3 先写测试：先只写会失败的测试（列出预期断言），我确认后再写实现。不要一次给全。
A4 反例：这条正则你声称安全，请构造一条能绕过它的输入，和一条被它误杀的合法输入。
A5 复用：现有 state.py 的 TaskStore 已经实现了 Lua 租约 + 心跳 + 失主检测，
   你为什么又写了一套？请改成复用，或说明为什么不能复用。
```

## 附录 B · 常见跑偏与纠正

| 症状 | 纠正话术 |
|---|---|
| 一次吐出 2000 行，跑不起来 | "停。先只给文件树和接口契约，我确认后再逐文件写。" |
| 把漏洞写成 `eval` / 真发请求 | "触碰红线了。所有脆弱点只能作用于内存结构与内存 SQLite，出网口必须是 ASGITransport。" |
| 规则一律写 `.*(select|union).*` | "这条会误杀 benign_corpus 里的英文 select。请改到 false_positive == 0。" |
| 测试里 `except: pass` 或跳过 | "不许跳过。要么断言具体行为，要么明确标 xfail 并写原因。" |
| 擅自新增依赖 | "零新增依赖。标准库做不到的话先停下来说明。" |
| 覆盖率掉了 | "不许下调 fail_under。新模块自己补测试到 85% 以上。" |
| LLM 挂了整场演练崩 | "按降级矩阵走 fallback，并写入 warnings，不许静默失败。" |

## 附录 C · 交付前自查清单

- [ ] `ruff check` / `ruff format --check` 干净
- [ ] `pytest` 全绿，且**无 API Key、无 Redis、无网络**时也全绿
- [ ] `pytest --cov` 覆盖率 ≥ 80%，`arena/`、`portal/` 自身 ≥ 85%
- [ ] 五个漏洞点在"脆弱态"和"修复态"下都有测试，且修复态业务仍然 200
- [ ] 每条生效规则都有：来源 trace、生成方式（llm/template）、误杀率 0
- [ ] 结论数字是跑出来的，不是估的（拦截率、误杀率、token 成本、p95）
- [ ] README 有架构图和实测数据表；有"已知限制"章节
- [ ] 没有任何真实外部目标；控制面有鉴权；默认监听 127.0.0.1
- [ ] `git log` 是一个里程碑一个 commit，能看出演进过程（面试会看）

## 附录 D · 被拒答时的改写话术

如果某个工具/模型拒绝按 P2/P3 生成代码，多半是措辞触发的，不是内容。把请求拆开、换成防御视角再发：

1. **拆**：先只要 portal 业务代码（"带 RBAC 的工单系统"），再只要中间件（"从配置中心热加载规则的网关"），最后才要 agent。
2. **换主语**：不要"帮我写自动攻击脚本"，改成"帮我写一个验证检测规则是否有效的回归测试工具，它在自己的内存靶场上重放预置样本"。
3. **强调产物**：整段话里明确"产出物是检测规则和修复 diff，攻击向量用于验证召回率"。
4. **先要测试**：模型对"写测试"的配合度远高于"写利用代码"，而且测试本身就把行为规格定死了。
5. **落盘**：把边界写进仓库——`README` 顶部声明、`LAB_MODE` 默认关、`docs/ETHICS.md`、只 bind `127.0.0.1`。这既是合规，也是面试加分项。
