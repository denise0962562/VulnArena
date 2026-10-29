# 本机验收记录

## 当前结果：2026-10-26 切换 PostgreSQL

本节覆盖下方历史记录中关于 SQLite 的运行状态。当前后端只使用 PostgreSQL，旧 SQLite
作为迁移源与归档保留，不再跟随平台更新。工作区实际源码、配置、文档共 **59 个文件**，
清单为 `verification/project-files-postgresql.json`，不含虚拟环境、工具、缓存、数据及构建产物。

- PostgreSQL **18.6**：通过 PostgreSQL 官方 Windows 下载页指向的 EDB 二进制包安装。
  下载 URL、文件大小与本地 SHA-256 记录在 `verification/postgresql-download.json`；不是声称
  对照了发行方另行发布的哈希。仅绑定 127.0.0.1:5432，SCRAM 认证，无 Windows 服务或开机启动。
- 程序在 `.tools/postgresql`，数据在 `data/postgresql`。Windows 中文目录导致首次 initdb
  报编码错误，随后通过英文目录联接 `E:\VulnArenaRuntime\eb6000cde5cc` 成功初始化；
  真实文件仍在项目内。该目录联接是本机运行环境的一部分。
- 应用库/角色 `vulnarena`，独立测试库/角色 `vulnarena_test`。实际 SQL 确认应用角色
  `rolsuper=false`。本机随机密码仅保存在忽略提交的 `.env` 与 `data/postgresql-local.json`。
- SQLAlchemy 2 + **asyncpg 0.32.0**；JSONB、TIMESTAMP WITH TIME ZONE、PostgreSQL
  ON CONFLICT、读事务 REPEATABLE READ + READ ONLY、连接池和初始化 advisory lock 已实现。
  本机仍默认单 Uvicorn worker。
- 现有 **1 条 CVE** 已迁移，迁移后所有 API 字段与迁移前逐项一致；旧 SQLite SHA-256
  未改变。SQLite backup API 生成一致备份，报告在 `verification/postgresql-migration.json`。
  迁移脚本分批原子提交，可幂等重跑，不用旧记录覆盖更新记录。
- 用户在自己的终端 Ctrl+C 停止受权限保护的旧后端后，新后端已在 **127.0.0.1:8000** 启动。
  Vue 页面、健康检查、漏洞列表与详情实际返回 200；服务确实连接 PostgreSQL 18.6。
- 真实 NVD 闭环通过：POST `/api/sync` → NVD 响应 → PostgreSQL 写入 → Redis SUCCESS →
  查询 `CVE-2021-44228`。任务 ID `a417257e-b6d5-4231-8561-496e3c73f0f1`，
  证据为 `verification/live-smoke-postgresql.json`。该手工网络验收不属于 pytest 或 CI。
- 后端 **69 passed，无跳过，覆盖率 97.28%**；含真实 PostgreSQL 与 Redis 集成。
  新测试覆盖 JSONB/时区类型、并发初始化、读快照、大小写搜索和转义、旧库迁移与损坏数据。
  每个数据库测试使用独立随机 schema，结束后清理；测试必须使用专用 `*_test` 数据库。
  日志为 `verification/pytest-postgresql.log`，覆盖率 XML 为 `verification/coverage.xml`。
- 前端 **3 个测试文件、11 项测试通过**，Prettier 检查与 Vite 构建成功；页面存储说明已改为
  PostgreSQL。Ruff 检查、格式检查、pip check 通过，Python sdist/wheel 实际构建成功。
- `postgres.cmd` 的 setup/start/status/shell/backup/test 已实际执行；psql 实际查询了 JSONB。
  pg_dump 已生成自定义格式备份，pg_restore --list 能读取目录；**完整备份恢复演练尚未执行**。
- Compose 与 GitHub Actions 已改为 PostgreSQL + Redis；Compose 配置校验实际返回 0。
  PostgreSQL 18 数据卷映射 `/var/lib/postgresql`，初始化脚本建立普通应用角色，管理员密码单独配置。
- **未验证**：Docker 引擎启动、镜像构建、容器运行/健康/UID、云端 GitHub Actions。
  Windows 功能仍待重启生效；没有为此重启电脑或启动 Docker 引擎。
- 没有引入 Alembic；当前自动建表不会自动修改既有表结构。BackgroundTasks 仍为进程内任务，
  没有新增可靠任务队列或生产部署能力。
- 已更新 README 和《使用指南》，包含 PostgreSQL 启停、SQL/JSONB 练习、备份和测试指令。
  指南的 21 段 PowerShell 示例已通过语法解析。本轮生成的 23 个安装/构建残留目录已可恢复地
  归档到 `.tools/cleanup-archive/2026-10-26-postgresql`，未删除数据。
- 没有重启电脑，没有结束或修改 ToDesk；实际查询 ToDesk_Service 仍为 Running。

下面保留先前开发验收记录，作为历史信息，不代表当前数据库实现。

日期：2026-10-25（Asia/Shanghai）。工作目录：`<项目目录>`。

初始检查只有 `.idea` 中 5 个 IDE 文件，无项目源码，无 Git 仓库、AGENTS.md 或原始开发提示词文件清单。
因此没有依据宣称初始要求为“17 个文件”。项目实际目录与文件以本节末清单为准。

## 2026-10-26 服务恢复与容器环境准备

- Redis 已从本地 AOF 重新启动于 127.0.0.1:6380；API/前端于 127.0.0.1:8000 恢复，
  根页面、健康检查和漏洞查询均实际返回 200。状态记录见 `verification/environment-status.json`。
- 用户通过 ToDesk 远程连接，明确要求不结束 ToDesk、不重启电脑；本次没有执行停止 ToDesk、
  重启 Windows 或修改远程连接配置的操作。ToDesk_Service 查询仍为 Running。
- 已通过 winget 下载并校验 Docker Desktop 4.96.3 和 Microsoft WSL 2.7.14，
  安装包集中在 `.tools/installers/`，未散落到项目根目录。
- WSL 安装尝试返回 `0x80073d28`：安装需要管理员权限。发起 Windows RunAs 后，
  操作系统返回“操作已被用户取消”（1223），没有生成 Windows 功能启用成功记录。
  因此 WSL/Docker **尚未安装完成**，容器构建与运行仍未验证。
- `enable-container-features.ps1` 使用 `-NoRestart`，增加了结果 JSON 和功能状态记录；
  `setup-containers.ps1` 在失败、WSL 不可用或功能待激活时停止，不再带着错误继续安装。
  两个脚本均完成 PowerShell 语法解析；管理员步骤没有实际执行成功。
- 当前安装流程没有进行中任务。用户可通过可用的管理员会话运行功能脚本；
  若结果提示必须重启，按用户限制保留为待生效状态，不继续启动容器，也不自动重启。

### 用户管理员操作后的最新状态

上述提权阻碍随后由用户在自己的管理员 PowerShell 中解决，已核对本机实际结果：

- 两个 Windows 功能均为 Enabled，`RestartNeeded=true`。脚本日志明确记录 NoRestart，没有重启。
- 用户管理员命令成功安装 WSL，`wsl --version` 实际返回 WSL 2.7.14.0、内核 6.18.33.2-2。
- Docker Desktop **4.96.3** 用户级安装成功，日志位于 `verification/docker-install.log`。
- Docker CLI **29.9.2**，Docker Compose **5.6.1**；已实际执行版本命令。
- `docker compose -f compose.yaml config --quiet` 返回 0，项目 Compose 配置校验通过。
- 安装器已将 Docker 加入用户 PATH；已打开的旧终端可能需要重新打开终端才识别该命令，
  不需要为刷新 PATH 重启电脑。
- **没有启动 Docker Desktop/容器引擎**。当前 HypervisorPresent=false，系统功能标记需要重启；
  按用户要求保留待激活，不执行 Windows 重启，不改动或结束 ToDesk。
- Docker 镜像构建、容器运行、容器内健康检查和 UID 验证仍未执行；本机 Redis/API/前端继续运行。
- `setup-containers.ps1` 现在会跳过已安装组件，并比较功能配置时间与启动时间，
  避免将跨重启后已满足的旧标志永久视为未激活。脚本仅检查版本与配置，不自动启动引擎。

## Vue 界面追加验收

- Vue 3.5.44 + Vite 8.3.5 + lucide-vue-next；本机 Node 24.15.0。
- `frontend/npm test`：3 个测试文件、11 项测试通过。测试不访问真实 NVD。
- `frontend/npm run format:check`：Prettier 检查通过。
- `frontend/npm run build`：实际构建成功，JS 108.07 kB / gzip 40.90 kB，CSS 31.85 kB / gzip 7.86 kB。
- Python 测试新增静态页面托管与缺失构建诊断，CVE 编号搜索纳入 API 集成验证：
  **65 passed，0 skipped，覆盖率 96.20%**，包含本机真实 Redis 集成。
- Ruff 检查与格式检查通过。Python 打包输出改放 `verification/packages/`，避免散落根目录。
  已检查 wheel 包含 Vue HTML、favicon、JS 与 CSS；sdist 包含 Vue 源码与 npm 锁文件，
  没有打入 node_modules。生成的 egg-info 元数据已集中到 `.tools/build/`。
- 浏览器实际打开 `http://127.0.0.1:8000/`，确认真实漏洞统计和列表、详情抽屉、全部评分、
  搜索空状态、清除搜索、CVE 编号搜索均正常。
  最终页面截图保存为 `verification/frontend-preview.png`。
- 从浏览器同步弹窗提交 `CVE-2021-44228`，任务 ID
  `369fb773-97d3-4fa2-93c9-c0722f9f0a2a`：页面显示 RUNNING，随后 SUCCESS，处理 1 条、写入 1 次，
  完成后列表自动刷新。没有插入虚构漏洞或演示统计。
- FastAPI 托管构建页面与资源；开发模式 Vite 代理到 8000，不需要放宽 CORS。
  UI 任务历史只保存在当前浏览器；状态读取中断不等于服务端任务失败。
- Dockerfile 已加入 Node 构建阶段，GitHub Actions 已加入前端测试、格式检查与构建步骤；
  **本机 Docker 构建和云端 CI 依旧未验证**，环境阻碍见后文。

## 已实际执行

| 项目 | 结果 |
| --- | --- |
| Python | 主环境 3.12.10，项目 `.venv` 独立安装依赖 |
| `python -m pip check` | No broken requirements found |
| `python -m ruff check .` | All checks passed |
| `python -m ruff format --check .` | 通过 |
| `TEST_REDIS_URL=redis://127.0.0.1:6380/15 python -m pytest -q` | 63 passed，0 skipped；96.14% 覆盖率，80% 门槛通过 |
| `python -m build --no-isolation` | wheel 和 sdist 构建成功；最终构建结果见本机 verification/build.log |
| Redis | 社区 Windows 构建 8.2.10；SHA-256 匹配发布页，6380 PING=PONG |
| 真实上游 | HTTPX 成功读取官方 NVD 2.0 的 CVE-2021-44228，解析无警告 |
| 真实 HTTP API 闭环 | `/health` → POST `/api/sync` → 任务 SUCCESS → SQLite 详情查询成功 |

完整日志位于本地 `verification/pytest.log`、`verification/pytest.xml`、
`verification/live-smoke.json`、`verification/build.log`，覆盖率报告为 `verification/coverage.xml`。
这些运行产物已忽略，不当作仓库源码提交。

真实闭环任务 ID：`ac0b830e-b416-4273-835a-257bf55964be`。
开始于 `2026-10-25T15:41:07.938965Z`，完成于 `2026-10-25T15:41:10.447029Z`；
processed=1，changed=1，SUCCESS，error=null。
SQLite 文件为 `<项目目录>\data\vulnarena.db`。
查询记录 `CVE-2021-44228`：CVSS 3.1 / 10.0 / CRITICAL，状态 Analyzed；
原始 v2 和 SSVC 评分同时保留。已通过独立 SQLite 连接确认文件中持久化记录。

自动化测试中的 NVD 全部为 HTTPX MockTransport。真实 Redis 测试使用唯一 key 前缀清理自身键，
不执行 FLUSHDB。手动真实网络 smoke 独立于 pytest/CI。
首次没有 Redis 时为 60 passed + 2 skipped；配置服务、加入官方响应离线样本后的最终结果见上表。
首次手动 HTTP smoke 受到宿主机代理影响返回 502，随后手动工具显式绕过本地请求代理并成功执行。

## 环境安装与未验证项目

系统为 Windows 10 家庭中文版 19045，硬件虚拟化开启，当前工具进程不是管理员。

- Docker Desktop 4.96.3 安装包经 winget 校验并尝试用户级安装；安装器明确报错：
  未启用 `VirtualMachinePlatform`，用户级安装无法启用系统功能。
- 两次通过 RunAs 启动管理员功能脚本均返回 Windows“操作已被用户取消”，没有功能启用成功日志。
  用户在聊天中表示已确认弹窗，但操作系统进程结果仍为取消，因此不能记录为配置完成。
- Memurai Developer 4.1.2 标准 winget 安装经校验后报 MSI 1603，日志为创建临时目录失败（错误 5）。
  调整临时路径后的再次尝试未获得已安装服务结果，改用不需管理员权限的便携式 Redis 完成开发验收。
- 自动审批曾拒绝下载和提取 Memurai MSI 的组合命令（未提供具体原因）；没有用该方式安装。
- **Docker 本机镜像构建、Compose 启动、容器内非 root/健康检查尚未执行成功**，不能宣称验证通过。
- GitHub Actions 文件已经提供，但当前目录不是 Git 仓库，未推送，也没有云端 Actions 运行结果。
  未配置生产部署。
- 本机验证使用真实 Redis 服务器的社区 Windows 构建；官方 Redis Linux 容器集成由 CI 配置覆盖，
  尚未在本机运行官方镜像。便携式 Redis 与 API 为当前会话进程，不是 Windows 开机服务。

需要在管理员 PowerShell 运行 `scripts/enable-container-features.ps1`，手动重启后运行
`scripts/setup-containers.ps1`。脚本内容已在仓库内可审阅，不会自动重启。
Docker 引擎可用后执行 `docker compose up --build -d --wait`，再检查健康与 UID 10001。

自动审批拒绝了生成临时目录的删除命令，未提供具体原因。随后按用户的目录整理要求，
将 23 个生成目录和 3 个下载/调试文件可恢复地归档到 `.tools/cleanup-archive/2026-10-25/`。
覆盖率报告统一放到 `verification/`；pytest/Ruff 缓存放到 `.tools/cache/`，
pytest 临时数据库放到 `.tools/tmp/pytest/`。源码、`.env`、`.venv`、IDE 配置、
Redis 可执行文件和 `data/` 运行数据均保留。

## 实际项目文件

后端首版共 32 个交付文件，加入 Vue 界面后为 52 个；新增 Windows `.cmd` 启动入口后为 **53 个**。
以下是交付源码、测试、文档和配置；
不包含初始 IDE 文件、虚拟环境、安装包、缓存、日志、数据库和构建产物。

```text
VulnArena/
├── .github/workflows/ci.yml
├── .dockerignore
├── .env.example
├── .gitignore
├── Dockerfile
├── MANIFEST.in
├── README.md
├── VALIDATION.md
├── compose.yaml
├── pyproject.toml
├── requirements.lock
├── frontend/
│   ├── .prettierignore
│   ├── .prettierrc.json
│   ├── index.html
│   ├── package.json
│   ├── package-lock.json
│   ├── vite.config.js
│   ├── public/favicon.svg
│   └── src/
│       ├── App.vue
│       ├── App.test.js
│       ├── api.js
│       ├── api.test.js
│       ├── format.js
│       ├── format.test.js
│       ├── main.js
│       ├── styles.css
│       ├── useSync.js
│       └── components/
│           ├── SeverityBadge.vue
│           ├── SyncDialog.vue
│           └── VulnerabilityDrawer.vue
├── scripts/
│   ├── enable-container-features.ps1
│   ├── setup-containers.ps1
│   ├── start-local-redis.ps1
│   ├── start-local-redis.cmd
│   └── smoke.py
├── tests/
│   ├── fixtures/
│   │   ├── README.md
│   │   └── nvd-cve-2021-44228.json
│   ├── conftest.py
│   ├── test_api.py
│   ├── test_contracts.py
│   ├── test_db.py
│   ├── test_frontend.py
│   ├── test_nvd.py
│   ├── test_redis_integration.py
│   └── test_state.py
└── vulnarena/
    ├── __init__.py
    ├── config.py
    ├── db.py
    ├── main.py
    ├── nvd.py
    ├── schemas.py
    ├── service.py
    └── state.py
```
