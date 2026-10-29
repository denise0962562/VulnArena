<script setup>
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import {
  Activity,
  ArrowDownToLine,
  ArrowRight,
  ArrowUpRight,
  BookOpen,
  Check,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  CircleHelp,
  Clock3,
  Database,
  Download,
  ExternalLink,
  FileSearch,
  Fingerprint,
  Globe2,
  LayoutDashboard,
  LoaderCircle,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  X,
} from 'lucide-vue-next'
import { api } from './api'
import { formatDate, scoreText, taskLabels } from './format'
import { useSync } from './useSync'
import SeverityBadge from './components/SeverityBadge.vue'
import SyncDialog from './components/SyncDialog.vue'
import VulnerabilityDrawer from './components/VulnerabilityDrawer.vue'

const view = ref('overview')
const openLab = () => window.location.assign('/lab')
const titles = { overview: '漏洞情报', tasks: '同步中心', guide: '使用说明' }
const search = ref('')
const filters = reactive({
  keyword: '',
  severity: '',
  status: '',
  topic: '',
  sort: 'published',
  year_from: 2020,
  year_to: 2026,
})
const period = ref('2020-2026')
const yearCoverage = ref([])
const yearSummary = computed(() =>
  yearCoverage.value.reduce(
    (sum, row) => ({ total: sum.total + row.total, translated: sum.translated + row.translated }),
    { total: 0, translated: 0 },
  ),
)
const topics = [
  'Linux',
  'Windows',
  'Java',
  'Go',
  'Python',
  'PHP',
  'C/C++',
  '.NET',
  'Rust',
  'JavaScript',
  '其他',
]
const page = ref(1)
const pageSize = ref(10)
const items = ref([])
const total = ref(null)
const stats = ref({ all: null, critical: null, high: null, unknown: null })
const loading = ref(true)
const listError = ref('')
const statsError = ref('')
const coverage = ref(null)
const health = ref(null)
const refreshedAt = ref(null)
const syncOpen = ref(false)
const selected = ref(null)
const detailLoading = ref('')
const detailError = ref('')
let listSequence = 0
let detailSequence = 0
let searchTimer
let healthTimer
let disposed = false

const { history, active, submitting, pollError, submit, resume } = useSync(refreshAll)
const pages = computed(() => Math.max(1, Math.ceil((total.value || 0) / pageSize.value)))
const currentRated = computed(() => items.value.filter((item) => item.cvss_score != null).length)
const currentRejected = computed(
  () => items.value.filter((item) => item.vuln_status === 'Rejected').length,
)
const hasFilter = computed(() =>
  Boolean(
    filters.keyword ||
    filters.severity ||
    filters.status ||
    filters.topic ||
    period.value !== '2020-2026',
  ),
)
const latestTask = computed(() => history.value[0])

async function loadList() {
  const sequence = ++listSequence
  loading.value = true
  listError.value = ''
  try {
    const data = await api.list({ ...filters, page: page.value, page_size: pageSize.value })
    if (disposed || sequence !== listSequence) return
    if (page.value > 1 && page.value > Math.max(1, Math.ceil(data.total / pageSize.value))) {
      page.value = 1
      return loadList()
    }
    items.value = data.items
    total.value = data.total
    refreshedAt.value = new Date().toISOString()
  } catch (error) {
    if (!disposed && sequence === listSequence) listError.value = error.message
  } finally {
    if (!disposed && sequence === listSequence) loading.value = false
  }
}

async function loadStats() {
  try {
    const counts = await Promise.all(
      ['', 'CRITICAL', 'HIGH', 'UNKNOWN'].map((severity) => api.list({ page_size: 1, severity })),
    )
    if (disposed) return
    stats.value = Object.fromEntries(
      ['all', 'critical', 'high', 'unknown'].map((key, i) => [key, counts[i].total]),
    )
    statsError.value = ''
  } catch (error) {
    if (!disposed) statsError.value = error.message
  }
}

async function loadCoverage() {
  try {
    const data = await api.libraryStats()
    if (!disposed) coverage.value = data
  } catch {
    if (!disposed) coverage.value = null
  }
}

async function loadYears() {
  try {
    const data = await api.years()
    if (!disposed) yearCoverage.value = data
  } catch {
    if (!disposed) yearCoverage.value = []
  }
}

function selectPeriod(value = period.value) {
  period.value = value
  const years = value.split('-').map(Number)
  filters.year_from = value ? years[0] : ''
  filters.year_to = value ? years[1] || years[0] : ''
  applyFilters()
}

async function checkHealth() {
  try {
    await api.health()
    if (!disposed) health.value = true
  } catch {
    if (!disposed) health.value = false
  }
}

async function refreshAll() {
  await Promise.all([loadList(), loadStats(), checkHealth(), loadCoverage(), loadYears()])
}

function applyFilters() {
  clearTimeout(searchTimer)
  filters.keyword = search.value.trim()
  page.value = 1
  void loadList()
}

function clearSearch() {
  search.value = ''
  applyFilters()
}

function filterSeverity(severity) {
  filters.severity = severity
  applyFilters()
}

function resetFilters() {
  search.value = ''
  Object.assign(filters, {
    keyword: '',
    severity: '',
    status: '',
    topic: '',
    sort: 'published',
    year_from: 2020,
    year_to: 2026,
  })
  period.value = '2020-2026'
  applyFilters()
}

function movePage(offset) {
  page.value += offset
  void loadList()
}

async function openDetail(item) {
  const sequence = ++detailSequence
  detailLoading.value = item.cve_id
  detailError.value = ''
  try {
    const detail = await api.detail(item.cve_id)
    if (!disposed && sequence === detailSequence) selected.value = detail
  } catch (error) {
    if (!disposed && sequence === detailSequence) detailError.value = error.message
  } finally {
    if (!disposed && sequence === detailSequence) detailLoading.value = ''
  }
}

watch(search, () => {
  clearTimeout(searchTimer)
  searchTimer = setTimeout(applyFilters, 350)
})

onMounted(() => {
  void refreshAll()
  if (active.value) resume()
  healthTimer = setInterval(() => {
    checkHealth()
    loadCoverage()
    loadYears()
  }, 30000)
})
onUnmounted(() => {
  disposed = true
  listSequence++
  detailSequence++
  clearTimeout(searchTimer)
  clearInterval(healthTimer)
})
</script>

<template>
  <div class="app-shell">
    <aside class="sidebar">
      <a class="brand" href="#" aria-label="VulnArena 首页" @click.prevent="view = 'overview'">
        <span class="brand-mark"><ShieldCheck :size="25" :stroke-width="1.8" /></span>
        <span>
          Vuln
          <span class="brand-light">Scope</span>
          <small>VULNERABILITY INTELLIGENCE</small>
        </span>
      </a>
      <div class="workspace-label">
        <span class="workspace-avatar"><Fingerprint :size="18" /></span>
        <div>
          本地工作空间
          <small>Personal workspace</small>
        </div>
        <span class="version-pill">V1</span>
      </div>
      <p class="nav-label">
        工作台
        <span>WORKSPACE</span>
      </p>
      <nav aria-label="主导航">
        <button
          :class="{ active: view === 'overview' }"
          :aria-current="view === 'overview' ? 'page' : undefined"
          @click="view = 'overview'"
        >
          <LayoutDashboard :size="18" />
          漏洞总览
          <ChevronRight :size="14" class="nav-arrow" />
        </button>
        <button
          :class="{ active: view === 'tasks' }"
          :aria-current="view === 'tasks' ? 'page' : undefined"
          @click="view = 'tasks'"
        >
          <RefreshCw :size="18" />
          同步中心
          <span v-if="active" class="nav-live"></span>
        </button>
        <button
          :class="{ active: view === 'guide' }"
          :aria-current="view === 'guide' ? 'page' : undefined"
          @click="view = 'guide'"
        >
          <BookOpen :size="18" />
          使用说明
        </button>
        <button class="nav-lab" @click="openLab">
          <Shield :size="18" />
          靶场演练
          <span class="nav-badge">LAB</span>
        </button>
      </nav>
      <div class="sidebar-source">
        <div class="source-orbit">
          <Globe2 :size="25" :stroke-width="1.3" />
          <span></span>
        </div>
        <p>好情报，始于可靠来源。</p>
        <span>
          连接 NVD 官方数据源
          <br />
          在本地构建你的漏洞情报库。
        </span>
        <a href="https://nvd.nist.gov/" target="_blank" rel="noopener noreferrer">
          了解 NVD
          <ArrowUpRight :size="14" />
        </a>
      </div>
      <div class="sidebar-footer">
        <span
          class="health-dot"
          :class="health === true ? 'online' : health === false ? 'offline' : ''"
        ></span>
        <div>
          {{
            health === true ? '服务运行正常' : health === false ? '服务连接异常' : '正在连接服务'
          }}
          <small>VulnArena · v0.1.0</small>
        </div>
        <Shield :size="18" />
      </div>
    </aside>

    <div class="workspace">
      <header class="topbar">
        <div class="breadcrumb">
          工作空间
          <span>/</span>
          <strong>{{ titles[view] }}</strong>
        </div>
        <div class="topbar-right">
          <span class="local-tag">
            <span></span>
            LOCAL
          </span>
          <a href="/docs" target="_blank" rel="noopener noreferrer" aria-label="打开 API 文档">
            <CircleHelp :size="18" />
          </a>
          <span class="user-avatar">VS</span>
        </div>
      </header>
      <main>
        <section class="page-heading">
          <div>
            <p class="eyebrow">YOUR INTELLIGENCE WORKSPACE</p>
            <h1>
              {{ titles[view] }}
              <span class="heading-dot">.</span>
            </h1>
            <p>
              {{
                view === 'overview'
                  ? '让分散的漏洞信息，成为清晰可追溯的情报。'
                  : view === 'tasks'
                    ? '追踪每一次同步，从官方数据源到本地数据库。'
                    : '从第一条漏洞开始，建立你的情报工作流。'
              }}
            </p>
          </div>
          <div class="heading-actions">
            <button class="button secondary" :disabled="loading" @click="refreshAll">
              <RefreshCw :size="16" :class="{ spin: loading }" />
              刷新
            </button>
            <button
              class="button primary"
              :disabled="!!active || submitting"
              @click="syncOpen = true"
            >
              <Download :size="17" />
              {{ active ? '正在同步' : '同步 NVD 情报' }}
            </button>
          </div>
        </section>

        <div v-if="health === false" class="alert warning" role="status">
          <Activity :size="18" />
          <p>服务状态异常。已有漏洞仍可能正常查询；发起同步前请确认后端和 Redis 已启动。</p>
          <button @click="checkHealth">重新检测</button>
        </div>
        <div v-if="active || pollError" class="alert task-alert" role="status">
          <LoaderCircle v-if="active && !pollError" :size="18" class="spin" />
          <Clock3 v-else :size="18" />
          <p>
            <strong>{{ pollError ? '任务状态读取中断' : '情报同步进行中' }}</strong>
            <span>
              {{
                pollError ||
                `${active.label || active.id} · ${taskLabels[active.status]}，完成后将自动刷新。`
              }}
            </span>
          </p>
          <button v-if="pollError && latestTask" @click="resume(latestTask)">重新连接</button>
          <button v-else @click="view = 'tasks'">
            查看任务
            <ArrowRight :size="14" />
          </button>
        </div>

        <template v-if="view === 'overview'">
          <section class="stat-grid" aria-label="漏洞数据统计">
            <article class="stat-card">
              <div class="stat-top">
                <span>全库已入库漏洞</span>
                <span class="stat-icon blue"><Database :size="18" /></span>
              </div>
              <div class="stat-value">
                {{ stats.all == null ? '—' : stats.all.toLocaleString() }}
                <small>条</small>
              </div>
              <div class="stat-caption">
                <span class="tiny-dot blue"></span>
                本地情报库
                <span class="stat-code">TOTAL</span>
              </div>
            </article>
            <article class="stat-card">
              <div class="stat-top">
                <span>严重漏洞</span>
                <span class="stat-icon red"><ShieldAlert :size="19" /></span>
              </div>
              <div class="stat-value">
                {{ stats.critical == null ? '—' : stats.critical.toLocaleString() }}
                <small>条</small>
              </div>
              <div class="stat-caption">
                <span class="tiny-dot red"></span>
                CVSS 9.0–10.0
                <span class="stat-code">CRITICAL</span>
              </div>
            </article>
            <article class="stat-card">
              <div class="stat-top">
                <span>高危漏洞</span>
                <span class="stat-icon orange"><Shield :size="18" /></span>
              </div>
              <div class="stat-value">
                {{ stats.high == null ? '—' : stats.high.toLocaleString() }}
                <small>条</small>
              </div>
              <div class="stat-caption">
                <span class="tiny-dot orange"></span>
                按评分版本划分
                <span class="stat-code">HIGH</span>
              </div>
            </article>
            <article class="stat-card">
              <div class="stat-top">
                <span>待评分漏洞</span>
                <span class="stat-icon slate"><FileSearch :size="19" /></span>
              </div>
              <div class="stat-value">
                {{ stats.unknown == null ? '—' : stats.unknown.toLocaleString() }}
                <small>条</small>
              </div>
              <div class="stat-caption">
                <span class="tiny-dot slate"></span>
                尚无代表评分
                <span class="stat-code">UNKNOWN</span>
              </div>
            </article>
          </section>
          <p v-if="statsError" class="form-error" role="alert">统计读取失败：{{ statsError }}</p>
          <section v-if="coverage" class="coverage-strip" aria-label="学习资料采集覆盖情况">
            <BookOpen :size="21" />
            <div>
              <strong>本地双语学习库</strong>
              <span>NVD · CVE CNA · GitHub 安全公告</span>
            </div>
            <p>
              <strong>{{ coverage.studied.toLocaleString() }}</strong>
              条已补采
            </p>
            <p>
              <strong>{{ coverage.translated.toLocaleString() }}</strong>
              条中文摘要
            </p>
            <p>
              <strong>{{ coverage.documents.toLocaleString() }}</strong>
              篇本地正文
            </p>
          </section>

          <section
            v-if="yearCoverage.length"
            class="year-panel"
            aria-label="2020至2026年收录与中文覆盖"
          >
            <div class="year-heading">
              <h2>2020–2026 近年漏洞</h2>
              <p>
                按 CVE 编号年份整理 ·
                {{
                  yearSummary.total === yearSummary.translated ? '中文摘要已齐' : '中文摘要补齐中'
                }}
                {{ yearSummary.translated.toLocaleString() }} /
                {{ yearSummary.total.toLocaleString() }}
                · 每 30 秒更新
              </p>
            </div>
            <div class="year-grid">
              <button
                v-for="row in [...yearCoverage].reverse()"
                :key="row.year"
                :class="{ active: period === String(row.year) }"
                @click="selectPeriod(String(row.year))"
              >
                <strong>{{ row.year }}</strong>
                <span>{{ row.total.toLocaleString() }} 条</span>
                <div class="year-progress">
                  <i
                    :style="{ width: `${row.total ? (row.translated / row.total) * 100 : 0}%` }"
                  ></i>
                </div>
                <small>
                  中文 {{ row.translated.toLocaleString() }} / {{ row.total.toLocaleString() }}
                </small>
              </button>
            </div>
          </section>
          <div class="content-grid">
            <section class="panel vulnerability-panel">
              <div class="panel-heading">
                <div>
                  <h2>
                    漏洞情报库
                    <span class="count-label">{{ total == null ? '—' : total }}</span>
                  </h2>
                  <p>
                    从本地数据库读取，按{{
                      filters.sort === 'published' ? '发布时间' : '上游修订时间'
                    }}排序。
                  </p>
                </div>
                <span class="source-chip">
                  <span></span>
                  NVD · CNA · GHSA
                </span>
              </div>
              <div class="severity-tabs" aria-label="按严重度筛选">
                <button :class="{ active: !filters.severity }" @click="filterSeverity('')">
                  全部漏洞
                </button>
                <button
                  :class="{ active: filters.severity === 'CRITICAL' }"
                  @click="filterSeverity('CRITICAL')"
                >
                  <span class="tiny-dot red"></span>
                  严重
                </button>
                <button
                  :class="{ active: filters.severity === 'HIGH' }"
                  @click="filterSeverity('HIGH')"
                >
                  <span class="tiny-dot orange"></span>
                  高危
                </button>
                <button
                  :class="{ active: filters.severity === 'MEDIUM' }"
                  @click="filterSeverity('MEDIUM')"
                >
                  中危
                </button>
                <button
                  :class="{ active: filters.severity === 'UNKNOWN' }"
                  @click="filterSeverity('UNKNOWN')"
                >
                  待评分
                </button>
              </div>
              <form class="filter-bar" role="search" @submit.prevent="applyFilters">
                <div class="status-filter">
                  <select v-model="period" aria-label="筛选 CVE 编号年份" @change="selectPeriod()">
                    <option value="2020-2026">2020–2026 年</option>
                    <option
                      v-for="year in [2026, 2025, 2024, 2023, 2022, 2021, 2020]"
                      :key="year"
                      :value="String(year)"
                    >
                      {{ year }} 年
                    </option>
                    <option value="">全部历史年份</option>
                  </select>
                </div>
                <div class="search-box">
                  <Search :size="17" />
                  <input
                    v-model="search"
                    placeholder="搜索编号、中文译文或英文描述…"
                    aria-label="搜索 CVE 编号或漏洞描述"
                    maxlength="100"
                  />
                  <button v-if="search" type="button" aria-label="清除搜索" @click="clearSearch">
                    <X :size="14" />
                  </button>
                </div>
                <div class="status-filter">
                  <select
                    v-model="filters.topic"
                    aria-label="筛选系统或语言生态"
                    @change="applyFilters"
                  >
                    <option value="">全部系统 / 语言</option>
                    <option v-for="topic in topics" :key="topic" :value="topic">{{ topic }}</option>
                  </select>
                </div>
                <div class="status-filter">
                  <select v-model="filters.sort" aria-label="排序方式" @change="applyFilters">
                    <option value="modified">最近修订</option>
                    <option value="published">最近发布</option>
                  </select>
                </div>
                <div class="status-filter">
                  <SlidersHorizontal :size="15" />
                  <select v-model="filters.status" aria-label="筛选漏洞状态" @change="applyFilters">
                    <option value="">全部状态</option>
                    <option value="Analyzed">已分析</option>
                    <option value="Modified">已修订</option>
                    <option value="Awaiting Analysis">等待分析</option>
                    <option value="Undergoing Analysis">分析中</option>
                    <option value="Received">新收录</option>
                    <option value="Deferred">暂缓分析</option>
                    <option value="Rejected">已拒绝</option>
                    <option value="GitHub Reviewed">GitHub 已审核</option>
                  </select>
                </div>
              </form>
              <div v-if="listError || detailError" class="inline-error" role="alert">
                <span>{{ listError || detailError }}</span>
                <button @click="loadList">重试</button>
              </div>
              <div class="table-scroll" :aria-busy="loading">
                <table>
                  <thead>
                    <tr>
                      <th class="vuln-column">漏洞 / 描述</th>
                      <th>严重度</th>
                      <th>CVSS</th>
                      <th>最后修订</th>
                      <th><span class="sr-only">操作</span></th>
                    </tr>
                  </thead>
                  <tbody>
                    <template v-if="loading">
                      <tr v-for="n in 3" :key="n" class="skeleton-row">
                        <td>
                          <span class="skeleton long"></span>
                          <span class="skeleton short"></span>
                        </td>
                        <td><span class="skeleton short"></span></td>
                        <td><span class="skeleton short"></span></td>
                        <td><span class="skeleton short"></span></td>
                        <td></td>
                      </tr>
                    </template>
                    <tr v-for="item in loading ? [] : items" :key="item.cve_id">
                      <td>
                        <button class="cve-link mono" @click="openDetail(item)">
                          {{ item.cve_id }}
                          <ArrowUpRight :size="13" />
                        </button>
                        <p class="table-description">
                          {{
                            (!item.study?.description_stale && item.study?.description_zh) ||
                            item.description ||
                            '上游暂未提供描述。'
                          }}
                        </p>
                        <div class="row-study-meta">
                          <span
                            v-for="topic in item.study?.topics || []"
                            :key="topic"
                            class="topic-tag"
                          >
                            {{ topic }}
                          </span>
                          <span v-if="item.study?.document_count" class="local-doc-count">
                            {{ item.study.document_count }} 篇本地资料 ·
                            {{
                              item.study.translation_status === 'complete' ? '中英对照' : '英文原文'
                            }}
                          </span>
                        </div>
                        <span v-if="item.vuln_status === 'Rejected'" class="rejected-label">
                          已拒绝记录
                        </span>
                      </td>
                      <td><SeverityBadge :severity="item.severity" /></td>
                      <td>
                        <span class="table-score" :class="item.severity.toLowerCase()">
                          {{ scoreText(item.cvss_score) }}
                        </span>
                        <small class="score-version">
                          {{ item.cvss_version ? `v${item.cvss_version}` : '未评分' }}
                        </small>
                      </td>
                      <td class="date-cell">{{ formatDate(item.last_modified_at) }}</td>
                      <td>
                        <button
                          class="icon-button row-action"
                          :aria-label="`查看 ${item.cve_id} 详情`"
                          :disabled="!!detailLoading"
                          @click="openDetail(item)"
                        >
                          <LoaderCircle
                            v-if="detailLoading === item.cve_id"
                            :size="17"
                            class="spin"
                          />
                          <ChevronRight v-else :size="17" />
                        </button>
                      </td>
                    </tr>
                  </tbody>
                </table>
                <div v-if="!loading && !items.length" class="empty-state">
                  <span class="empty-icon"><FileSearch :size="32" :stroke-width="1.3" /></span>
                  <h3>
                    {{
                      listError
                        ? '暂时无法读取情报'
                        : hasFilter
                          ? '没有找到匹配的漏洞'
                          : '你的情报库，等待第一条线索'
                    }}
                  </h3>
                  <p>
                    {{
                      listError
                        ? '请检查服务连接后重试。'
                        : hasFilter
                          ? '试试其他关键词，或清除筛选条件。'
                          : '同步一条 CVE，开始探索真实的漏洞数据。'
                    }}
                  </p>
                  <button v-if="hasFilter" class="button secondary" @click="resetFilters">
                    清除筛选
                  </button>
                  <button
                    v-else-if="!listError"
                    class="button primary"
                    :disabled="!!active"
                    @click="syncOpen = true"
                  >
                    <Download :size="16" />
                    同步第一条漏洞
                  </button>
                </div>
              </div>
              <div class="pagination">
                <span>
                  共 {{ total ?? '—' }} 条
                  <span class="pagination-divider">·</span>
                  <select v-model.number="pageSize" aria-label="每页条数" @change="applyFilters">
                    <option :value="10">10 条 / 页</option>
                    <option :value="20">20 条 / 页</option>
                    <option :value="50">50 条 / 页</option>
                  </select>
                </span>
                <div>
                  <button
                    class="icon-button"
                    aria-label="上一页"
                    :disabled="page <= 1 || loading"
                    @click="movePage(-1)"
                  >
                    <ChevronLeft :size="16" />
                  </button>
                  <span class="page-number">{{ page }}</span>
                  <span class="page-total">/ {{ pages }}</span>
                  <button
                    class="icon-button"
                    aria-label="下一页"
                    :disabled="page >= pages || loading"
                    @click="movePage(1)"
                  >
                    <ChevronRight :size="16" />
                  </button>
                </div>
              </div>
            </section>

            <aside class="insight-column">
              <section class="panel source-panel">
                <div class="mini-heading">
                  <span class="icon-tile small"><Globe2 :size="18" /></span>
                  <span class="eyebrow">CONNECTED SOURCE</span>
                </div>
                <h2>
                  多源漏洞资料
                  <span class="verified-icon"><Check :size="11" /></span>
                </h2>
                <p>
                  NVD · CVE CNA · GitHub Advisory
                  <br />
                  原始记录、维护者公告与本地正文
                </p>
                <div class="source-divider"></div>
                <div class="source-fact">
                  <span>数据接口</span>
                  <strong>NVD / CVE / GHSA</strong>
                </div>
                <div class="source-fact">
                  <span>存储位置</span>
                  <strong>
                    <Database :size="12" />
                    本地 PostgreSQL
                  </strong>
                </div>
                <div class="source-fact">
                  <span>评分版本</span>
                  <strong class="mono">4.0 / 3.1 / 3.0 / 2.0</strong>
                </div>
                <a
                  href="https://nvd.nist.gov/developers/vulnerabilities"
                  target="_blank"
                  rel="noopener noreferrer"
                  class="text-link"
                >
                  查看数据源文档
                  <ArrowUpRight :size="14" />
                </a>
              </section>
              <section class="panel quality-panel">
                <div class="small-panel-heading">
                  <h3>当前页数据质量</h3>
                  <ShieldCheck :size="17" />
                </div>
                <div class="quality-value">
                  {{ items.length ? Math.round((currentRated / items.length) * 100) : '—' }}
                  <small v-if="items.length">%</small>
                  <span>评分覆盖率</span>
                </div>
                <div class="quality-track">
                  <span
                    :style="{ width: `${items.length ? (currentRated / items.length) * 100 : 0}%` }"
                  ></span>
                </div>
                <div class="quality-caption">
                  <span>{{ currentRated }} / {{ items.length }} 条已有评分</span>
                  <span>当前页</span>
                </div>
                <p class="quality-note">
                  缺失评分保留为空值，不以 0 分替代。{{
                    currentRejected ? `当前页包含 ${currentRejected} 条已拒绝记录。` : ''
                  }}
                </p>
              </section>
              <button class="workflow-card" @click="view = 'guide'">
                <span class="workflow-icon"><BookOpen :size="21" /></span>
                <strong>从情报到理解</strong>
                <p>了解评分策略与同步工作流</p>
                <ArrowUpRight :size="17" class="workflow-arrow" />
                <span class="workflow-line"></span>
              </button>
            </aside>
          </div>
          <div class="bottom-note">
            <ShieldCheck :size="14" />
            <span>所有漏洞数据均来自本地持久化记录</span>
            <span class="last-refreshed">
              {{ refreshedAt ? `最近刷新 ${formatDate(refreshedAt, true)}` : '等待数据读取' }}
            </span>
          </div>
        </template>

        <template v-else-if="view === 'tasks'">
          <section class="sync-intro">
            <span class="sync-intro-icon"><ArrowDownToLine :size="32" :stroke-width="1.5" /></span>
            <div>
              <span class="eyebrow">SYNC YOUR INTELLIGENCE</span>
              <h2>与官方情报保持连接</h2>
              <p>按 CVE 编号精确获取，或按关键词探索。同步完成后，数据自动进入本地情报库。</p>
            </div>
            <button class="button primary" :disabled="!!active" @click="syncOpen = true">
              创建同步
              <ArrowRight :size="16" />
            </button>
          </section>
          <section class="panel task-panel">
            <div class="panel-heading">
              <div>
                <h2>
                  最近同步任务
                  <span class="count-label">{{ history.length }}</span>
                </h2>
                <p>仅保留本浏览器最近 8 个任务。状态以服务端记录为准。</p>
              </div>
              <Clock3 :size="19" class="muted" />
            </div>
            <div v-if="!history.length" class="empty-state">
              <span class="empty-icon"><RefreshCw :size="30" :stroke-width="1.3" /></span>
              <h3>还没有同步记录</h3>
              <p>点击「创建同步」，获取你的第一条漏洞情报。</p>
            </div>
            <article v-for="task in history" :key="task.id" class="task-row">
              <span
                class="task-state-icon"
                :class="task.unavailable ? 'unknown' : task.status.toLowerCase()"
              >
                <CheckCircle2 v-if="task.status === 'SUCCESS'" :size="21" />
                <LoaderCircle
                  v-else-if="task.status === 'RUNNING' && !task.unavailable"
                  :size="21"
                  class="spin"
                />
                <Clock3 v-else :size="21" />
              </span>
              <div class="task-summary">
                <strong>{{ task.label || 'NVD 同步' }}</strong>
                <p class="mono">{{ task.id }}</p>
                <span v-if="task.error" class="task-error">{{ task.error }}</span>
              </div>
              <div class="task-result">
                <span class="status-tag" :class="task.unavailable ? '' : task.status.toLowerCase()">
                  {{ task.unavailable ? '记录不可用 / 已过期' : taskLabels[task.status] }}
                </span>
                <p v-if="task.status === 'SUCCESS'">
                  处理 {{ task.processed }} 条 · 写入 {{ task.changed }} 次
                </p>
                <p v-else>{{ formatDate(task.updated_at, true) }}</p>
              </div>
            </article>
          </section>
          <div class="info-note task-caveat">
            <CircleHelp :size="18" />
            <p>
              同步在服务进程内执行。应用中断后，未完成任务可能失败；状态过期或读取中断时可重新查询，再提交幂等同步。
            </p>
          </div>
        </template>

        <template v-else>
          <section class="guide-hero">
            <span class="eyebrow">SMALL PROJECT. REAL DATA.</span>
            <h2>一条清晰的情报工作流。</h2>
            <p>获取、理解、追踪。用真实漏洞数据，探索安全情报与 Python 工程化。</p>
            <div class="workflow-steps">
              <div>
                <Download :size="23" />
                <strong>01. 同步情报</strong>
                <span>按 CVE 编号或关键词获取</span>
              </div>
              <ArrowRight :size="21" />
              <div>
                <Database :size="23" />
                <strong>02. 本地持久化</strong>
                <span>保留原始数据与字段修订</span>
              </div>
              <ArrowRight :size="21" />
              <div>
                <FileSearch :size="23" />
                <strong>03. 检索与理解</strong>
                <span>筛选漏洞，追溯评分与来源</span>
              </div>
            </div>
          </section>
          <div class="guide-grid">
            <article class="panel guide-card">
              <span class="icon-tile"><BookOpen :size="21" /></span>
              <h3>直接在这里学习漏洞</h3>
              <p>
                按系统或语言筛选，打开「双语学习资料」即可阅读本地公告、英文原文和中文机器翻译。受影响版本保留上游范围与状态；下载学习包可离线保存
                JSON 和中英 Markdown。
              </p>
            </article>
            <article class="panel guide-card">
              <span class="icon-tile"><ShieldCheck :size="21" /></span>
              <h3>如何选择代表评分？</h3>
              <p>
                优先级为 CVSS 4.0 → 3.1 → 3.0 → 2.0。同版本优先 Primary，再优先 NVD
                来源。详情页保留所有评分与原始数据。
              </p>
            </article>
            <article class="panel guide-card">
              <span class="icon-tile"><FileSearch :size="21" /></span>
              <h3>未评分意味着什么？</h3>
              <p>
                暂无有效评分时显示「待评分」与破折号。0 分是有效评分，不能用来代替缺失值。Rejected
                记录保留，但不展示代表评分。
              </p>
            </article>
            <article class="panel guide-card">
              <span class="icon-tile"><RefreshCw :size="21" /></span>
              <h3>为什么同步需要等待？</h3>
              <p>
                请求遵守 NVD
                官方配额，遇到限流会进行有限次数重试。同一时间仅允许一个同步任务，成功后自动刷新当前列表。
              </p>
            </article>
            <article class="panel guide-card">
              <span class="icon-tile"><BookOpen :size="21" /></span>
              <h3>继续探索项目</h3>
              <p>
                这是一个本地学习工作台。可以通过 API
                文档检查请求参数和返回契约，进一步理解每一条数据的流转。
              </p>
              <a href="/docs" target="_blank" rel="noopener noreferrer" class="text-link">
                打开 API 文档
                <ExternalLink :size="14" />
              </a>
            </article>
          </div>
        </template>
        <footer class="page-footer">
          <span>
            VulnArena
            <span class="footer-divider">/</span>
            让每一条情报都有迹可循。
          </span>
          <span>Built for curiosity. NVD · CVE · GHSA.</span>
        </footer>
      </main>
    </div>
    <SyncDialog v-if="syncOpen" :submit="submit" :busy="submitting" @close="syncOpen = false" />
    <VulnerabilityDrawer
      v-if="selected"
      :record="selected"
      @close="selected = null"
      @updated="
        (record) => {
          selected = record
          loadList()
        }
      "
    />
  </div>
</template>
