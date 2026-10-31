<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import {
  Sparkles,
  Search,
  BookOpen,
  BarChart3,
  Database,
  RefreshCw,
  ArrowUpRight,
  Square,
} from 'lucide-vue-next'
import { api, streamAnswer } from '../api'
import EvidenceSources from './EvidenceSources.vue'
import { formatDate } from '../format'

const emit = defineEmits(['open-cve', 'browse'])
const tab = ref('assistant')
const status = ref(null)
const dashboard = ref(null)
const error = ref('')
const statusError = ref('')
const question = ref('')
const busy = ref(false)
const phase = ref('')
const answer = ref(null)
const sources = ref([])
const selected = ref(null)
const reviewSelected = ref(null)
const year = ref('')
const topic = ref('')
const severity = ref('')
const mode = ref('hybrid')
const indexLimit = ref(5000)
const startingJob = ref(false)
const includeGeneration = ref(false)
const evaluationDataset = ref('development')
const report = ref(null)
const reportError = ref('')
let pollTimer
let controller
let askSequence = 0
let runningEvaluationId = ''
let disposed = false
const activeJobs = computed(() =>
  (status.value?.jobs || []).filter((job) => ['pending', 'running'].includes(job.status)),
)
const evaluations = computed(() =>
  (dashboard.value?.jobs || []).filter(
    (job) => job.kind === 'evaluation' && job.status === 'complete',
  ),
)
const failedJobs = computed(() =>
  (status.value?.jobs || []).filter(
    (job, index, jobs) =>
      ['failed', 'interrupted'].includes(job.status) &&
      jobs.findIndex((other) => other.kind === job.kind) === index,
  ),
)
const remainingCalls = computed(() =>
  status.value
    ? Math.max(
        0,
        (status.value?.limits.daily_model_calls || 0) -
          (status.value?.limits.daily_calls_used || 0),
      )
    : null,
)
const phases = {
  retrieving: '检索本地原文',
  sources: '已找到资料，准备解释',
  generating: '正在生成并校验原文引用',
  complete: '已完成',
  cancelled: '已停止等待',
}
const samples = [
  '解释 CVE-2021-44228 的原因与影响',
  '2024 年 Python 高危漏洞有多少条？',
  'Linux 管道缓冲区如何导致只读文件被修改和提权？',
]
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
]
const number = (value) => (value == null ? '—' : Number(value).toLocaleString())
const percent = (value) => (value == null ? '—' : (value * 100).toFixed(1) + '%')
const duration = (value) => (value == null ? '—' : (value / 1000).toFixed(2) + ' s')
const jobLabels = {
  pending: '准备中',
  running: '运行中',
  complete: '已完成',
  failed: '未完成',
  interrupted: '已中断',
}

async function refresh() {
  const values = await Promise.allSettled([api.aiStatus(), api.aiDashboard()])
  if (disposed) return
  if (values[0].status === 'fulfilled') {
    status.value = values[0].value
    statusError.value = ''
  } else statusError.value = values[0].reason.message || 'AI 服务状态读取失败。'
  if (values[1].status === 'fulfilled') {
    dashboard.value = values[1].value
    const completedRun = evaluations.value.find((job) => job.id === runningEvaluationId)
    if (completedRun) {
      report.value = completedRun
      runningEvaluationId = ''
    }
    if (!report.value && evaluations.value.length) report.value = evaluations.value[0]
  }
}
async function poll() {
  await refresh()
  if (!disposed) pollTimer = setTimeout(poll, activeJobs.value.length ? 3500 : 30000)
}
async function ask() {
  if (busy.value || question.value.trim().length < 2) return
  const sequence = ++askSequence
  busy.value = true
  error.value = ''
  answer.value = null
  sources.value = []
  selected.value = null
  phase.value = 'retrieving'
  controller = new AbortController()
  const requestController = controller
  const filters = {}
  if (year.value) {
    filters.year_from = Number(year.value)
    filters.year_to = Number(year.value)
  }
  if (topic.value) filters.topic = topic.value
  if (severity.value) filters.severity = severity.value
  try {
    await streamAnswer(
      { question: question.value.trim(), filters, mode: mode.value },
      (event, data) => {
        if (disposed || sequence !== askSequence) return
        if (event === 'phase') {
          phase.value = data.phase
          if (data.sources) sources.value = data.sources
        }
        if (event === 'answer') {
          answer.value = data
          sources.value = data.sources || []
          phase.value = 'complete'
        }
        if (event === 'error') error.value = data.message
      },
      requestController.signal,
    )
  } catch (failure) {
    if (!disposed && sequence === askSequence && failure.name !== 'AbortError')
      error.value = failure.message
  } finally {
    if (!disposed && sequence === askSequence) {
      busy.value = false
      void refresh()
    }
  }
}
function stop() {
  askSequence++
  controller?.abort()
  phase.value = 'cancelled'
  busy.value = false
}
async function buildIndex() {
  startingJob.value = true
  error.value = ''
  try {
    await api.aiIndex(Number(indexLimit.value))
    await refresh()
    clearTimeout(pollTimer)
    pollTimer = setTimeout(poll, 1500)
  } catch (failure) {
    error.value = failure.message
  } finally {
    startingJob.value = false
  }
}
async function evaluate() {
  startingJob.value = true
  error.value = ''
  try {
    const job = await api.aiEvaluate(includeGeneration.value, evaluationDataset.value)
    runningEvaluationId = job.id
    await refresh()
    clearTimeout(pollTimer)
    pollTimer = setTimeout(poll, 1500)
  } catch (failure) {
    error.value = failure.message
  } finally {
    startingJob.value = false
  }
}
async function loadReport(job) {
  reportError.value = ''
  if (!job) {
    report.value = null
    return
  }
  try {
    report.value = await api.aiJob(job.id)
  } catch (failure) {
    reportError.value = failure.message
  }
}
async function cancelJob(id) {
  try {
    await api.aiCancelJob(id)
    await refresh()
  } catch (failure) {
    error.value = failure.message
  }
}
function exportReport() {
  if (!report.value) return
  const blob = new Blob([JSON.stringify(report.value, null, 2)], {
    type: 'application/json;charset=utf-8',
  })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = 'NVD-AI-evaluation-' + report.value.id + '.json'
  link.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
async function exportReviewTemplate() {
  if (!report.value) return
  try {
    const body = await api.aiReviewTemplate(report.value.id)
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(body, null, 2)], { type: 'application/json' }),
    )
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = 'human-review-' + report.value.id + '.json'
    anchor.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  } catch (failure) {
    reportError.value = failure.message
  }
}
async function importReviews(event) {
  const file = event.target.files?.[0]
  if (!file || !report.value) return
  try {
    if (file.size > 1000000) throw new Error('评审文件不得超过 1 MB。')
    const body = JSON.parse(await file.text())
    if (body.report_id !== report.value.id) throw new Error('评审文件与当前报告编号不一致。')
    report.value = await api.aiSaveReviews(report.value.id, body.reviews)
    reportError.value = ''
  } catch (failure) {
    reportError.value = failure.message
  }
  event.target.value = ''
}
const failedCases = computed(() =>
  (report.value?.result.rows || [])
    .filter(
      (row) =>
        !row.skipped && (row.expected_abstain ? row.retrieved_cves.length : row.recall_at_5 === 0),
    )
    .slice(0, 12),
)
onMounted(poll)
onUnmounted(() => {
  disposed = true
  clearTimeout(pollTimer)
  controller?.abort()
})
</script>

<template>
  <section class="ai-workspace" aria-label="NVD AI 情报助手">
    <div class="ai-intro">
      <div class="ai-orbit"><Sparkles :size="25" /></div>
      <div>
        <span class="eyebrow">READ WITH EVIDENCE</span>
        <h2>把漏洞资料，变成有依据的理解。</h2>
        <p>检索本地原文，查看引用，再决定如何使用答案。</p>
      </div>
      <span class="provider-pill">
        {{ !status ? '读取模型配置…' : status.configured ? status.model : '模型尚未配置' }}
      </span>
    </div>
    <div class="ai-navigation" role="tablist" aria-label="AI 工作区">
      <button
        role="tab"
        :aria-selected="tab === 'assistant'"
        :class="{ selected: tab === 'assistant' }"
        @click="tab = 'assistant'"
      >
        <BookOpen :size="16" />
        知识问答
      </button>
      <button
        role="tab"
        :aria-selected="tab === 'quality'"
        :class="{ selected: tab === 'quality' }"
        @click="tab = 'quality'"
      >
        <BarChart3 :size="16" />
        质量评测与调用
      </button>
      <button class="refresh-ai" aria-label="刷新 AI 状态" @click="refresh">
        <RefreshCw :size="15" />
      </button>
    </div>
    <p v-if="error || statusError" class="ai-error" role="alert">{{ error || statusError }}</p>
    <div class="index-panel">
      <Database :size="19" />
      <div class="index-copy">
        <strong>
          代表性证据索引
          <span>
            {{ number(status?.index.records) }} 条 CVE · {{ number(status?.index.chunks) }} 段原文
          </span>
        </strong>
        <p>
          CVE 编号可查全库；自然语言检索覆盖已建立的索引。CPU 最多
          {{ status?.limits.embedding_threads || 2 }} 线程，空闲后卸载模型。
        </p>
        <p v-if="status?.index.outdated_records" class="ai-warning">
          {{ number(status.index.outdated_records) }} 条旧版索引待升级；当前可用
          {{ number(status.index.current_records) }} 条。
        </p>
        <small v-if="status?.build_id">
          构建 {{ status.build_id }} · {{ status.index.source_version }}
        </small>
      </div>
      <select v-model="indexLimit" aria-label="语义索引记录数量">
        <option :value="1000">1,000 条</option>
        <option :value="5000">5,000 条</option>
        <option :value="10000">10,000 条</option>
      </select>
      <button
        class="button secondary"
        :disabled="startingJob || !!activeJobs.length || !status?.embedding_available"
        @click="buildIndex"
      >
        {{ activeJobs.some((job) => job.kind === 'index') ? '索引构建中…' : '构建 / 更新索引' }}
      </button>
    </div>
    <p v-if="status && !status.embedding_available" class="ai-warning">
      语义模型尚未配置。CVE 编号查询仍可用；请按使用指南配置本地 CPU 语义模型。
    </p>
    <article v-for="job in activeJobs" :key="job.id" class="job-progress" role="status">
      <div>
        <strong>
          {{ job.kind === 'index' ? '证据索引' : 'AI 评测' }} · {{ jobLabels[job.status] }}
        </strong>
        <span>{{ number(job.progress) }} / {{ number(job.total) }}</span>
      </div>
      <progress :value="job.progress" :max="job.total || 1"></progress>
      <button type="button" class="text-link" @click="cancelJob(job.id)">
        停止任务，保留已保存数据
      </button>
      <small>{{ job.result?.current_cve || job.result?.stage || '准备资料与模型，请稍候…' }}</small>
    </article>
    <p v-for="job in failedJobs" :key="job.id" class="ai-warning">
      {{ job.kind === 'index' ? '最近索引任务' : '最近评测任务' }}：{{ job.error }}
      已保存的数据仍保留，可重新发起。
    </p>

    <template v-if="tab === 'assistant'">
      <form class="question-box" @submit.prevent="ask">
        <label for="ai-question">想了解哪个漏洞或技术问题？</label>
        <textarea
          id="ai-question"
          v-model="question"
          maxlength="1000"
          rows="3"
          placeholder="例如：解释 Log4j 的 JNDI 漏洞，列出触发条件并引用原文。"
          @keydown.ctrl.enter.prevent="ask"
        ></textarea>
        <div class="question-filters">
          <select v-model="year" aria-label="AI 查询 CVE 年份">
            <option value="">全部年份</option>
            <option
              v-for="item in [2026, 2025, 2024, 2023, 2022, 2021, 2020]"
              :key="item"
              :value="String(item)"
            >
              {{ item }} 年
            </option>
          </select>
          <select v-model="topic" aria-label="AI 查询生态">
            <option value="">全部生态</option>
            <option v-for="item in topics" :key="item">{{ item }}</option>
          </select>
          <select v-model="severity" aria-label="AI 查询严重度">
            <option value="">全部严重度</option>
            <option value="CRITICAL">严重</option>
            <option value="HIGH">高危</option>
            <option value="MEDIUM">中危</option>
            <option value="LOW">低危</option>
          </select>
          <select v-model="mode" aria-label="AI 检索方式">
            <option value="hybrid">混合检索</option>
            <option value="keyword">关键词检索</option>
            <option value="semantic">语义检索</option>
          </select>
          <button v-if="busy" type="button" class="button secondary ask-button" @click="stop">
            <Square :size="14" />
            停止等待
          </button>
          <button v-else class="button primary ask-button" :disabled="question.trim().length < 2">
            <Search :size="15" />
            检索并回答
          </button>
        </div>
        <div class="sample-questions">
          <button v-for="sample in samples" :key="sample" type="button" @click="question = sample">
            {{ sample }}
            <ArrowUpRight :size="12" />
          </button>
        </div>
        <p class="question-note">
          有依据才解释；每次独立检索。统计直接查询数据库。模型生成按需调用，今日剩余
          {{ remainingCalls ?? '—' }} 次请求额度（UTC 日重置）。问题与检索片段会发送给已配置模型。
        </p>
      </form>
      <div class="answer-grid">
        <section class="answer-panel" aria-label="AI 回答">
          <div class="answer-title">
            <Sparkles :size="18" />
            <h3>
              {{
                busy
                  ? phases[phase] || '处理中'
                  : answer
                    ? '基于本地资料的回答'
                    : '从一个具体问题开始'
              }}
            </h3>
            <span v-if="answer?.telemetry.cached" class="cache-pill">命中缓存</span>
          </div>
          <p v-if="!busy && !answer" class="answer-empty">
            这里会展示中文解释、原文引用和资料缺口。可以先问一个 CVE，再到详情页生成五段学习卡片。
          </p>
          <div v-if="busy" class="answer-working">
            <RefreshCw :size="18" class="spin" />
            {{ phases[phase] || '处理中' }}，校验通过后展示答案。
          </div>
          <template v-if="answer">
            <p v-if="answer.message" class="ai-warning">{{ answer.message }}</p>
            <div v-if="answer.statistics" class="statistics-answer">
              <span>本地数据库统计结果</span>
              <strong>
                {{ number(answer.statistics.count) }}
                <small>条</small>
              </strong>
              <p>{{ answer.statistics.scope }}</p>
              <p>
                {{ answer.statistics.source }} · CVE 编号年份
                {{ answer.statistics.filters.year_from || '全部' }}
                <template
                  v-if="
                    answer.statistics.filters.year_to &&
                    answer.statistics.filters.year_to !== answer.statistics.filters.year_from
                  "
                >
                  –{{ answer.statistics.filters.year_to }}
                </template>
                · {{ answer.statistics.filters.topic || '全部生态' }} ·
                {{
                  { CRITICAL: '严重', HIGH: '高危', MEDIUM: '中危', LOW: '低危' }[
                    answer.statistics.filters.severity
                  ] || '全部严重度'
                }}
                <template v-if="answer.statistics.keyword">
                  · 关键词 {{ answer.statistics.keyword }}
                </template>
              </p>
              <button
                class="text-link"
                @click="
                  emit('browse', {
                    ...answer.statistics.filters,
                    keyword: answer.statistics.keyword,
                  })
                "
              >
                在情报库查看筛选结果
              </button>
            </div>
            <article
              v-for="(claim, index) in answer.claims || []"
              :key="index"
              class="answer-claim"
            >
              <p>{{ claim.text }}</p>
              <button
                v-for="(reference, ri) in claim.references"
                :key="ri"
                class="citation-button"
                @click="selected = reference"
              >
                [{{ reference.source_id }}] 查看原文
              </button>
            </article>
            <div v-if="answer.missing_information?.length" class="missing-info">
              <strong>资料缺口</strong>
              <p v-for="item in answer.missing_information" :key="item">{{ item }}</p>
            </div>
            <p v-if="answer.telemetry" class="answer-meta">
              耗时 {{ duration(answer.telemetry.latency_ms) }} · 检索
              {{ duration(answer.telemetry.retrieval_ms) }} · {{ answer.telemetry.mode }} · 请求
              {{ answer.trace_id?.slice(0, 8) }}
            </p>
            <p class="answer-meta">{{ answer.note }}</p>
          </template>
        </section>
        <EvidenceSources
          :sources="sources"
          :selected="selected"
          @open-cve="emit('open-cve', $event)"
        />
      </div>
    </template>
    <template v-else>
      <div class="quality-stats" aria-label="AI 调用统计">
        <article>
          <small>模型请求 / 全部请求</small>
          <strong>
            {{ number(dashboard?.model_calls) }}
            <span>/ {{ number(dashboard?.requests) }}</span>
          </strong>
        </article>
        <article>
          <small>P95 请求耗时</small>
          <strong>{{ duration(dashboard?.p95_ms) }}</strong>
        </article>
        <article>
          <small>输入 / 输出 Token</small>
          <strong>
            {{ number(dashboard?.input_tokens) }}
            <span>/ {{ number(dashboard?.output_tokens) }}</span>
          </strong>
        </article>
        <article>
          <small>模型费用估算（{{ status?.price_reference?.currency || '参考币种' }}）</small>
          <strong>
            {{
              dashboard?.estimated_cost == null ? '未配置单价' : dashboard.estimated_cost.toFixed(5)
            }}
          </strong>
          <p v-if="dashboard?.unpriced_calls">{{ dashboard.unpriced_calls }} 次请求缺少费用估算</p>
        </article>
      </div>
      <p class="quality-note">
        {{ status?.price_reference?.note }}
      </p>
      <p class="quality-note">
        {{ dashboard?.window }} 缓存命中 {{ number(dashboard?.cache_hits) }} 次；引用或结构校验拒绝
        {{ number(dashboard?.validation_failures) }} 次。
        <span v-if="dashboard?.usage_unknown_calls">
          {{ dashboard.usage_unknown_calls }} 次模型请求未返回用量。
        </span>
      </p>
      <section class="evaluation-panel">
        <div class="evaluation-heading">
          <div>
            <span class="eyebrow">MEASURE BEFORE OPTIMIZING</span>
            <h3>检索与回答评测</h3>
            <p>开发基线与独立留出集分别保存，三种检索方式分别运行。留出集尚未经过独立人工标注。</p>
          </div>
          <button
            class="button primary"
            :disabled="startingJob || !!activeJobs.length || !status?.index.records"
            @click="evaluate"
          >
            运行评测
          </button>
        </div>
        <label class="generation-choice">
          <input v-model="includeGeneration" type="checkbox" />
          追加最多 5 题生成检查，会调用已配置模型并占用每日额度。
        </label>
        <label class="generation-choice">
          评测题集
          <select v-model="evaluationDataset" aria-label="评测题集">
            <option value="development">开发集 · 100 题 / 20 个 CVE</option>
            <option value="regression">扩展回归 · 25 题 / 10 个 CVE（已用于诊断）</option>
            <option value="holdout">留出集 · 25 题 / 10 个不同 CVE</option>
          </select>
        </label>
        <div class="report-picker">
          <select
            :value="report?.id || ''"
            aria-label="选择评测报告"
            @change="loadReport(evaluations.find((job) => job.id === $event.target.value))"
          >
            <option value="">暂无报告</option>
            <option v-for="job in evaluations" :key="job.id" :value="job.id">
              {{ formatDate(job.created_at, true) }} · {{ job.id.slice(0, 8) }}
            </option>
          </select>
          <button v-if="report" class="text-link" @click="loadReport(report)">查看逐题结果</button>
          <button v-if="report?.result.rows" class="text-link" @click="exportReport">
            下载完整报告 JSON
          </button>
          <button
            v-if="report?.result.generation?.length"
            class="text-link"
            @click="exportReviewTemplate"
          >
            下载人工评审表
          </button>
          <label v-if="report?.result.generation?.length" class="text-link">
            导入已填写评审
            <input
              type="file"
              accept="application/json,.json"
              aria-label="导入人工评审 JSON"
              @change="importReviews"
            />
          </label>
        </div>
        <p v-if="reportError" class="ai-error">{{ reportError }}</p>
        <template v-if="report?.result.modes">
          <p class="quality-note">
            当前报告：{{
              { development: '开发集', regression: '扩展回归', holdout: '留出集' }[
                report.result.dataset
              ] || '历史报告'
            }}
            · {{ report.result.dataset_version || '未记录题集版本' }}
          </p>
          <p class="quality-note">
            {{ report.result.dataset_note }} {{ report.result.classification_note }}
          </p>
          <div class="quality-table-wrap">
            <table>
              <thead>
                <tr>
                  <th>检索方式</th>
                  <th>自然语言 Recall@5</th>
                  <th>自然语言 MRR</th>
                  <th>负例检索无返回率</th>
                  <th>平均检索耗时</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="(metrics, key) in report.result.modes" :key="key">
                  <td>{{ { keyword: '关键词', semantic: '语义', hybrid: '混合 RRF' }[key] }}</td>
                  <td>{{ percent(report.result.natural_language?.[key]?.recall_at_5) }}</td>
                  <td>{{ report.result.natural_language?.[key]?.mrr ?? '—' }}</td>
                  <td>{{ percent(metrics.no_evidence_accuracy) }}</td>
                  <td>{{ metrics.mean_retrieval_ms }} ms</td>
                </tr>
              </tbody>
            </table>
          </div>
          <p class="quality-note">
            自然语言指标单独排除精确 CVE 编号题。部分缺少索引的题会跳过，跳过数会保存在报告中。{{
              report.result.generation_note
            }}
          </p>
          <section v-if="report.result.generation?.length" class="generation-results">
            <h4>生成抽查记录</h4>
            <p class="quality-note">
              引文校验只检查来源和原文位置。打开每题结果核对语义；这些样例保留“待人工复核”状态。
            </p>
            <details
              v-for="sample in report.result.generation"
              :key="sample.trace_id"
              class="generation-case"
            >
              <summary>
                {{ sample.question }} ·
                {{
                  sample.quote_validation_status === 'no_citations'
                    ? '资料不足，无引文可校验'
                    : sample.quote_validation_status === 'legacy_unverified'
                      ? '历史记录待核对'
                      : sample.quote_validation_passed
                        ? '引文位置通过'
                        : '未通过引文校验'
                }}
                ·
                {{
                  sample.human_entailment_review === 'reviewed' ? '已登记人工复核' : '待人工复核'
                }}
              </summary>
              <template v-if="sample.answer">
                <p v-if="sample.latest_human_review" class="quality-note">
                  {{ sample.latest_human_review.reviewer }} ·
                  {{ sample.latest_human_review.verdict }}：{{
                    sample.latest_human_review.explanation
                  }}
                </p>
                <p v-if="sample.answer.message" class="ai-warning">{{ sample.answer.message }}</p>
                <div v-if="sample.answer.missing_information?.length" class="missing-information">
                  <strong>资料缺口</strong>
                  <p v-for="(item, i) in sample.answer.missing_information" :key="i">{{ item }}</p>
                </div>
                <article
                  v-for="(claim, i) in sample.answer.claims || []"
                  :key="i"
                  class="answer-claim"
                >
                  <p>{{ claim.text }}</p>
                  <button
                    v-for="(reference, ri) in claim.references"
                    :key="ri"
                    class="citation-button"
                    @click="reviewSelected = { ...reference, trace_id: sample.trace_id }"
                  >
                    [{{ reference.source_id }}] 查看原文
                  </button>
                </article>
                <EvidenceSources
                  :sources="sample.answer.sources"
                  :selected="reviewSelected?.trace_id === sample.trace_id ? reviewSelected : null"
                  @open-cve="emit('open-cve', $event)"
                />
              </template>
              <p v-else class="quality-note">
                点击“查看逐题结果”载入完整回答与依据；早期报告可能只保存调用信息。
              </p>
            </details>
          </section>
          <details v-if="report.result.rows">
            <summary>需要改进的样例（最多显示 12 条）</summary>
            <p v-if="!failedCases.length" class="quality-note">
              本轮没有命中失败的样例。请继续增加独立留出测试集。
            </p>
            <article v-for="row in failedCases" :key="row.id + row.mode" class="failed-case">
              <strong>{{ row.question }}</strong>
              <p>
                {{ row.mode }} · 预期 {{ row.expected_cves.join(', ') || '无证据' }} · 返回
                {{ row.retrieved_cves.join(', ') || '无结果' }}
              </p>
            </article>
          </details>
        </template>
        <p v-else class="quality-note">
          建立索引后运行一次评测，结果将保存到本地数据库。默认只测检索，不消耗模型调用额度。
        </p>
      </section>
      <section class="trace-panel">
        <h3>最近调用记录</h3>
        <p class="quality-note">
          保留模型版本、提示词版本、耗时、Token、来源版本和校验状态；不记录 API Key。
        </p>
        <p v-if="!dashboard?.recent_traces.length" class="quality-note">暂无请求记录。</p>
        <div class="quality-table-wrap">
          <table>
            <thead>
              <tr>
                <th>问题 / 请求</th>
                <th>状态</th>
                <th>方式</th>
                <th>耗时</th>
                <th>Token 输入 / 输出</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="trace in dashboard?.recent_traces || []" :key="trace.id">
                <td>
                  <details>
                    <summary>{{ trace.question }}</summary>
                    <pre>{{
                      JSON.stringify(
                        {
                          id: trace.id,
                          model: trace.model,
                          prompt: trace.prompt_version,
                          sources: trace.cve_ids,
                          source_versions: trace.source_versions,
                          validation: trace.citation_check,
                        },
                        null,
                        2,
                      )
                    }}</pre>
                  </details>
                </td>
                <td>{{ trace.status }}</td>
                <td>{{ trace.cached ? '缓存' : trace.model_called ? '模型 API' : '本地' }}</td>
                <td>{{ duration(trace.latency_ms) }}</td>
                <td>{{ number(trace.input_tokens) }} / {{ number(trace.output_tokens) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </template>
  </section>
</template>

<style scoped>
.ai-workspace {
  color: #2d3b52;
}
.ai-intro {
  display: flex;
  align-items: center;
  gap: 18px;
  padding: 24px 28px;
  border-radius: 16px;
  background: linear-gradient(110deg, #edf2ff, #f8fbff);
  border: 1px solid #e0e8f7;
}
.ai-orbit {
  display: grid;
  place-items: center;
  width: 54px;
  height: 54px;
  flex-shrink: 0;
  background: white;
  color: #4e71bb;
  border-radius: 16px;
  box-shadow: 0 6px 20px #335da210;
}
.ai-intro h2 {
  font-size: 21px;
  margin: 7px 0;
}
.ai-intro p {
  font-size: 12px;
  color: #7a8aa4;
  margin: 0;
}
.provider-pill {
  margin-left: auto;
  border: 1px solid #d9e2f4;
  background: white;
  border-radius: 20px;
  padding: 7px 12px;
  font-size: 11px;
  color: #5873a6;
  max-width: 200px;
  overflow-wrap: anywhere;
}
.ai-navigation {
  display: flex;
  gap: 8px;
  margin: 22px 0;
}
.ai-navigation button {
  display: flex;
  align-items: center;
  gap: 8px;
  border: 0;
  border-radius: 8px;
  background: none;
  color: #8190a7;
  padding: 11px 16px;
  font-size: 13px;
  cursor: pointer;
}
.ai-navigation .selected {
  background: #eaf0ff;
  color: #3962b6;
}
.ai-navigation .refresh-ai {
  margin-left: auto;
}
.index-panel {
  display: flex;
  align-items: center;
  gap: 14px;
  border: 1px solid #e4e9f2;
  border-radius: 12px;
  background: white;
  padding: 18px;
  color: #6e84a9;
}
.index-copy {
  flex: 1;
  min-width: 0;
}
.index-copy strong {
  color: #40516d;
  font-size: 12px;
}
.index-copy strong span {
  font-weight: 400;
  margin-left: 8px;
  color: #7d8aa0;
}
.index-copy p,
.question-note,
.quality-note {
  font-size: 11px;
  line-height: 1.9;
  color: #8491a5;
  margin: 7px 0 0;
}
select {
  border: 1px solid #e1e7f0;
  border-radius: 7px;
  background: white;
  padding: 9px;
  font-size: 11px;
  color: #67788e;
  max-width: 100%;
}
.ai-error,
.ai-warning {
  font-size: 12px;
  line-height: 1.8;
  padding: 12px 15px;
  border-radius: 8px;
}
.ai-error {
  background: #fff1f1;
  color: #aa5353;
}
.ai-warning {
  background: #fff8e8;
  color: #987c43;
}
.job-progress {
  background: white;
  border: 1px solid #e2e8f5;
  border-radius: 10px;
  padding: 14px 18px;
  margin-top: 12px;
}
.job-progress > div {
  display: flex;
  justify-content: space-between;
  font-size: 12px;
}
.job-progress small {
  font-size: 10px;
  color: #8a97ab;
}
progress {
  width: 100%;
  height: 6px;
  accent-color: #7098ce;
  margin: 10px 0;
}
.question-box {
  background: white;
  border: 1px solid #dee5f2;
  border-radius: 14px;
  padding: 22px;
  margin: 20px 0;
}
.question-box label {
  font-size: 14px;
  font-weight: 600;
}
.question-box textarea {
  display: block;
  resize: vertical;
  width: 100%;
  box-sizing: border-box;
  border: 0;
  border-bottom: 1px solid #eef1f7;
  margin: 12px 0;
  padding: 9px 0;
  font: inherit;
  font-size: 14px;
  line-height: 1.9;
  color: #334764;
  outline: none;
}
.question-box textarea:focus {
  border-color: #82a0d9;
}
.question-filters {
  display: flex;
  gap: 8px;
  align-items: center;
  flex-wrap: wrap;
}
.ask-button {
  margin-left: auto;
}
.sample-questions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  margin-top: 17px;
}
.sample-questions button {
  display: flex;
  gap: 6px;
  align-items: center;
  background: #f5f7fb;
  border: 0;
  border-radius: 6px;
  padding: 8px 10px;
  font-size: 10px;
  color: #8090a9;
  cursor: pointer;
  text-align: left;
}
.sample-questions button:hover {
  color: #4167b4;
  background: #edf2ff;
}
.answer-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.2fr) minmax(0, 1fr);
  gap: 18px;
  align-items: start;
}
.answer-panel {
  background: white;
  border: 1px solid #e3e8f1;
  border-radius: 14px;
  padding: 23px;
  min-width: 0;
}
.answer-title {
  display: flex;
  gap: 10px;
  align-items: center;
  color: #5779b4;
}
.answer-title h3 {
  font-size: 14px;
  color: #324760;
  margin: 0;
}
.answer-empty {
  font-size: 13px;
  line-height: 2;
  color: #8d99ad;
  padding: 24px 0;
}
.answer-working {
  display: flex;
  gap: 10px;
  align-items: center;
  font-size: 12px;
  color: #8292aa;
  padding: 25px 0;
}
.answer-claim {
  padding: 17px 0;
  border-bottom: 1px solid #edf1f7;
}
.answer-claim p {
  white-space: pre-wrap;
  font-size: 13px;
  line-height: 2;
  margin: 0 0 9px;
}
.citation-button {
  background: #edf3ff;
  border: 0;
  padding: 5px 8px;
  border-radius: 5px;
  font-size: 10px;
  color: #4e6fae;
  cursor: pointer;
  margin: 3px 7px 0 0;
}
.cache-pill {
  font-size: 9px;
  background: #eaf7ef;
  color: #4e8a67;
  padding: 4px 6px;
  margin-left: auto;
  border-radius: 4px;
}
.answer-meta {
  font-size: 10px;
  line-height: 1.9;
  color: #8c99ad;
  overflow-wrap: anywhere;
}
.missing-info {
  margin-top: 18px;
  background: #fbf8f1;
  border-radius: 8px;
  padding: 14px;
  font-size: 12px;
  color: #988057;
}
.missing-info p {
  line-height: 1.8;
}
.statistics-answer {
  padding: 24px 0;
}
.statistics-answer > span {
  font-size: 12px;
  color: #8392a8;
}
.statistics-answer > strong {
  display: block;
  font-size: 39px;
  color: #456aa9;
  margin: 12px 0;
}
.statistics-answer small {
  font-size: 12px;
  font-weight: 400;
}
.statistics-answer p {
  font-size: 11px;
  line-height: 1.9;
  color: #8190a6;
  overflow-wrap: anywhere;
}
.quality-stats {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 13px;
  margin-top: 20px;
}
.quality-stats article {
  background: white;
  border: 1px solid #e5eaf2;
  border-radius: 11px;
  padding: 19px;
}
.quality-stats small {
  font-size: 10px;
  color: #8996a9;
}
.quality-stats strong {
  display: block;
  font-size: 21px;
  margin-top: 13px;
  overflow-wrap: anywhere;
}
.quality-stats strong span {
  font-size: 12px;
  color: #98a3b3;
}
.quality-stats p {
  font-size: 10px;
  color: #a5936a;
}
.evaluation-panel,
.trace-panel {
  border: 1px solid #e4e9f1;
  border-radius: 13px;
  background: white;
  padding: 23px;
  margin-top: 20px;
  min-width: 0;
}
.evaluation-heading {
  display: flex;
  align-items: center;
  gap: 15px;
  justify-content: space-between;
}
.evaluation-heading h3,
.trace-panel h3 {
  font-size: 15px;
  margin: 8px 0;
}
.evaluation-heading p {
  font-size: 11px;
  color: #8c99ad;
  line-height: 1.8;
}
.generation-choice {
  display: flex;
  align-items: center;
  gap: 7px;
  font-size: 11px;
  color: #8a96a9;
  margin: 14px 0;
}
.report-picker {
  display: flex;
  gap: 12px;
  align-items: center;
  flex-wrap: wrap;
  margin: 16px 0;
}
.quality-table-wrap {
  overflow-x: auto;
  max-width: 100%;
  margin-top: 18px;
}
.quality-table-wrap table {
  width: 100%;
  border-collapse: collapse;
  min-width: 560px;
}
.quality-table-wrap th {
  font-size: 10px;
  color: #8695ac;
  background: #f8fafd;
  text-align: left;
  padding: 12px;
}
.quality-table-wrap td {
  font-size: 11px;
  padding: 13px 12px;
  border-bottom: 1px solid #edf1f6;
  vertical-align: top;
  line-height: 1.8;
}
.quality-table-wrap td:first-child {
  max-width: 300px;
  overflow-wrap: anywhere;
}
.quality-table-wrap summary {
  cursor: pointer;
}
.quality-table-wrap pre {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  font-size: 10px;
  max-width: 280px;
}
.evaluation-panel > details {
  margin-top: 18px;
  font-size: 12px;
}
.evaluation-panel summary {
  cursor: pointer;
  color: #657f9f;
}
.failed-case {
  padding: 12px 0;
  border-bottom: 1px solid #edf0f4;
  font-size: 11px;
}
.failed-case p {
  color: #8b99ad;
  overflow-wrap: anywhere;
}
.generation-results {
  margin-top: 20px;
}
.generation-results h4 {
  font-size: 13px;
}
.generation-case {
  border-top: 1px solid #edf0f5;
  padding: 13px 0;
  font-size: 12px;
}
.generation-case summary {
  cursor: pointer;
  line-height: 1.9;
  color: #677f9f;
}
@media (max-width: 1150px) {
  .answer-grid {
    grid-template-columns: 1fr;
  }
  .index-panel {
    flex-wrap: wrap;
  }
  .quality-stats {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .provider-pill {
    display: none;
  }
}
@media (max-width: 600px) {
  .ai-intro {
    padding: 18px;
  }
  .ai-intro h2 {
    font-size: 17px;
  }
  .ai-orbit {
    display: none;
  }
  .index-copy {
    flex-basis: 80%;
  }
  .index-copy strong span {
    display: block;
    margin: 7px 0;
  }
  .question-box,
  .answer-panel,
  .evaluation-panel,
  .trace-panel {
    padding: 16px;
  }
  .question-filters select {
    flex: 1;
    min-width: 40%;
  }
  .ask-button {
    width: 100%;
    justify-content: center;
    margin-top: 8px;
  }
  .quality-stats {
    gap: 8px;
  }
  .quality-stats article {
    padding: 13px;
  }
  .quality-stats strong {
    font-size: 17px;
  }
  .evaluation-heading {
    align-items: start;
    flex-direction: column;
  }
}
</style>
