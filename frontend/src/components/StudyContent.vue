<script setup>
import { computed, onUnmounted, ref, watch } from 'vue'
import { Download, RefreshCw, ExternalLink, Languages, BookOpen } from 'lucide-vue-next'
import { api } from '../api'
import { formatDate, safeReference } from '../format'
import AIStudyCard from './AIStudyCard.vue'

const props = defineProps({ record: Object })
const emit = defineEmits(['updated'])
const language = ref('both')
const selectedArticle = ref(0)
const busy = ref(false)
const error = ref('')
const job = ref(null)
let timer
let summaryTimer
let summaryPolls = 0
const summaryBusy = ref(false)
const summaryError = ref('')
let disposed = false
const study = computed(() => props.record.study || {})
const documents = computed(() => study.value.documents || [])
const article = computed(() => documents.value[selectedArticle.value])

async function pollSummary() {
  if (disposed) return
  try {
    const status = await api.translationStatus(props.record.cve_id)
    if (disposed) return
    if (status.status === 'complete') {
      const updated = await api.detail(props.record.cve_id)
      if (!disposed) emit('updated', updated)
      summaryBusy.value = false
      return
    }
    if (status.status === 'failed' || ++summaryPolls >= 80)
      throw new Error('中文翻译暂未完成，请重试。')
    if (status.status === 'missing') await api.translate(props.record.cve_id)
    summaryTimer = setTimeout(pollSummary, 1500)
  } catch (failure) {
    if (!disposed) {
      summaryBusy.value = false
      summaryError.value = '中文翻译暂未就绪，可点击重试。'
    }
  }
}
async function requestSummary() {
  if (summaryBusy.value || !props.record.description?.trim()) return
  summaryBusy.value = true
  summaryError.value = ''
  summaryPolls = 0
  try {
    const status = await api.translate(props.record.cve_id)
    if (disposed) return
    if (status.status === 'source_missing') {
      summaryBusy.value = false
      return
    }
    await pollSummary()
  } catch {
    if (!disposed) {
      summaryBusy.value = false
      summaryError.value = '中文翻译暂未就绪，可点击重试。'
    }
  }
}
watch(
  () => [props.record.cve_id, study.value.description_zh, study.value.description_stale],
  () => {
    if (!study.value.description_zh || study.value.description_stale) void requestSummary()
  },
  { immediate: true },
)

async function poll() {
  try {
    const task = await api.task(job.value)
    if (disposed) return
    if (['PENDING', 'RUNNING'].includes(task.status)) {
      timer = setTimeout(poll, 1800)
      return
    }
    if (task.status === 'FAILED') {
      job.value = null
      throw new Error(task.error || '补采未完成，请重试。')
    }
    const record = await api.detail(props.record.cve_id)
    if (!disposed) emit('updated', record)
    busy.value = false
    job.value = null
  } catch (failure) {
    if (!disposed) {
      error.value = failure.message
      busy.value = false
    }
  }
}
async function enrich() {
  error.value = ''
  busy.value = true
  try {
    if (!job.value) {
      const task = await api.enrich(props.record.cve_id)
      if (disposed) return
      job.value = task.id
    }
    await poll()
  } catch (failure) {
    if (!disposed) {
      error.value = failure.message
      busy.value = false
    }
  }
}
function versionText(version) {
  let text = `${version.status || 'unknown'}: ${version.version || '*'}`
  if (version.lessThan) text += ` · < ${version.lessThan}`
  if (version.lessThanOrEqual) text += ` · ≤ ${version.lessThanOrEqual}`
  if (version.versionType) text += ` (${version.versionType})`
  if (version.changes?.length) text += ` · changes: ${JSON.stringify(version.changes)}`
  return text
}
onUnmounted(() => {
  disposed = true
  clearTimeout(timer)
  clearTimeout(summaryTimer)
})
</script>

<template>
  <section class="study-content" aria-label="漏洞学习资料">
    <div class="study-heading">
      <div>
        <span class="eyebrow">READ · UNDERSTAND · KEEP</span>
        <h3>{{ study.title || record.cve_id }}</h3>
        <p class="muted">
          {{ documents.length }} 篇本地资料
          <template v-if="study.fetched_at">
            · 采集于 {{ formatDate(study.fetched_at, true) }}
          </template>
        </p>
      </div>
      <div class="study-actions">
        <button class="button secondary" :disabled="busy" @click="enrich">
          <RefreshCw :size="15" :class="{ spin: busy }" />
          {{
            busy
              ? '正在采集和翻译…'
              : job
                ? '继续查询任务'
                : study.fetched_at
                  ? '重新补采'
                  : '采集详情与翻译'
          }}
        </button>
        <a
          class="button primary"
          :href="`/api/vulnerabilities/${encodeURIComponent(record.cve_id)}/download`"
          download
        >
          <Download :size="15" />
          下载学习包
        </a>
      </div>
    </div>
    <p v-if="error" class="form-error" role="alert">{{ error }}</p>
    <p v-if="study.stale" class="warning-note">
      原始记录已更新，请核对公告的采集时间和版本信息。中文摘要会按当前英文内容独立更新。
    </p>
    <AIStudyCard
      :key="record.study?.ai_source_signature || record.cve_id"
      :cve-id="record.cve_id"
    />
    <div class="topic-tags">
      <span v-for="topic in study.topics" :key="topic" class="topic-tag">{{ topic }}</span>
      <span v-for="cwe in study.weaknesses" :key="cwe" class="topic-tag mono">{{ cwe }}</span>
    </div>
    <div class="reading-toolbar">
      <span>
        <Languages :size="16" />
        阅读语言
      </span>
      <div class="segmented">
        <button :class="{ selected: language === 'both' }" @click="language = 'both'">
          中英对照
        </button>
        <button :class="{ selected: language === 'en' }" @click="language = 'en'">English</button>
        <button :class="{ selected: language === 'zh' }" @click="language = 'zh'">中文</button>
      </div>
    </div>
    <div class="bilingual-grid" :class="{ single: language !== 'both' }">
      <article v-if="language !== 'zh'" class="reading-card">
        <span class="reading-label">ENGLISH ORIGINAL · 漏洞摘要</span>
        <p>{{ record.description || '上游未提供英文描述。' }}</p>
      </article>
      <article v-if="language !== 'en'" class="reading-card chinese">
        <span class="reading-label">中文 · 机器翻译</span>
        <p>
          {{
            (!study.description_stale && study.description_zh) ||
            (!record.description?.trim()
              ? '上游尚未提供漏洞描述。'
              : summaryBusy
                ? '正在生成当前英文描述的中文翻译…'
                : '中文摘要正在补齐，英文原文可先阅读。')
          }}
        </p>
        <p v-if="summaryError" class="form-error">{{ summaryError }}</p>
        <button
          v-if="
            !summaryBusy &&
            (!study.description_zh || study.description_stale) &&
            record.description?.trim()
          "
          class="text-link"
          @click="requestSummary"
        >
          翻译中文摘要
        </button>
      </article>
    </div>
    <p class="translation-note">
      中文为机器翻译，仅作学习辅助。版本号、代码和修复条件请结合英文核对。生态标签由文本线索归类，可能跨多个领域。
      <span v-if="study.translation_provider">翻译来源：{{ study.translation_provider }}</span>
    </p>

    <div class="study-facts">
      <details v-if="study.affected?.length" open>
        <summary>
          受影响产品、版本范围与修复版本
          <span>{{ study.affected.length }}</span>
        </summary>
        <div class="affected-table-wrap">
          <table class="affected-table">
            <thead>
              <tr>
                <th>厂商 / 生态</th>
                <th>产品 / 软件包</th>
                <th>版本与状态（保留上游语义）</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(product, index) in study.affected" :key="index">
                <td>{{ product.vendor || '未提供' }}</td>
                <td>
                  <strong>{{ product.product || product.packageName || '未提供' }}</strong>
                  <small v-if="product.defaultStatus">默认状态：{{ product.defaultStatus }}</small>
                </td>
                <td>
                  <p v-for="(version, i) in product.versions || []" :key="i" class="mono">
                    {{ versionText(version) }}
                  </p>
                  <p v-if="product.range">受影响：{{ product.range }}</p>
                  <p v-if="product.fixed">首次修复：{{ product.fixed }}</p>
                  <p v-if="product.versionStartIncluding">≥ {{ product.versionStartIncluding }}</p>
                  <p v-if="product.versionStartExcluding">
                    &gt; {{ product.versionStartExcluding }}
                  </p>
                  <p v-if="product.versionEndIncluding">≤ {{ product.versionEndIncluding }}</p>
                  <p v-if="product.versionEndExcluding">&lt; {{ product.versionEndExcluding }}</p>
                  <small v-if="product.criteria" class="mono">{{ product.criteria }}</small>
                  <span v-if="!product.versions?.length && !product.range && !product.criteria">
                    上游未提供版本范围
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </details>
      <p v-else class="empty-inline">受影响版本尚未获取；不能据此判断某个版本安全。</p>
    </div>

    <div class="article-heading">
      <BookOpen :size="19" />
      <h3>公告与详细讲解</h3>
      <span class="count-label">{{ documents.length }}</span>
    </div>
    <p v-if="!documents.length" class="empty-inline">
      暂无本地公告正文。补采会尝试获取 CNA 说明、GitHub 安全公告和厂商静态正文。
    </p>
    <div v-else class="article-library">
      <nav class="article-list" aria-label="选择本地公告">
        <button
          v-for="(doc, index) in documents"
          :key="index"
          :class="{ active: selectedArticle === index }"
          @click="selectedArticle = index"
        >
          <small>{{ doc.source }} · {{ String(index + 1).padStart(2, '0') }}</small>
          <strong>{{ doc.title }}</strong>
          <span>
            {{ doc.text_en?.length.toLocaleString() }} 字符 ·
            {{ doc.translation_status === 'complete' ? '已翻译' : '翻译待补全' }}
          </span>
        </button>
      </nav>
      <div v-if="article" class="article-reader">
        <div class="article-source">
          <span>{{ article.source }} · {{ formatDate(article.fetched_at, true) }}</span>
          <a
            v-if="safeReference(article.url)"
            :href="safeReference(article.url)"
            target="_blank"
            rel="noopener noreferrer"
          >
            核对来源
            <ExternalLink :size="13" />
          </a>
        </div>
        <p v-if="article.truncated" class="warning-note">
          正文超过本地保存上限，当前为截取内容，完整原文见来源。
        </p>
        <div class="bilingual-grid" :class="{ single: language !== 'both' }">
          <article v-if="language !== 'zh'" class="reading-card">
            <span class="reading-label">ENGLISH ORIGINAL</span>
            <p class="article-text">{{ article.text_en }}</p>
          </article>
          <article v-if="language !== 'en'" class="reading-card chinese">
            <span class="reading-label">中文 · 机器翻译</span>
            <p class="article-text">
              {{ article.text_zh || '此篇翻译尚未完成，请阅读英文或重新补采。' }}
            </p>
          </article>
        </div>
      </div>
    </div>
    <details v-if="study.errors?.length" class="source-errors">
      <summary>采集未完成的来源（{{ study.errors.length }}）</summary>
      <p v-for="(failure, index) in study.errors" :key="index">
        <strong>{{ failure.error }}</strong>
        <br />
        {{ failure.url }}
      </p>
    </details>
  </section>
</template>
