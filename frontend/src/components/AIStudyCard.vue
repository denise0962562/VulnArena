<script setup>
import { ref } from 'vue'
import { Sparkles, Download, ChevronDown, RefreshCw } from 'lucide-vue-next'
import { api } from '../api'
import EvidenceSources from './EvidenceSources.vue'
import { formatDate } from '../format'
const props = defineProps({ cveId: String })
const open = ref(false)
const card = ref(null)
const busy = ref(false)
const error = ref('')
const selected = ref(null)
async function expand() {
  open.value = !open.value
  if (!open.value || card.value) return
  try {
    card.value = await api.aiCard(props.cveId)
  } catch (failure) {
    error.value = failure.message
  }
}
async function generate(force = false) {
  busy.value = true
  error.value = ''
  try {
    card.value = await api.aiGenerateCard(props.cveId, force)
    if (card.value.status !== 'complete')
      error.value = card.value.message || '当前资料不足以生成可靠卡片。'
  } catch (failure) {
    error.value = failure.message
  } finally {
    busy.value = false
  }
}
async function download() {
  error.value = ''
  let blob
  try {
    blob = await api.aiCardDownload(props.cveId)
  } catch (failure) {
    error.value = failure.message
    return
  }
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = props.cveId + '-AI-study.md'
  anchor.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
</script>

<template>
  <section class="ai-card" aria-label="AI 漏洞学习卡片">
    <button class="ai-card-heading" :aria-expanded="open" @click="expand">
      <Sparkles :size="19" />
      <span>
        <strong>AI 漏洞学习卡片</strong>
        <small>按需生成 · 原文引用 · 缺失信息明确标注</small>
      </span>
      <ChevronDown :size="17" />
    </button>
    <div v-if="open" class="ai-card-body">
      <p v-if="error" class="form-error" role="alert">{{ error }}</p>
      <p v-if="card?.status === 'stale'" class="muted">
        来源或模型版本已更新，旧卡片不再作为当前解释展示，请重新生成。
      </p>
      <p v-if="!card || card.status !== 'complete'" class="muted">
        根据当前 CVE
        的原始描述与已下载公告整理五段学习内容。生成会请求已配置的模型，结果校验通过后保存。
      </p>
      <div class="ai-card-actions">
        <button
          class="button secondary"
          :disabled="busy"
          @click="generate(card?.status === 'complete')"
        >
          <RefreshCw :size="14" :class="{ spin: busy }" />
          {{
            busy ? '正在阅读原文并生成…' : card?.status === 'complete' ? '重新生成' : '生成学习卡片'
          }}
        </button>
        <button v-if="card?.status === 'complete'" class="button secondary" @click="download">
          <Download :size="14" />
          下载卡片与依据
        </button>
      </div>
      <template v-if="card?.status === 'complete'">
        <p class="card-meta">
          {{ card.model }} · {{ formatDate(card.created_at, true) }} ·
          {{ card.cached ? '读取已保存卡片' : '已保存' }}
        </p>
        <article v-for="section in card.sections" :key="section.key" class="card-section">
          <div>
            <h4>{{ section.title }}</h4>
            <small :class="{ missing: section.status === 'missing' }">
              {{ section.status === 'missing' ? '资料不足' : '附原文依据' }}
            </small>
          </div>
          <p>{{ section.text }}</p>
          <button
            v-for="(reference, i) in section.references"
            :key="i"
            class="citation"
            @click="selected = reference"
          >
            [{{ reference.source_id }}] 查看引文
          </button>
        </article>
        <p class="card-meta">{{ card.note }}</p>
        <EvidenceSources :sources="card.sources" :selected="selected" :show-local="false" />
      </template>
    </div>
  </section>
</template>

<style scoped>
.ai-card {
  border: 1px solid #dce4f5;
  border-radius: 12px;
  background: linear-gradient(120deg, #f6f8ff, white);
  margin: 22px 0;
}
.ai-card-heading {
  width: 100%;
  display: flex;
  align-items: center;
  gap: 12px;
  border: 0;
  background: none;
  padding: 18px;
  text-align: left;
  color: #4262a2;
  cursor: pointer;
}
.ai-card-heading span {
  display: grid;
  gap: 5px;
  flex: 1;
}
.ai-card-heading strong {
  font-size: 14px;
}
.ai-card-heading small {
  font-size: 11px;
  color: #7d8da8;
  font-weight: 400;
}
.ai-card-body {
  padding: 0 18px 18px;
}
.ai-card-actions {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  margin: 14px 0;
}
.card-meta {
  font-size: 11px;
  line-height: 1.9;
  color: #8390a5;
  overflow-wrap: anywhere;
}
.card-section {
  border-top: 1px solid #e5eaf4;
  padding: 15px 0;
}
.card-section > div {
  display: flex;
  align-items: center;
  gap: 10px;
}
.card-section h4 {
  font-size: 14px;
  margin: 0;
}
.card-section small {
  font-size: 10px;
  color: #398272;
  background: #edf7f3;
  padding: 3px 6px;
  border-radius: 4px;
}
.card-section small.missing {
  color: #9b7b34;
  background: #fff8e9;
}
.card-section p {
  font-size: 13px;
  line-height: 2;
  white-space: pre-wrap;
}
.citation {
  background: #eaf0ff;
  border: 0;
  color: #4266b1;
  padding: 4px 8px;
  border-radius: 5px;
  font-size: 11px;
  cursor: pointer;
  margin-right: 7px;
}
</style>
