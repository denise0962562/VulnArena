<script setup>
import { nextTick, onMounted, onUnmounted, ref } from 'vue'
import { ArrowRight, Database, Download, LoaderCircle, X } from 'lucide-vue-next'
import { syncPayload } from '../format'

const props = defineProps({ submit: Function, busy: Boolean })
const emit = defineEmits(['close'])
const dialog = ref(null)
const input = ref(null)
const mode = ref('cve')
const term = ref('')
const limit = ref(100)
const error = ref('')
const enrichDetails = ref(false)
const latest = ref(true)
const presets = [
  'Linux',
  'Windows',
  'Java',
  'golang',
  'Python',
  'PHP',
  'C++',
  '.NET',
  'Rust',
  'FastAPI',
]
let returnFocus

function setMode(value) {
  mode.value = value
  error.value = ''
}

async function send() {
  error.value = ''
  try {
    const payload = syncPayload(mode.value, term.value, limit.value)
    if (enrichDetails.value) {
      if (mode.value === 'keyword' && Number(limit.value) > 20)
        throw new Error(
          '包含正文与翻译时，每批最多 20 条，避免任务超时。大批采集请用 refresh_library.py。',
        )
      payload.enrich = true
    }
    if (mode.value === 'keyword') payload.latest = latest.value
    await props.submit(payload)
    emit('close')
  } catch (failure) {
    error.value = failure.message
  }
}

onMounted(async () => {
  returnFocus = document.activeElement
  dialog.value.showModal()
  await nextTick()
  input.value?.focus()
})
onUnmounted(() => returnFocus?.focus())
</script>

<template>
  <dialog
    ref="dialog"
    class="sync-dialog"
    aria-labelledby="sync-title"
    @cancel.prevent="!busy && emit('close')"
    @click="(event) => event.target === dialog && !busy && emit('close')"
  >
    <div class="dialog-head">
      <span class="icon-tile"><Download :size="22" /></span>
      <button class="icon-button" aria-label="关闭同步窗口" :disabled="busy" @click="emit('close')">
        <X :size="20" />
      </button>
    </div>
    <p class="eyebrow">CONNECT TO THE SOURCE</p>
    <h2 id="sync-title">同步 NVD 情报</h2>
    <p class="muted">从官方数据源获取漏洞，更新你的本地情报库。</p>
    <div class="segmented">
      <button :class="{ selected: mode === 'cve' }" @click="setMode('cve')">按 CVE 编号</button>
      <button :class="{ selected: mode === 'keyword' }" @click="setMode('keyword')">
        按关键词
      </button>
    </div>
    <form @submit.prevent="send">
      <div v-if="mode === 'keyword'" class="sync-presets">
        <button v-for="preset in presets" :key="preset" type="button" @click="term = preset">
          {{ preset }}
        </button>
      </div>
      <label for="sync-term">{{ mode === 'cve' ? 'CVE 编号' : '检索关键词' }}</label>
      <input
        id="sync-term"
        ref="input"
        v-model="term"
        :placeholder="mode === 'cve' ? '例如 CVE-2021-44228' : '例如 openssl、nginx'"
        :maxlength="mode === 'cve' ? 40 : 100"
        :disabled="busy"
        autocomplete="off"
        required
      />
      <template v-if="mode === 'keyword'">
        <label for="sync-limit">最多同步条数</label>
        <input
          id="sync-limit"
          v-model="limit"
          type="number"
          min="1"
          max="1000"
          step="1"
          :disabled="busy"
          required
        />
      </template>
      <label v-if="mode === 'keyword'" class="checkbox-label">
        <input v-model="latest" type="checkbox" />
        优先采集最近发布的记录
      </label>
      <label class="checkbox-label">
        <input v-model="enrichDetails" type="checkbox" />
        同时采集公告正文与中文翻译（每批建议 1–5 条）
      </label>
      <div class="info-note">
        <Database :size="17" />
        <p>新漏洞会写入本地数据库；已存在的 CVE 会按上游修改时间更新。</p>
      </div>
      <p v-if="error" class="form-error" role="alert">{{ error }}</p>
      <button type="submit" class="button primary full" :disabled="busy">
        <LoaderCircle v-if="busy" :size="17" class="spin" />
        <template v-else>
          <Download :size="17" />
          开始同步
          <ArrowRight :size="17" />
        </template>
        <span v-if="busy">正在提交…</span>
      </button>
    </form>
    <p class="dialog-footnote">遵守 NVD 请求限额，同步可能需要几分钟。</p>
  </dialog>
</template>
