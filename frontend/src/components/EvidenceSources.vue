<script setup>
import { computed } from 'vue'
import { ExternalLink, FileText } from 'lucide-vue-next'
import { safeReference } from '../format'
const props = defineProps({
  sources: { type: Array, default: () => [] },
  selected: Object,
  showLocal: { type: Boolean, default: true },
})
const emit = defineEmits(['open-cve'])
const rows = computed(() =>
  props.sources.map((source) => {
    const quote = props.selected?.source_id === source.source_id ? props.selected.quote : ''
    const index = quote ? source.text.indexOf(quote) : -1
    return { ...source, url: safeReference(source.url), quote, index }
  }),
)
</script>

<template>
  <section class="evidence" aria-label="回答依据与原文">
    <div class="evidence-title">
      <FileText :size="18" />
      <h3>回答依据与原文</h3>
      <span>{{ sources.length }} 段</span>
    </div>
    <p class="evidence-note">
      以下是本地保存的原文。引用编号对应本次回答，点击引用可展开对应片段。
    </p>
    <p v-if="!sources.length" class="evidence-note">尚未检索到可引用的本地资料。</p>
    <details
      v-for="source in rows"
      :key="source.id"
      :open="selected?.source_id === source.source_id"
    >
      <summary>
        <span class="source-code">{{ source.source_id }}</span>
        <strong>{{ source.cve_id }}</strong>
        <small>{{ source.source }}</small>
      </summary>
      <p class="source-title">{{ source.title }}</p>
      <pre
        v-if="
          source.index >= 0
        ">{{ source.text.slice(0, source.index) }}<mark>{{ source.quote }}</mark>{{ source.text.slice(source.index + source.quote.length) }}</pre>
      <template v-else>
        <blockquote v-if="source.quote">{{ source.quote }}</blockquote>
        <pre>{{ source.text }}</pre>
      </template>
      <p class="evidence-note">上游修订 {{ source.updated_at?.slice(0, 10) }}</p>
      <div class="source-actions">
        <button
          v-if="showLocal"
          type="button"
          class="text-link"
          @click="emit('open-cve', source.cve_id)"
        >
          查看本地 CVE
        </button>
        <a v-if="source.url" :href="source.url" target="_blank" rel="noopener noreferrer">
          打开原始来源
          <ExternalLink :size="13" />
        </a>
      </div>
    </details>
  </section>
</template>

<style scoped>
.evidence {
  border: 1px solid var(--border, #e4e8f1);
  border-radius: 14px;
  background: white;
  padding: 20px;
  min-width: 0;
}
.evidence-title {
  display: flex;
  align-items: center;
  gap: 9px;
  color: #4869a4;
}
.evidence-title h3 {
  font-size: 15px;
  margin: 0;
  color: #26364e;
}
.evidence-title span {
  margin-left: auto;
  font-size: 12px;
}
.evidence-note {
  font-size: 12px;
  color: #7c889e;
  line-height: 1.8;
}
.evidence details {
  border-top: 1px solid #edf0f5;
  padding: 13px 0;
}
summary {
  cursor: pointer;
  display: flex;
  gap: 9px;
  align-items: center;
  list-style: none;
}
summary strong {
  font-size: 12px;
}
summary small {
  font-size: 11px;
  color: #8792a5;
  margin-left: auto;
}
.source-code {
  background: #edf3ff;
  color: #4264b0;
  padding: 3px 6px;
  border-radius: 4px;
  font-size: 11px;
  flex-shrink: 0;
}
.source-title {
  font-size: 12px;
  font-weight: 600;
  overflow-wrap: anywhere;
}
pre,
blockquote {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  font-size: 12px;
  line-height: 1.9;
  font-family: inherit;
  background: #f7f9fc;
  padding: 14px;
  border-radius: 8px;
  margin: 10px 0;
}
mark {
  background: #f8e8b4;
  color: inherit;
}
blockquote {
  border-left: 3px solid #d8b95a;
}
.source-actions {
  display: flex;
  gap: 14px;
  flex-wrap: wrap;
}
.source-actions a {
  font-size: 12px;
  color: #4669b0;
  display: flex;
  align-items: center;
  gap: 5px;
  text-decoration: none;
}
</style>
