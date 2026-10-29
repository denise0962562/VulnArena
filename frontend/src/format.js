export const severityLabels = {
  CRITICAL: '严重',
  HIGH: '高危',
  MEDIUM: '中危',
  LOW: '低危',
  NONE: '无危害',
  UNKNOWN: '待评分',
}
export const taskLabels = {
  PENDING: '等待执行',
  RUNNING: '同步中',
  SUCCESS: '已完成',
  FAILED: '同步失败',
}

export function formatDate(value, time = false) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    ...(time ? { hour: '2-digit', minute: '2-digit', hour12: false } : {}),
  }).format(date)
}

export const scoreText = (value) => (value == null ? '—' : Number(value).toFixed(1))

export function safeReference(value) {
  try {
    const url = new URL(value)
    return ['https:', 'http:'].includes(url.protocol) ? url.href : null
  } catch {
    return null
  }
}

export function syncPayload(mode, term, limit) {
  const value = term.trim()
  if (!value) throw new Error(mode === 'cve' ? '请输入 CVE 编号。' : '请输入检索关键词。')
  if (mode === 'cve') {
    if (!/^CVE-\d{4}-\d{4,}$/i.test(value)) throw new Error('CVE 编号格式应为 CVE-2021-44228。')
    return { cve_id: value.toUpperCase() }
  }
  const count = Number(limit)
  if (!Number.isInteger(count) || count < 1 || count > 1000)
    throw new Error('同步数量应为 1–1000 的整数。')
  if (value.length > 100) throw new Error('关键词最多 100 个字符。')
  return { keyword: value, max_records: count }
}
