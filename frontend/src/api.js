export class ApiError extends Error {
  constructor(message, status) {
    super(message)
    this.status = status
  }
}

export async function request(path, options = {}) {
  const { timeoutMs = 15000, ...fetchOptions } = options
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const response = await fetch(path, { ...fetchOptions, signal: controller.signal })
    const body = await response.json().catch(() => null)
    if (!response.ok) {
      const detail = typeof body?.detail === 'string' ? body.detail : null
      const messages = {
        401: '管理会话已过期，请打开 /login 重新登录。',
        409: '已有同步任务正在等待或运行，请稍后重试。',
        422: '请求参数有误，请检查 CVE 编号或关键词。',
        503: '服务暂时不可用，请检查后端和 Redis 是否运行。',
        404: '记录不存在或任务已过期。',
      }
      throw new ApiError(
        (response.status === 409 ? detail : null) ||
          messages[response.status] ||
          detail ||
          `请求失败（${response.status}）`,
        response.status,
      )
    }
    return body
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw new ApiError(
      error.name === 'AbortError' ? '请求超时，请稍后重试。' : '无法连接服务，请确认后端已启动。',
      0,
    )
  } finally {
    clearTimeout(timeout)
  }
}

export const api = {
  async aiCardDownload(id) {
    const response = await fetch('/api/ai/cards/' + encodeURIComponent(id) + '/download')
    if (!response.ok) {
      const body = await response.json().catch(() => null)
      throw new ApiError(body?.detail || '卡片下载失败，请重试。', response.status)
    }
    return response.blob()
  },
  aiStatus: () => request('/api/ai/status'),
  aiDashboard: () => request('/api/ai/dashboard'),
  aiIndex: (limit = 5000) =>
    request('/api/ai/index', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ limit }),
    }),
  aiJob: (id) => request('/api/ai/jobs/' + encodeURIComponent(id)),
  aiCancelJob: (id) =>
    request('/api/ai/jobs/' + encodeURIComponent(id) + '/cancel', { method: 'POST' }),
  aiEvaluate: (includeGeneration = false, dataset = 'development') =>
    request('/api/ai/evaluations', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        include_generation: includeGeneration,
        dataset,
        generation_limit: 5,
        limit: 100,
      }),
    }),
  aiReviewTemplate: (id) =>
    request('/api/ai/evaluations/' + encodeURIComponent(id) + '/review-template'),
  aiSaveReviews: (id, reviews) =>
    request('/api/ai/evaluations/' + encodeURIComponent(id) + '/reviews', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reviews }),
    }),
  aiCard: (id) => request('/api/ai/cards/' + encodeURIComponent(id)),
  aiGenerateCard: (id, force = false) =>
    request('/api/ai/cards/' + encodeURIComponent(id) + '?force=' + force, {
      method: 'POST',
      timeoutMs: 110000,
    }),
  list(params = {}) {
    const query = new URLSearchParams()
    for (const [key, value] of Object.entries(params)) {
      if (value !== '' && value != null) query.set(key, String(value))
    }
    return request(`/api/vulnerabilities?${query}`)
  },
  detail: (id) => request(`/api/vulnerabilities/${encodeURIComponent(id)}`),
  health: () => request('/health'),
  libraryStats: () => request('/api/library/stats'),
  years: () => request('/api/library/years?year_from=2020&year_to=2026'),
  translate: (id) =>
    request(`/api/vulnerabilities/${encodeURIComponent(id)}/translate`, { method: 'POST' }),
  translationStatus: (id) => request(`/api/vulnerabilities/${encodeURIComponent(id)}/translation`),
  sync: (query) =>
    request('/api/sync', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(query),
    }),
  task: (id) => request(`/api/tasks/${encodeURIComponent(id)}`),
  enrich: (id) =>
    request(`/api/vulnerabilities/${encodeURIComponent(id)}/enrich`, { method: 'POST' }),
  downloadUrl: (id) => `/api/vulnerabilities/${encodeURIComponent(id)}/download`,
}

export async function streamAnswer(body, onEvent, signal) {
  const response = await fetch('/api/ai/ask/stream', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal,
  })
  if (!response.ok || !response.body)
    throw new ApiError('AI 服务暂不可用，请稍后重试。', response.status)
  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  let completed = false
  try {
    while (true) {
      const { value, done } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })
      let boundary
      while ((boundary = buffer.indexOf('\n\n')) >= 0) {
        const packet = buffer.slice(0, boundary)
        buffer = buffer.slice(boundary + 2)
        const lines = packet.split('\n')
        const event = lines
          .find((line) => line.startsWith('event:'))
          ?.slice(6)
          .trim()
        const data = lines
          .filter((line) => line.startsWith('data:'))
          .map((line) => line.slice(5).trim())
          .join('\n')
        if (event && data) {
          onEvent(event, JSON.parse(data))
          if (event === 'done') completed = true
        }
      }
    }
    if (!completed && !signal?.aborted)
      throw new ApiError('连接中断，请重试；已检索到的原文仍可阅读。', 0)
  } finally {
    reader.releaseLock()
  }
}
