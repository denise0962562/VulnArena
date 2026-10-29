export class ApiError extends Error {
  constructor(message, status) {
    super(message)
    this.status = status
  }
}

export async function request(path, options = {}) {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), 15000)
  try {
    const response = await fetch(path, { ...options, signal: controller.signal })
    const body = await response.json().catch(() => null)
    if (!response.ok) {
      const detail = typeof body?.detail === 'string' ? body.detail : null
      const messages = {
        409: '已有同步任务正在等待或运行，请稍后重试。',
        422: '请求参数有误，请检查 CVE 编号或关键词。',
        503: '服务暂时不可用，请检查后端和 Redis 是否运行。',
        404: '记录不存在或任务已过期。',
      }
      throw new ApiError(
        messages[response.status] || detail || `请求失败（${response.status}）`,
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
