import { afterEach, describe, expect, it, vi } from 'vitest'
import { api, request } from './api'

afterEach(() => {
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

describe('API boundary', () => {
  it('encodes filters and omits empty values', async () => {
    const fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ items: [] }) })
    vi.stubGlobal('fetch', fetch)
    await api.list({ keyword: 'openssl & nginx', severity: '', page: 2, page_size: 10 })
    const url = new URL(fetch.mock.calls[0][0], 'http://test')
    expect(url.searchParams.get('keyword')).toBe('openssl & nginx')
    expect(url.searchParams.has('severity')).toBe(false)
    expect(url.searchParams.get('page')).toBe('2')
  })
  it('surfaces duplicate task conflicts and service outages', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({ ok: false, status: 409, json: async () => ({}) }),
    )
    await expect(api.sync({ cve_id: 'CVE-2021-44228' })).rejects.toMatchObject({
      status: 409,
      message: expect.stringContaining('已有同步任务'),
    })
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('offline')))
    await expect(request('/health')).rejects.toMatchObject({
      status: 0,
      message: expect.stringContaining('无法连接'),
    })
  })
})
