import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { api } from './api'
import App from './App.vue'

vi.mock('./api', () => ({
  api: {
    list: vi.fn(),
    detail: vi.fn(),
    health: vi.fn(),
    sync: vi.fn(),
    task: vi.fn(),
    years: vi.fn(),
    libraryStats: vi.fn(),
    translate: vi.fn(),
    translationStatus: vi.fn(),
  },
}))

const record = {
  cve_id: 'CVE-2021-44228',
  description: 'Apache Log4j vulnerability',
  description_lang: 'en',
  cvss_score: 10,
  cvss_version: '3.1',
  severity: 'CRITICAL',
  published_at: '2021-12-10T00:00:00Z',
  last_modified_at: '2024-01-01T00:00:00Z',
  vuln_status: 'Analyzed',
  metrics: {
    cvssMetricV31: [{ source: 'nvd@nist.gov', type: 'Primary', cvssData: { baseScore: 10 } }],
  },
  references: [{ url: 'https://nvd.nist.gov/' }],
  raw: { id: 'CVE-2021-44228' },
  parse_warnings: [],
}
let wrapper

beforeEach(() => {
  vi.useRealTimers()
  localStorage.clear()
  vi.resetAllMocks()
  HTMLDialogElement.prototype.showModal = function () {
    this.setAttribute('open', '')
  }
  api.health.mockResolvedValue({ status: 'ok' })
  api.years.mockResolvedValue([{ year: 2020, total: 21086, translated: 21086, pending: 0 }])
  api.libraryStats.mockResolvedValue({ studied: 3140, translated: 270587, documents: 3447 })
  api.translate.mockResolvedValue({ status: 'pending' })
  api.translationStatus.mockResolvedValue({ status: 'pending' })
  api.detail.mockResolvedValue(record)
  api.list.mockImplementation(async (params = {}) => {
    const matches =
      (!params.severity || params.severity === record.severity) &&
      (!params.keyword ||
        record.description.includes(params.keyword) ||
        record.cve_id.includes(params.keyword))
    return {
      items: matches ? [record] : [],
      total: matches ? 11 : 0,
      page: params.page || 1,
      page_size: params.page_size || 10,
    }
  })
})
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
  vi.useRealTimers()
})

async function render() {
  wrapper = mount(App, { attachTo: document.body })
  await flushPromises()
  return wrapper
}

describe('intelligence workspace', () => {
  it('defaults to 2020–2026, filters a year from coverage, and restores the period', async () => {
    await render()
    expect(api.list).toHaveBeenCalledWith(
      expect.objectContaining({ year_from: 2020, year_to: 2026 }),
    )
    expect(wrapper.text()).toContain('中文 21,086 / 21,086')
    await wrapper.findAll('.year-grid button')[0].trigger('click')
    await flushPromises()
    expect(api.list).toHaveBeenLastCalledWith(
      expect.objectContaining({ year_from: 2020, year_to: 2020, page: 1 }),
    )
    await wrapper.get('[aria-label="筛选 CVE 编号年份"]').setValue('')
    await flushPromises()
    expect(api.list).toHaveBeenLastCalledWith(
      expect.objectContaining({ year_from: '', year_to: '' }),
    )
  })
  it('queries real API contracts, paginates, searches and clears empty results', async () => {
    await render()
    expect(wrapper.text()).toContain('CVE-2021-44228')
    expect(wrapper.text()).toContain('10.0')
    await wrapper.get('[aria-label="下一页"]').trigger('click')
    await flushPromises()
    expect(api.list).toHaveBeenLastCalledWith(expect.objectContaining({ page: 2 }))
    await wrapper.get('[aria-label="搜索 CVE 编号或漏洞描述"]').setValue('missing')
    await wrapper.get('form[role="search"]').trigger('submit')
    await flushPromises()
    expect(api.list).toHaveBeenLastCalledWith(
      expect.objectContaining({ page: 1, keyword: 'missing' }),
    )
    expect(wrapper.text()).toContain('没有找到匹配的漏洞')
    await wrapper
      .findAll('button')
      .find((b) => b.text() === '清除筛选')
      .trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('CVE-2021-44228')
  })

  it('opens detail with all scoring versions and original data', async () => {
    await render()
    await wrapper.get('[aria-label="查看 CVE-2021-44228 详情"]').trigger('click')
    await flushPromises()
    expect(api.detail).toHaveBeenCalledWith(record.cve_id)
    expect(wrapper.get('dialog').attributes('open')).toBeDefined()
    await wrapper
      .findAll('[role="tab"]')
      .find((tab) => tab.text().includes('全部评分'))
      .trigger('click')
    expect(wrapper.get('dialog').text()).toContain('nvd@nist.gov')
    await wrapper
      .findAll('[role="tab"]')
      .find((tab) => tab.text().includes('原始数据'))
      .trigger('click')
    expect(wrapper.get('.raw-json').text()).toContain('CVE-2021-44228')
    await wrapper.get('[aria-label="关闭漏洞详情"]').trigger('click')
    expect(wrapper.find('dialog').exists()).toBe(false)
  })

  it('validates sync, polls RUNNING to SUCCESS and refreshes data without duplicate submission', async () => {
    vi.useFakeTimers()
    const task = { id: 'test-job', status: 'PENDING', processed: 0, changed: 0 }
    api.sync.mockResolvedValue(task)
    api.task
      .mockResolvedValueOnce({ ...task, status: 'RUNNING' })
      .mockResolvedValueOnce({ ...task, status: 'SUCCESS', processed: 1, changed: 1 })
    await render()
    await wrapper
      .findAll('button')
      .find((b) => b.text().includes('同步 NVD 情报'))
      .trigger('click')
    await wrapper.get('#sync-term').setValue('wrong')
    await wrapper.get('dialog form').trigger('submit')
    await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toContain('CVE 编号格式')
    expect(api.sync).not.toHaveBeenCalled()
    await wrapper.get('#sync-term').setValue('cve-2021-44228')
    await wrapper.get('dialog form').trigger('submit')
    await flushPromises()
    expect(api.sync).toHaveBeenCalledExactlyOnceWith({ cve_id: 'CVE-2021-44228' })
    expect(wrapper.find('dialog').exists()).toBe(false)
    expect(
      wrapper
        .findAll('button')
        .find((b) => b.text() === '正在同步')
        .attributes('disabled'),
    ).toBeDefined()
    const readsBefore = api.list.mock.calls.length
    await vi.advanceTimersByTimeAsync(1500)
    await flushPromises()
    expect(api.list.mock.calls.length).toBeGreaterThan(readsBefore)
    await wrapper
      .findAll('nav button')
      .find((b) => b.text() === '同步中心')
      .trigger('click')
    expect(wrapper.text()).toContain('已完成')
    expect(wrapper.text()).toContain('处理 1 条')
    expect(JSON.parse(localStorage.getItem('vulnarena.tasks.v1'))[0].status).toBe('SUCCESS')
  })

  it('preserves unknown task outcome on polling error and allows reconnection', async () => {
    localStorage.setItem(
      'vulnarena.tasks.v1',
      JSON.stringify([{ id: 'saved-task', status: 'RUNNING', label: 'openssl' }]),
    )
    api.task.mockRejectedValueOnce(new Error('连接中断')).mockResolvedValueOnce({
      id: 'saved-task',
      status: 'FAILED',
      error: 'NVDUpstreamError: retries exhausted',
    })
    await render()
    expect(wrapper.text()).toContain('任务状态读取中断')
    expect(JSON.parse(localStorage.getItem('vulnarena.tasks.v1'))[0].status).toBe('RUNNING')
    await wrapper
      .findAll('button')
      .find((b) => b.text() === '重新连接')
      .trigger('click')
    await flushPromises()
    await wrapper
      .findAll('nav button')
      .find((b) => b.text() === '同步中心')
      .trigger('click')
    expect(wrapper.text()).toContain('同步失败')
    expect(wrapper.text()).toContain('retries exhausted')
  })

  it('renders backend outages without inventing statistics', async () => {
    api.list.mockRejectedValue(new Error('后端不可用'))
    api.health.mockRejectedValue(new Error('offline'))
    await render()
    expect(wrapper.text()).toContain('服务连接异常')
    expect(wrapper.text()).toContain('统计读取失败')
    expect(wrapper.text()).toContain('暂时无法读取情报')
    expect(wrapper.findAll('.stat-value')[0].text()).toContain('—')
  })
})
