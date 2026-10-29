import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import StudyContent from './StudyContent.vue'
import { api } from '../api'

vi.mock('../api', () => ({
  api: {
    enrich: vi.fn(),
    task: vi.fn(),
    detail: vi.fn(),
    translate: vi.fn(),
    translationStatus: vi.fn(),
  },
}))
const record = {
  cve_id: 'CVE-2024-1234',
  description: 'English original',
  study: {
    title: 'Example issue',
    description_zh: '中文漏洞说明',
    topics: ['Python'],
    affected: [
      {
        vendor: 'pip',
        product: 'package',
        versions: [{ status: 'affected', version: '1.0', lessThan: '2.0' }],
      },
    ],
    documents: [
      {
        title: 'Detailed advisory',
        source: 'CVE CNA',
        text_en: '<script>unsafe()</script> Full original',
        text_zh: '完整中文说明',
        translation_status: 'complete',
        url: 'javascript:unsafe()',
      },
    ],
  },
}
let wrapper
afterEach(() => {
  wrapper?.unmount()
  vi.useRealTimers()
  vi.resetAllMocks()
})

describe('local study reader', () => {
  it('automatically fills a missing Chinese summary and returns the saved detail', async () => {
    vi.useFakeTimers()
    api.translate.mockResolvedValue({ status: 'pending' })
    api.translationStatus
      .mockResolvedValueOnce({ status: 'pending' })
      .mockResolvedValueOnce({ status: 'complete' })
    api.detail.mockResolvedValue(record)
    wrapper = mount(StudyContent, { props: { record: { ...record, study: {} } } })
    await flushPromises()
    expect(wrapper.text()).toContain('正在生成当前英文描述的中文翻译')
    expect(api.translate).toHaveBeenCalledExactlyOnceWith(record.cve_id)
    await vi.advanceTimersByTimeAsync(1500)
    await flushPromises()
    expect(wrapper.emitted('updated')[0]).toEqual([record])
    expect(api.enrich).not.toHaveBeenCalled()
  })

  it('does not hide current Chinese when only unrelated source metadata is stale', async () => {
    wrapper = mount(StudyContent, {
      props: {
        record: { ...record, study: { ...record.study, stale: true, description_stale: false } },
      },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('中文漏洞说明')
    expect(api.translate).not.toHaveBeenCalled()
  })
  it('renders bilingual content as inert text, preserves ranges and exposes the bundle', async () => {
    wrapper = mount(StudyContent, { props: { record } })
    expect(wrapper.text()).toContain('English original')
    expect(wrapper.text()).toContain('中文漏洞说明')
    expect(wrapper.text()).toContain('affected: 1.0 · < 2.0')
    expect(wrapper.find('script').exists()).toBe(false)
    expect(wrapper.find('a[target="_blank"]').exists()).toBe(false)
    expect(wrapper.get('a[download]').attributes('href')).toBe(
      '/api/vulnerabilities/CVE-2024-1234/download',
    )
    await wrapper
      .findAll('button')
      .find((b) => b.text() === '中文')
      .trigger('click')
    expect(wrapper.text()).not.toContain('English original')
    expect(wrapper.text()).toContain('完整中文说明')
  })

  it('polls enrichment and returns the persisted detail to the parent', async () => {
    api.enrich.mockResolvedValue({ id: 'job' })
    api.task.mockResolvedValue({ status: 'SUCCESS' })
    api.detail.mockResolvedValue(record)
    wrapper = mount(StudyContent, { props: { record } })
    await wrapper
      .findAll('button')
      .find((b) => b.text().includes('采集详情'))
      .trigger('click')
    await flushPromises()
    expect(api.enrich).toHaveBeenCalledWith(record.cve_id)
    expect(wrapper.emitted('updated')[0]).toEqual([record])
  })

  it('leaves failed jobs visible and allows retrying status without creating duplicate work', async () => {
    api.enrich.mockResolvedValue({ id: 'job' })
    api.task
      .mockRejectedValueOnce(new Error('Network interrupted'))
      .mockResolvedValueOnce({ status: 'SUCCESS' })
    api.detail.mockResolvedValue(record)
    wrapper = mount(StudyContent, { props: { record } })
    await wrapper
      .findAll('button')
      .find((b) => b.text().includes('采集详情'))
      .trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('Network interrupted')
    await wrapper
      .findAll('button')
      .find((b) => b.text().includes('继续查询'))
      .trigger('click')
    await flushPromises()
    expect(api.enrich).toHaveBeenCalledTimes(1)
    expect(wrapper.emitted('updated')).toHaveLength(1)
  })
})
