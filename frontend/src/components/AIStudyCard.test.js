import { afterEach, expect, it, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import AIStudyCard from './AIStudyCard.vue'
import { api } from '../api'
vi.mock('../api', () => ({ api: { aiCard: vi.fn(), aiGenerateCard: vi.fn() } }))
let wrapper
afterEach(() => {
  wrapper?.unmount()
  vi.resetAllMocks()
})
it('generates only after explicit selection and clearly shows missing evidence', async () => {
  api.aiCard.mockResolvedValue({ status: 'missing' })
  api.aiGenerateCard.mockResolvedValue({
    status: 'complete',
    model: 'fixture',
    created_at: '2026-10-29T00:00:00Z',
    sources: [],
    sections: [
      {
        key: 'overview',
        title: '问题是什么',
        status: 'supported',
        text: '中文原理说明',
        references: [],
      },
      {
        key: 'remediation',
        title: '修复与缓解依据',
        status: 'missing',
        text: '当前本地资料未提供足够依据。',
        references: [],
      },
    ],
  })
  wrapper = mount(AIStudyCard, { props: { cveId: 'CVE-2021-44228' } })
  expect(api.aiCard).not.toHaveBeenCalled()
  await wrapper.get('.ai-card-heading').trigger('click')
  await flushPromises()
  expect(api.aiGenerateCard).not.toHaveBeenCalled()
  await wrapper
    .findAll('button')
    .find((button) => button.text() === '生成学习卡片')
    .trigger('click')
  await flushPromises()
  expect(api.aiGenerateCard).toHaveBeenCalledExactlyOnceWith('CVE-2021-44228', false)
  expect(wrapper.text()).toContain('中文原理说明')
  expect(wrapper.text()).toContain('资料不足')
  expect(wrapper.text()).toContain('下载卡片与依据')
})
