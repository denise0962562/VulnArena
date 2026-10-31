import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import AIWorkspace from './AIWorkspace.vue'
import { api, streamAnswer } from '../api'

vi.mock('../api', () => ({
  api: {
    aiStatus: vi.fn(),
    aiDashboard: vi.fn(),
    aiIndex: vi.fn(),
    aiEvaluate: vi.fn(),
    aiJob: vi.fn(),
  },
  streamAnswer: vi.fn(),
}))
const source = {
  id: 'chunk-1',
  source_id: 'S1',
  cve_id: 'CVE-2021-44228',
  text: 'Original evidence <script>unsafe()</script>',
  title: 'Original advisory',
  url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228',
  source: 'NVD',
  updated_at: '2026-01-01T00:00:00Z',
}
let wrapper
beforeEach(() => {
  vi.resetAllMocks()
  api.aiStatus.mockResolvedValue({
    configured: true,
    model: 'fixture-model',
    embedding_available: true,
    index: { records: 5000, chunks: 15000 },
    jobs: [],
    limits: { embedding_threads: 2, daily_model_calls: 30, daily_calls_used: 0 },
  })
  api.aiDashboard.mockResolvedValue({
    jobs: [],
    recent_traces: [],
    requests: 0,
    model_calls: 0,
    cache_hits: 0,
  })
})
afterEach(() => wrapper?.unmount())
async function render() {
  wrapper = mount(AIWorkspace)
  await flushPromises()
}

it('shows grounded answers and expands the cited inert source text', async () => {
  streamAnswer.mockImplementation(async (body, event) => {
    event('phase', { phase: 'sources', sources: [source] })
    event('answer', {
      status: 'complete',
      sources: [source],
      claims: [
        { text: '基于原文的中文解释', references: [{ source_id: 'S1', quote: source.text }] },
      ],
      telemetry: { latency_ms: 300, retrieval_ms: 20, mode: 'hybrid' },
      trace_id: 'trace-example',
    })
    event('done', {})
  })
  await render()
  await wrapper.get('#ai-question').setValue('解释 Log4j 漏洞')
  await wrapper.get('form').trigger('submit')
  await flushPromises()
  expect(wrapper.text()).toContain('基于原文的中文解释')
  expect(streamAnswer).toHaveBeenCalledWith(
    expect.objectContaining({ question: '解释 Log4j 漏洞', mode: 'hybrid' }),
    expect.any(Function),
    expect.any(AbortSignal),
  )
  await wrapper.get('.citation-button').trigger('click')
  expect(wrapper.get('details').attributes('open')).toBeDefined()
  expect(wrapper.get('mark').text()).toBe(source.text)
  expect(wrapper.find('script').exists()).toBe(false)
})

it('keeps deterministic statistics and returns criteria to the library', async () => {
  streamAnswer.mockImplementation(async (body, event) => {
    event('answer', {
      status: 'statistics',
      claims: [],
      sources: [],
      statistics: {
        count: 15,
        filters: { year_from: 2024, year_to: 2024, topic: 'Python', severity: 'HIGH' },
        source: '本地 PostgreSQL',
        scope: 'CVE 编号年份',
      },
      telemetry: { latency_ms: 100, retrieval_ms: 0, mode: 'hybrid' },
    })
  })
  await render()
  await wrapper.get('#ai-question').setValue('2024 年 Python 高危漏洞有多少条')
  await wrapper.get('form').trigger('submit')
  await flushPromises()
  expect(wrapper.get('.statistics-answer').text()).toContain('15')
  await wrapper.get('.statistics-answer button').trigger('click')
  expect(wrapper.emitted('browse')[0][0]).toEqual(
    expect.objectContaining({ year_from: 2024, topic: 'Python' }),
  )
})

it('retains readable sources when the model connection fails and defaults evaluations to retrieval only', async () => {
  streamAnswer.mockImplementation(async (body, event) => {
    event('phase', { phase: 'sources', sources: [source] })
    throw new Error('连接中断，请重试')
  })
  api.aiEvaluate.mockResolvedValue({ id: 'evaluation-job' })
  await render()
  await wrapper.get('#ai-question').setValue('解释 Log4j 漏洞')
  await wrapper.get('form').trigger('submit')
  await flushPromises()
  expect(wrapper.get('[role="alert"]').text()).toContain('连接中断')
  expect(wrapper.text()).toContain('CVE-2021-44228')
  await wrapper
    .findAll('[role="tab"]')
    .find((item) => item.text().includes('质量评测'))
    .trigger('click')
  await wrapper
    .findAll('button')
    .find((item) => item.text() === '运行评测')
    .trigger('click')
  await flushPromises()
  expect(api.aiEvaluate).toHaveBeenCalledWith(false, 'development')
})

it('shows evidence gaps instead of calling an empty abstention a citation pass', async () => {
  api.aiDashboard.mockResolvedValue({
    jobs: [
      {
        id: 'report',
        kind: 'evaluation',
        status: 'complete',
        created_at: '2026-10-29T11:00:00Z',
        result: {
          modes: {},
          generation: [
            {
              trace_id: 'empty',
              question: 'Log4j 的原因？',
              quote_validation_passed: false,
              quote_validation_status: 'no_citations',
              answer: { claims: [], sources: [], missing_information: ['没有找到 Log4j 证据。'] },
            },
          ],
        },
      },
    ],
    recent_traces: [],
  })
  await render()
  await wrapper
    .findAll('[role="tab"]')
    .find((item) => item.text().includes('质量评测'))
    .trigger('click')
  expect(wrapper.text()).toContain('资料不足，无引文可校验')
  expect(wrapper.text()).toContain('没有找到 Log4j 证据。')
})
