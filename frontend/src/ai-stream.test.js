import { afterEach, expect, it, vi } from 'vitest'
import { streamAnswer } from './api'
afterEach(() => vi.unstubAllGlobals())
function stream(text) {
  const bytes = new TextEncoder().encode(text)
  return new ReadableStream({
    start(controller) {
      for (let offset = 0; offset < bytes.length; offset += 7)
        controller.enqueue(bytes.slice(offset, offset + 7))
      controller.close()
    },
  })
}
it('decodes split UTF-8 SSE packets without displaying unvalidated partial answers', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue({
      ok: true,
      body: stream(
        'event: phase\ndata: {"phase":"generating"}\n\n: keepalive\n\nevent: answer\ndata: {"status":"complete","text":"中文解释"}\n\nevent: done\ndata: {}\n\n',
      ),
    }),
  )
  const events = []
  await streamAnswer(
    { question: '解释漏洞' },
    (event, data) => events.push([event, data]),
    new AbortController().signal,
  )
  expect(events.map(([event]) => event)).toEqual(['phase', 'answer', 'done'])
  expect(events[1][1].text).toBe('中文解释')
})
it('reports an incomplete connection instead of marking it complete', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue({
      ok: true,
      body: stream('event: phase\ndata: {"phase":"generating"}\n\n'),
    }),
  )
  await expect(streamAnswer({}, () => {}, new AbortController().signal)).rejects.toThrow('连接中断')
})
