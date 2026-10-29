import { describe, expect, it } from 'vitest'
import { formatDate, safeReference, scoreText, syncPayload } from './format'

describe('NVD presentation contract', () => {
  it('keeps missing scores distinct from a legitimate zero', () => {
    expect(scoreText(null)).toBe('—')
    expect(scoreText(undefined)).toBe('—')
    expect(scoreText(0)).toBe('0.0')
    expect(scoreText(9.8)).toBe('9.8')
  })
  it('rejects executable and malformed reference URLs', () => {
    expect(safeReference('javascript:alert(1)')).toBeNull()
    expect(safeReference('data:text/html,test')).toBeNull()
    expect(safeReference('bad-url')).toBeNull()
    expect(safeReference('https://nvd.nist.gov/')).toBe('https://nvd.nist.gov/')
  })
  it('normalizes CVE inputs and bounds keyword imports', () => {
    expect(syncPayload('cve', ' cve-2021-44228 ', 100)).toEqual({ cve_id: 'CVE-2021-44228' })
    expect(syncPayload('keyword', ' openssl ', '20')).toEqual({
      keyword: 'openssl',
      max_records: 20,
    })
    expect(() => syncPayload('cve', 'bad', 10)).toThrow('CVE 编号格式')
    expect(() => syncPayload('keyword', '', 10)).toThrow('请输入')
    for (const limit of [0, 1001, 1.5]) expect(() => syncPayload('keyword', 'x', limit)).toThrow()
    expect(() => syncPayload('keyword', 'x'.repeat(101), 10)).toThrow('100')
  })
  it('handles missing and invalid timestamps', () => {
    expect(formatDate(null)).toBe('—')
    expect(formatDate('invalid')).toBe('—')
    expect(formatDate('2024-01-01T00:00:00Z')).toContain('2024')
  })
})
