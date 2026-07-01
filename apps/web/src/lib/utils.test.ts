import { describe, it, expect } from 'vitest'
import {
  cn,
  formatBounty,
  SEVERITY_COLORS,
  SEVERITY_DOT,
  VULN_CLASS_LABELS,
} from './utils'
import type { Severity, VulnClass } from './types'

// ── cn() ─────────────────────────────────────────────────────────────────────

describe('cn', () => {
  it('merges class strings', () => {
    expect(cn('foo', 'bar')).toBe('foo bar')
  })

  it('deduplicates conflicting Tailwind classes', () => {
    const result = cn('text-red-500', 'text-blue-500')
    expect(result).toBe('text-blue-500')
  })

  it('ignores falsy values', () => {
    const falsy = false as boolean;
    expect(cn('foo', falsy && 'bar', null, undefined, '')).toBe('foo')
  })

  it('handles conditional classes via object syntax', () => {
    const result = cn({ 'font-bold': true, 'text-sm': false })
    expect(result).toBe('font-bold')
    expect(result).not.toContain('text-sm')
  })

  it('returns empty string for no args', () => {
    expect(cn()).toBe('')
  })

  it('merges array args', () => {
    expect(cn(['a', 'b'], 'c')).toBe('a b c')
  })
})

// ── formatBounty() ────────────────────────────────────────────────────────────

describe('formatBounty', () => {
  it('returns em-dash for null', () => {
    expect(formatBounty(null)).toBe('—')
  })

  it('formats zero as $0', () => {
    expect(formatBounty(0)).toBe('$0')
  })

  it('formats amounts under 1000 as plain dollar', () => {
    expect(formatBounty(500)).toBe('$500')
    expect(formatBounty(999)).toBe('$999')
  })

  it('formats 1000 as $1.0k', () => {
    expect(formatBounty(1000)).toBe('$1.0k')
  })

  it('formats large amounts in k with 1 decimal', () => {
    expect(formatBounty(2500)).toBe('$2.5k')
    expect(formatBounty(10000)).toBe('$10.0k')
    expect(formatBounty(12345)).toBe('$12.3k')
  })

  it('formats 100k correctly', () => {
    expect(formatBounty(100000)).toBe('$100.0k')
  })
})

// ── SEVERITY_COLORS ───────────────────────────────────────────────────────────

describe('SEVERITY_COLORS', () => {
  const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

  it('has an entry for every severity level', () => {
    for (const s of severities) {
      expect(SEVERITY_COLORS).toHaveProperty(s)
    }
  })

  it('critical uses red color classes', () => {
    expect(SEVERITY_COLORS.critical).toContain('red')
  })

  it('high uses orange color classes', () => {
    expect(SEVERITY_COLORS.high).toContain('orange')
  })

  it('medium uses yellow color classes', () => {
    expect(SEVERITY_COLORS.medium).toContain('yellow')
  })

  it('low uses blue color classes', () => {
    expect(SEVERITY_COLORS.low).toContain('blue')
  })

  it('each value is a non-empty string', () => {
    for (const val of Object.values(SEVERITY_COLORS)) {
      expect(typeof val).toBe('string')
      expect(val.length).toBeGreaterThan(0)
    }
  })
})

// ── SEVERITY_DOT ──────────────────────────────────────────────────────────────

describe('SEVERITY_DOT', () => {
  it('has exactly 5 severity levels', () => {
    expect(Object.keys(SEVERITY_DOT)).toHaveLength(5)
  })

  it('critical dot is red', () => {
    expect(SEVERITY_DOT.critical).toContain('red')
  })

  it('all values are background class strings', () => {
    for (const val of Object.values(SEVERITY_DOT)) {
      expect(val).toMatch(/^bg-/)
    }
  })
})

// ── VULN_CLASS_LABELS ─────────────────────────────────────────────────────────

describe('VULN_CLASS_LABELS', () => {
  const expectedKeys: VulnClass[] = [
    'sqli', 'xss', 'ssrf', 'idor', 'rce', 'lfi', 'xxe',
    'auth_bypass', 'privilege_escalation', 'info_disclosure',
    'csrf', 'open_redirect', 'ssti', 'path_traversal',
    'race_condition', 'business_logic', 'misconfig', 'dos', 'other',
  ]

  it('has a label for every known VulnClass', () => {
    for (const key of expectedKeys) {
      expect(VULN_CLASS_LABELS).toHaveProperty(key)
    }
  })

  it('sqli is labelled SQLi', () => {
    expect(VULN_CLASS_LABELS.sqli).toBe('SQLi')
  })

  it('all labels are non-empty strings', () => {
    for (const label of Object.values(VULN_CLASS_LABELS)) {
      expect(typeof label).toBe('string')
      expect(label.length).toBeGreaterThan(0)
    }
  })
})
