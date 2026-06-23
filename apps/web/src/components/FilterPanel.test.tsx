import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { FilterPanel } from './FilterPanel'
import type { SearchFilters } from '../lib/types'

const empty: SearchFilters = { severity: [], vuln_class: [], tech_stack: [] }

describe('FilterPanel', () => {
  // ── render ────────────────────────────────────────────────────────────────

  it('renders "Filters" heading', () => {
    render(<FilterPanel filters={empty} onChange={vi.fn()} />)
    expect(screen.getByText('Filters')).toBeInTheDocument()
  })

  it('renders all 5 severity buttons', () => {
    render(<FilterPanel filters={empty} onChange={vi.fn()} />)
    // Use exact capitalize text to avoid matching vuln class labels (e.g. "Info Disclosure")
    for (const s of ['Critical', 'High', 'Medium', 'Low', 'Info']) {
      const btn = screen.getAllByRole('button', { name: new RegExp(`^${s}$`, 'i') })
      expect(btn.length).toBeGreaterThanOrEqual(1)
    }
  })

  it('renders vuln class buttons', () => {
    render(<FilterPanel filters={empty} onChange={vi.fn()} />)
    expect(screen.getByRole('button', { name: 'SQLi' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'XSS' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'SSRF' })).toBeInTheDocument()
  })

  // ── clear button ──────────────────────────────────────────────────────────

  it('does not show Clear button when no filters active', () => {
    render(<FilterPanel filters={empty} onChange={vi.fn()} />)
    expect(screen.queryByText(/Clear/)).not.toBeInTheDocument()
  })

  it('shows "Clear N" when severity filters active', () => {
    const f: SearchFilters = { ...empty, severity: ['critical', 'high'] }
    render(<FilterPanel filters={f} onChange={vi.fn()} />)
    expect(screen.getByText(/Clear 2/)).toBeInTheDocument()
  })

  it('counts all active filter types in clear count', () => {
    const f: SearchFilters = { severity: ['critical'], vuln_class: ['sqli', 'xss'], tech_stack: [] }
    render(<FilterPanel filters={f} onChange={vi.fn()} />)
    expect(screen.getByText(/Clear 3/)).toBeInTheDocument()
  })

  it('clicking Clear calls onChange with empty filters', async () => {
    const onChange = vi.fn()
    const f: SearchFilters = { ...empty, severity: ['critical'] }
    render(<FilterPanel filters={f} onChange={onChange} />)
    await userEvent.click(screen.getByText(/Clear/))
    expect(onChange).toHaveBeenCalledWith({ severity: [], vuln_class: [], tech_stack: [] })
  })

  // ── severity toggle ───────────────────────────────────────────────────────

  it('clicking a severity adds it to the filter', async () => {
    const onChange = vi.fn()
    render(<FilterPanel filters={empty} onChange={onChange} />)
    await userEvent.click(screen.getByRole('button', { name: /critical/i }))
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ severity: ['critical'] })
    )
  })

  it('clicking an active severity removes it', async () => {
    const onChange = vi.fn()
    const f: SearchFilters = { ...empty, severity: ['critical', 'high'] }
    render(<FilterPanel filters={f} onChange={onChange} />)
    await userEvent.click(screen.getByRole('button', { name: /critical/i }))
    const called = onChange.mock.calls[0][0] as SearchFilters
    expect(called.severity).not.toContain('critical')
    expect(called.severity).toContain('high')
  })

  // ── vuln class toggle ─────────────────────────────────────────────────────

  it('clicking a vuln class button adds it', async () => {
    const onChange = vi.fn()
    render(<FilterPanel filters={empty} onChange={onChange} />)
    await userEvent.click(screen.getByRole('button', { name: 'SQLi' }))
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ vuln_class: ['sqli'] })
    )
  })

  it('clicking an active vuln class removes it', async () => {
    const onChange = vi.fn()
    const f: SearchFilters = { ...empty, vuln_class: ['sqli', 'xss'] }
    render(<FilterPanel filters={f} onChange={onChange} />)
    await userEvent.click(screen.getByRole('button', { name: 'SQLi' }))
    const called = onChange.mock.calls[0][0] as SearchFilters
    expect(called.vuln_class).not.toContain('sqli')
    expect(called.vuln_class).toContain('xss')
  })

  it('toggling vuln class preserves existing severity filters', async () => {
    const onChange = vi.fn()
    const f: SearchFilters = { severity: ['high'], vuln_class: [], tech_stack: [] }
    render(<FilterPanel filters={f} onChange={onChange} />)
    await userEvent.click(screen.getByRole('button', { name: 'SQLi' }))
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ severity: ['high'], vuln_class: ['sqli'] })
    )
  })
})
