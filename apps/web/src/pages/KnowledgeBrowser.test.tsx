import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import KnowledgeBrowser from './KnowledgeBrowser'
import type { KnowledgeSummary, SearchFilters } from '../lib/types'

const { mockUseKnowledgeSearch, mockNavigate } = vi.hoisted(() => ({
  mockUseKnowledgeSearch: vi.fn(),
  mockNavigate: vi.fn(),
}))

vi.mock('../lib/api', () => ({
  useKnowledgeSearch: mockUseKnowledgeSearch,
}))

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom')
  return { ...actual, useNavigate: () => mockNavigate }
})

vi.mock('../components/KnowledgeCard', () => ({
  KnowledgeCard: ({ record, onClick }: { record: KnowledgeSummary; onClick: (id: string) => void }) => (
    <button type="button" onClick={() => onClick(record.id)}>
      {record.title}
    </button>
  ),
}))

vi.mock('../components/KnowledgeDrawer', () => ({
  KnowledgeDrawer: ({ recordId, onClose }: { recordId: string | null; onClose: () => void }) => (
    recordId ? (
      <div role="dialog" aria-label="Knowledge drawer">
        Drawer {recordId}
        <button type="button" onClick={onClose}>Close Drawer</button>
      </div>
    ) : null
  ),
}))

vi.mock('../components/FilterPanel', () => ({
  FilterPanel: ({ filters, onChange }: { filters: SearchFilters; onChange: (f: SearchFilters) => void }) => (
    <div>
      <span>Filter Panel</span>
      <span data-testid="severity-count">{filters.severity.length}</span>
      <button
        type="button"
        onClick={() => onChange({ ...filters, severity: ['high'] })}
      >
        Apply High
      </button>
    </div>
  ),
}))

function makeRecord(overrides: Partial<KnowledgeSummary> = {}): KnowledgeSummary {
  return {
    id: 'kb-1',
    title: 'IDOR on Rails API',
    vuln_class: 'idor',
    severity: 'high',
    program: 'acme',
    tech_stack: ['rails'],
    key_insight: 'Missing object authorization',
    bounty_usd: 500,
    source: 'h1_public',
    source_url: 'https://hackerone.test/report/1',
    ...overrides,
  }
}

beforeEach(() => {
  mockUseKnowledgeSearch.mockReset()
  mockNavigate.mockReset()
  mockUseKnowledgeSearch.mockReturnValue({
    data: undefined,
    isLoading: false,
    isError: false,
    error: null,
  })
})

describe('KnowledgeBrowser', () => {
  it('renders header and initial empty state', () => {
    render(<KnowledgeBrowser />)

    expect(screen.getByText('Knowledge Base')).toBeInTheDocument()
    expect(screen.getByText('Enter a query to search the knowledge base')).toBeInTheDocument()
    expect(screen.getByPlaceholderText(/Search by attack type/)).toBeInTheDocument()
  })

  it('keeps Search disabled until query has non-space content', async () => {
    render(<KnowledgeBrowser />)
    const searchButton = screen.getByRole('button', { name: 'Search' })

    expect(searchButton).toBeDisabled()
    await userEvent.type(screen.getByPlaceholderText(/Search by attack type/), '   ')
    expect(searchButton).toBeDisabled()
  })

  it('submits search by clicking Search', async () => {
    render(<KnowledgeBrowser />)

    await userEvent.type(screen.getByPlaceholderText(/Search by attack type/), 'IDOR rails')
    await userEvent.click(screen.getByRole('button', { name: 'Search' }))

    expect(mockUseKnowledgeSearch).toHaveBeenLastCalledWith(
      { q: 'IDOR rails', severity: [], vuln_class: [], tech_stack: [] },
      true
    )
  })

  it('submits search with Enter key', async () => {
    render(<KnowledgeBrowser />)

    await userEvent.type(screen.getByPlaceholderText(/Search by attack type/), 'SSRF metadata{Enter}')

    expect(mockUseKnowledgeSearch).toHaveBeenLastCalledWith(
      { q: 'SSRF metadata', severity: [], vuln_class: [], tech_stack: [] },
      true
    )
  })

  it('shows loading state', () => {
    mockUseKnowledgeSearch.mockReturnValue({
      data: undefined,
      isLoading: true,
      isError: false,
      error: null,
    })

    render(<KnowledgeBrowser />)

    expect(screen.getByText('Searching…')).toBeInTheDocument()
  })

  it('shows search error message', async () => {
    mockUseKnowledgeSearch.mockReturnValue({
      data: undefined,
      isLoading: false,
      isError: true,
      error: new Error('Search API unavailable'),
    })

    render(<KnowledgeBrowser />)
    await userEvent.type(screen.getByPlaceholderText(/Search by attack type/), 'xss')
    await userEvent.click(screen.getByRole('button', { name: 'Search' }))

    expect(screen.getByText('Search failed: Search API unavailable')).toBeInTheDocument()
  })

  it('renders zero-result state after search', async () => {
    mockUseKnowledgeSearch.mockReturnValue({
      data: [],
      isLoading: false,
      isError: false,
      error: null,
    })

    render(<KnowledgeBrowser />)
    await userEvent.type(screen.getByPlaceholderText(/Search by attack type/), 'nope')
    await userEvent.click(screen.getByRole('button', { name: 'Search' }))

    expect(screen.getByText('No results for "nope"')).toBeInTheDocument()
    expect(screen.getByText('No matching records found')).toBeInTheDocument()
  })

  it('renders result cards and count', async () => {
    mockUseKnowledgeSearch.mockReturnValue({
      data: [
        makeRecord({ id: 'kb-1', title: 'IDOR on Rails API' }),
        makeRecord({ id: 'kb-2', title: 'SSRF against metadata service', vuln_class: 'ssrf' }),
      ],
      isLoading: false,
      isError: false,
      error: null,
    })

    render(<KnowledgeBrowser />)
    await userEvent.type(screen.getByPlaceholderText(/Search by attack type/), 'api bugs')
    await userEvent.click(screen.getByRole('button', { name: 'Search' }))

    expect(screen.getByText('2 results for "api bugs"')).toBeInTheDocument()
    expect(screen.getByText('IDOR on Rails API')).toBeInTheDocument()
    expect(screen.getByText('SSRF against metadata service')).toBeInTheDocument()
  })

  it('opens and closes drawer when a result is clicked', async () => {
    mockUseKnowledgeSearch.mockReturnValue({
      data: [makeRecord({ id: 'kb-42', title: 'Stored XSS in upload' })],
      isLoading: false,
      isError: false,
      error: null,
    })

    render(<KnowledgeBrowser />)
    await userEvent.type(screen.getByPlaceholderText(/Search by attack type/), 'xss')
    await userEvent.click(screen.getByRole('button', { name: 'Search' }))
    await userEvent.click(screen.getByRole('button', { name: 'Stored XSS in upload' }))

    const drawer = screen.getByRole('dialog', { name: 'Knowledge drawer' })
    expect(within(drawer).getByText(/Drawer kb-42/)).toBeInTheDocument()

    await userEvent.click(within(drawer).getByRole('button', { name: 'Close Drawer' }))
    expect(screen.queryByRole('dialog', { name: 'Knowledge drawer' })).not.toBeInTheDocument()
  })

  it('navigates to knowledge inject page', async () => {
    render(<KnowledgeBrowser />)

    await userEvent.click(screen.getByRole('button', { name: /inject/i }))

    expect(mockNavigate).toHaveBeenCalledWith('/knowledge/inject')
  })

  it('passes filter changes into subsequent search params', async () => {
    render(<KnowledgeBrowser />)

    await userEvent.click(screen.getByRole('button', { name: 'Apply High' }))
    await userEvent.type(screen.getByPlaceholderText(/Search by attack type/), 'sqli')
    await userEvent.click(screen.getByRole('button', { name: 'Search' }))

    expect(mockUseKnowledgeSearch).toHaveBeenLastCalledWith(
      { q: 'sqli', severity: ['high'], vuln_class: [], tech_stack: [] },
      true
    )
  })
})
