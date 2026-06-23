import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import DashboardPage from './DashboardPage'

const { mockGet, mockNavigate } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  mockNavigate: vi.fn(),
}))

vi.mock('../lib/api', () => ({
  apiClient: { get: mockGet },
}))

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom')
  return { ...actual, useNavigate: () => mockNavigate }
})

function renderDashboard() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  })
  return render(
    <QueryClientProvider client={qc}>
      <DashboardPage />
    </QueryClientProvider>
  )
}

function mockDashboardApi({
  engagements = [],
  findings = [],
  stats = {
    total_engagements: engagements.length,
    total_findings: findings.length,
    total_knowledge_records: 8341,
    total_workspaces: 2,
  },
}: {
  engagements?: unknown[]
  findings?: unknown[]
  stats?: Record<string, unknown>
} = {}) {
  mockGet.mockImplementation((url: string) => {
    if (url.startsWith('/api/v1/admin/stats')) return Promise.resolve({ data: stats })
    if (url.startsWith('/api/v1/engagements')) return Promise.resolve({ data: engagements })
    if (url.startsWith('/api/v1/findings/recent')) return Promise.resolve({ data: findings })
    return Promise.reject(new Error(`Unexpected URL: ${url}`))
  })
}

beforeEach(() => {
  mockGet.mockReset()
  mockNavigate.mockReset()
  mockDashboardApi()
})

describe('DashboardPage', () => {
  it('renders page heading', () => {
    renderDashboard()
    expect(screen.getByRole('heading', { name: 'Dashboard' })).toBeInTheDocument()
  })

  it('shows empty states when there are no engagements or findings', async () => {
    renderDashboard()
    expect(await screen.findByText('No engagements yet.')).toBeInTheDocument()
    expect(screen.getByText('No findings yet.')).toBeInTheDocument()
  })

  it('renders engagement cards from API data', async () => {
    mockDashboardApi({
      engagements: [
        {
          id: 'eng-1',
          name: 'Acme Scan',
          status: 'active',
          in_scope: ['acme.test'],
          target_domain: 'acme.test',
          findings_count: 3,
        },
      ],
    })

    renderDashboard()

    expect(await screen.findByText('Acme Scan')).toBeInTheDocument()
    expect(screen.getByText('acme.test')).toBeInTheDocument()
    expect(screen.getByText('3 findings')).toBeInTheDocument()
  })

  it('renders recent findings from API data', async () => {
    mockDashboardApi({
      findings: [
        {
          id: 'finding-1',
          engagement_id: 'eng-1',
          title: 'SQLi in search',
          severity: 'high',
          vuln_class: 'sql_injection',
        },
      ],
    })

    renderDashboard()

    expect(await screen.findByText('SQLi in search')).toBeInTheDocument()
    expect(screen.getByText('high')).toBeInTheDocument()
    expect(screen.getByText('sql_injection')).toBeInTheDocument()
  })

  it('navigates to workspaces from New Engagement button', async () => {
    renderDashboard()
    await userEvent.click(screen.getByRole('button', { name: /new engagement/i }))
    expect(mockNavigate).toHaveBeenCalledWith('/workspaces')
  })

  it('navigates to engagement detail when an engagement card is clicked', async () => {
    mockDashboardApi({
      engagements: [
        { id: 'eng-1', name: 'Acme Scan', status: 'active', in_scope: ['acme.test'] },
      ],
    })
    renderDashboard()

    await userEvent.click(await screen.findByText('Acme Scan'))

    expect(mockNavigate).toHaveBeenCalledWith('/engagements/eng-1')
  })

  it('navigates from quick action buttons', async () => {
    renderDashboard()
    await waitFor(() => expect(mockGet).toHaveBeenCalled())
    await userEvent.click(screen.getByRole('button', { name: /browse knowledge base/i }))
    expect(mockNavigate).toHaveBeenCalledWith('/knowledge')
  })
})
