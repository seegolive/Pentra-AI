import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { EngagementOverviewCard } from './EngagementOverviewCard'
import type { Engagement, Finding } from '../lib/types'

// ── API mocks ──────────────────────────────────────────────────────────────
const mockApprove = vi.fn()
const mockStop = vi.fn()

vi.mock('../lib/api', () => ({
  useApproveAction: () => ({ mutateAsync: mockApprove, isPending: false }),
  useStopEngagement: () => ({ mutateAsync: mockStop, isPending: false }),
}))

vi.mock('../lib/toast', () => ({
  toastSuccess: vi.fn(),
  toastError: vi.fn(),
}))

// ── Fixtures ──────────────────────────────────────────────────────────────
function makeEngagement(overrides: Partial<Engagement> = {}): Engagement {
  return {
    id: 'eng-001',
    workspace_id: 'ws-001',
    name: 'Acme Pentest',
    description: null,
    mode: 'semi_auto',
    status: 'active',
    in_scope: ['acme.com'],
    out_of_scope: [],
    llm_model: 'qwen2.5-coder:32b',
    langgraph_thread_id: 'thread-001',
    opsec_mode: false,
    request_jitter_ms: 0,
    created_by: 'user-001',
    created_at: '2026-06-23T09:00:00Z',
    updated_at: '2026-06-23T09:00:00Z',
    started_at: '2026-06-23T09:00:00Z',
    completed_at: null,
    ...overrides,
  }
}

function makeFindings(severities: Array<Finding['severity']>): Finding[] {
  return severities.map((severity, i) => ({
    id: `f-${i}`,
    engagement_id: 'eng-001',
    title: `Finding ${i}`,
    vuln_class: 'sqli',
    severity,
    cvss_score: null,
    target_url: 'https://acme.com/login',
    http_method: 'POST',
    status: 'open',
    discovered_by: 'agent',
    discovered_at: '2026-06-23T10:00:00Z',
    cve_ids: [],
  }))
}

function renderCard(eng: Engagement, findings: Finding[] = []) {
  return render(
    <MemoryRouter>
      <EngagementOverviewCard engagement={eng} findings={findings} />
    </MemoryRouter>
  )
}

beforeEach(() => {
  mockApprove.mockReset()
  mockStop.mockReset()
})

describe('EngagementOverviewCard', () => {
  // ── renders ───────────────────────────────────────────────────────────────

  it('renders engagement name', () => {
    renderCard(makeEngagement())
    expect(screen.getByText('Acme Pentest')).toBeInTheDocument()
  })

  it('renders finding counts', () => {
    const findings = makeFindings(['critical', 'critical', 'high', 'medium', 'low'])
    renderCard(makeEngagement(), findings)
    expect(screen.getByText('2')).toBeInTheDocument()  // crit count (unique)
    expect(screen.getAllByText('1').length).toBeGreaterThanOrEqual(1) // high/med counts
    expect(screen.getByText('5')).toBeInTheDocument()  // all count
  })

  it('renders zero counts when no findings', () => {
    renderCard(makeEngagement(), [])
    // All four KPI cells should show 0
    const zeros = screen.getAllByText('0')
    expect(zeros.length).toBeGreaterThanOrEqual(4)
  })

  it('renders View button', () => {
    renderCard(makeEngagement())
    expect(screen.getByRole('button', { name: /view/i })).toBeInTheDocument()
  })

  // ── status-dependent buttons ──────────────────────────────────────────────

  it('shows Approve button when status=awaiting_approval', () => {
    renderCard(makeEngagement({ status: 'awaiting_approval' }))
    expect(screen.getByRole('button', { name: /approve/i })).toBeInTheDocument()
  })

  it('does not show Approve button when status=active', () => {
    renderCard(makeEngagement({ status: 'active' }))
    expect(screen.queryByRole('button', { name: /approve/i })).not.toBeInTheDocument()
  })

  it('shows Stop button when status=active', () => {
    renderCard(makeEngagement({ status: 'active' }))
    // Stop button has OctagonX icon, no text — find by role
    const buttons = screen.getAllByRole('button')
    // At least View + Stop
    expect(buttons.length).toBeGreaterThanOrEqual(2)
  })

  it('shows Stop button when status=awaiting_approval', () => {
    renderCard(makeEngagement({ status: 'awaiting_approval' }))
    const buttons = screen.getAllByRole('button')
    expect(buttons.length).toBeGreaterThanOrEqual(3) // View + Approve + Stop
  })

  it('does not show Stop button when status=completed', () => {
    renderCard(makeEngagement({ status: 'completed' }))
    // Only View button visible
    expect(screen.getAllByRole('button')).toHaveLength(1)
  })

  it('shows Planning text when status=planning', () => {
    renderCard(makeEngagement({ status: 'planning' }))
    expect(screen.getByText('Planning')).toBeInTheDocument()
  })

  // ── actions ───────────────────────────────────────────────────────────────

  it('clicking Approve calls approve.mutateAsync', async () => {
    mockApprove.mockResolvedValue({})
    renderCard(makeEngagement({ status: 'awaiting_approval' }))
    await userEvent.click(screen.getByRole('button', { name: /approve/i }))
    expect(mockApprove).toHaveBeenCalledWith({ action: 'approve' })
  })

  it('clicking Stop calls stop.mutateAsync', async () => {
    mockStop.mockResolvedValue({})
    renderCard(makeEngagement({ status: 'active' }))
    // Stop button — last button in the card
    const buttons = screen.getAllByRole('button')
    await userEvent.click(buttons[buttons.length - 1])
    expect(mockStop).toHaveBeenCalledOnce()
  })
})
