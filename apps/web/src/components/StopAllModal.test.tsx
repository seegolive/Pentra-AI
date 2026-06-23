import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { StopAllModal } from './StopAllModal'
import type { Engagement } from '../lib/types'

const { mockPatch, mockStop, mockToastSuccess, mockToastError } = vi.hoisted(() => ({
  mockPatch: vi.fn(),
  mockStop: vi.fn(),
  mockToastSuccess: vi.fn(),
  mockToastError: vi.fn(),
}))

vi.mock('../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../lib/api')>('../lib/api')
  return {
    ...actual,
    apiClient: { patch: mockPatch },
    useStopEngagement: () => ({ mutateAsync: mockStop, isPending: false }),
  }
})

vi.mock('../lib/toast', () => ({
  toastSuccess: mockToastSuccess,
  toastError: mockToastError,
}))

function makeEngagement(overrides: Partial<Engagement> = {}): Engagement {
  return {
    id: 'eng-1',
    workspace_id: 'ws-1',
    name: 'Acme Scan',
    description: null,
    mode: 'semi_auto',
    status: 'active',
    in_scope: ['acme.test'],
    out_of_scope: [],
    llm_model: 'qwen2.5-coder:7b',
    langgraph_thread_id: 'eng-1',
    opsec_mode: false,
    request_jitter_ms: 0,
    scan_sequential: false,
    auto_approve_exploit_validation: false,
    created_by: 'user-1',
    created_at: '2026-06-23T08:00:00Z',
    updated_at: '2026-06-23T08:00:00Z',
    started_at: '2026-06-23T08:01:00Z',
    completed_at: null,
    ...overrides,
  }
}

function renderModal(props: Partial<React.ComponentProps<typeof StopAllModal>> = {}) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <QueryClientProvider client={qc}>
      <StopAllModal
        open={true}
        onClose={vi.fn()}
        runningEngagements={[makeEngagement()]}
        {...props}
      />
    </QueryClientProvider>
  )
}

beforeEach(() => {
  mockPatch.mockReset()
  mockStop.mockReset()
  mockToastSuccess.mockReset()
  mockToastError.mockReset()
  mockPatch.mockResolvedValue({ data: { status: 'cancelled' } })
  mockStop.mockResolvedValue({ status: 'cancelled' })
})

describe('StopAllModal', () => {
  it('renders nothing when open=false', () => {
    renderModal({ open: false })
    expect(screen.queryByText('Stop Running Engagements')).not.toBeInTheDocument()
  })

  it('renders running engagement names', () => {
    renderModal({
      runningEngagements: [
        makeEngagement({ id: 'eng-1', name: 'Acme Scan' }),
        makeEngagement({ id: 'eng-2', name: 'Beta Scan', status: 'awaiting_approval' }),
      ],
    })

    expect(screen.getByText('Stop Running Engagements')).toBeInTheDocument()
    expect(screen.getByText('Acme Scan')).toBeInTheDocument()
    expect(screen.getByText('Beta Scan')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Stop All (2)' })).toBeInTheDocument()
  })

  it('disables Stop All when there are no running engagements', () => {
    renderModal({ runningEngagements: [] })
    expect(screen.getByRole('button', { name: 'Stop All (0)' })).toBeDisabled()
  })

  it('calls onClose from Cancel', async () => {
    const onClose = vi.fn()
    renderModal({ onClose })

    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))

    expect(onClose).toHaveBeenCalledOnce()
  })

  it('stops a single engagement from its row button', async () => {
    renderModal()

    await userEvent.click(screen.getByRole('button', { name: 'Stop' }))

    expect(mockStop).toHaveBeenCalledOnce()
    expect(await screen.findByText('Stopped')).toBeInTheDocument()
  })

  it('Stop All patches each pending engagement and closes on success', async () => {
    const onClose = vi.fn()
    renderModal({
      onClose,
      runningEngagements: [
        makeEngagement({ id: 'eng-1', name: 'Acme Scan' }),
        makeEngagement({ id: 'eng-2', name: 'Beta Scan' }),
      ],
    })

    await userEvent.click(screen.getByRole('button', { name: 'Stop All (2)' }))

    await waitFor(() => expect(mockPatch).toHaveBeenCalledTimes(2))
    expect(mockPatch).toHaveBeenNthCalledWith(1, '/api/v1/engagements/eng-1/stop')
    expect(mockPatch).toHaveBeenNthCalledWith(2, '/api/v1/engagements/eng-2/stop')
    expect(mockToastSuccess).toHaveBeenCalledWith(
      'All engagements stopped',
      '2 engagement(s) stopped successfully'
    )
    expect(onClose).toHaveBeenCalledOnce()
  })

  it('shows partial failure toast and leaves modal open when one stop fails', async () => {
    const onClose = vi.fn()
    mockPatch
      .mockResolvedValueOnce({ data: { status: 'cancelled' } })
      .mockRejectedValueOnce(new Error('boom'))
    renderModal({
      onClose,
      runningEngagements: [
        makeEngagement({ id: 'eng-1', name: 'Acme Scan' }),
        makeEngagement({ id: 'eng-2', name: 'Beta Scan' }),
      ],
    })

    await userEvent.click(screen.getByRole('button', { name: 'Stop All (2)' }))

    await waitFor(() =>
      expect(mockToastError).toHaveBeenCalledWith('Partial failure', '1 stopped, 1 failed')
    )
    expect(onClose).not.toHaveBeenCalled()
  })

  it('disables Stop All after all engagements are stopped individually', async () => {
    renderModal()

    await userEvent.click(screen.getByRole('button', { name: 'Stop' }))

    expect(await screen.findByRole('button', { name: 'Stop All (0)' })).toBeDisabled()
  })
})
