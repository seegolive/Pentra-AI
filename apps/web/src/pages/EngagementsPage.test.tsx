import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import EngagementsPage from './EngagementsPage'
import type { Engagement, Workspace } from '../lib/types'

const {
  mockUseEngagements,
  mockUseWorkspaces,
  mockCreate,
  mockImport,
  mockNavigate,
  mockUseParams,
} = vi.hoisted(() => ({
  mockUseEngagements: vi.fn(),
  mockUseWorkspaces: vi.fn(),
  mockCreate: vi.fn(),
  mockImport: vi.fn(),
  mockNavigate: vi.fn(),
  mockUseParams: vi.fn(),
}))

vi.mock('../lib/api', () => ({
  useEngagements: mockUseEngagements,
  useWorkspaces: mockUseWorkspaces,
  useCreateEngagement: () => ({ mutateAsync: mockCreate, isPending: false }),
  useImportEngagement: () => ({ mutateAsync: mockImport, isPending: false }),
}))

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom')
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useParams: () => mockUseParams(),
  }
})

function makeWorkspace(overrides: Partial<Workspace> = {}): Workspace {
  return {
    id: 'ws-1',
    name: 'Acme Workspace',
    description: 'Bug bounty work',
    created_at: '2026-06-23T08:00:00Z',
    updated_at: '2026-06-23T08:00:00Z',
    ...overrides,
  }
}

function makeEngagement(overrides: Partial<Engagement> = {}): Engagement {
  return {
    id: 'eng-1',
    workspace_id: 'ws-1',
    name: 'Acme Q2',
    description: 'External test',
    mode: 'semi_auto',
    status: 'planning',
    in_scope: ['acme.test'],
    out_of_scope: [],
    llm_model: 'qwen2.5-coder:7b',
    langgraph_thread_id: 'eng-1',
    opsec_mode: false,
    request_jitter_ms: 0,
    created_by: 'user-1',
    created_at: '2026-06-23T08:00:00Z',
    updated_at: '2026-06-23T08:00:00Z',
    started_at: null,
    completed_at: null,
    ...overrides,
  }
}

beforeEach(() => {
  mockUseEngagements.mockReset()
  mockUseWorkspaces.mockReset()
  mockCreate.mockReset()
  mockImport.mockReset()
  mockNavigate.mockReset()
  mockUseParams.mockReset()
  mockUseParams.mockReturnValue({ workspaceId: 'ws-1' })
  mockUseWorkspaces.mockReturnValue({ data: [makeWorkspace()] })
  mockUseEngagements.mockReturnValue({ data: [], isLoading: false })
  mockCreate.mockResolvedValue(makeEngagement())
  mockImport.mockResolvedValue(makeEngagement())
  vi.stubGlobal('alert', vi.fn())
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('EngagementsPage', () => {
  it('renders page heading and workspace breadcrumb', () => {
    render(<EngagementsPage />)

    expect(screen.getByRole('heading', { name: 'Engagements' })).toBeInTheDocument()
    expect(screen.getByText('Acme Workspace')).toBeInTheDocument()
  })

  it('requests engagements for the current workspace id', () => {
    render(<EngagementsPage />)
    expect(mockUseEngagements).toHaveBeenCalledWith('ws-1')
  })

  it('shows loading state', () => {
    mockUseEngagements.mockReturnValue({ data: undefined, isLoading: true })
    render(<EngagementsPage />)
    expect(screen.getByText('Loading…')).toBeInTheDocument()
  })

  it('shows empty state when there are no engagements', () => {
    render(<EngagementsPage />)
    expect(screen.getByText('No engagements yet')).toBeInTheDocument()
    expect(screen.getByText('Create one to start a penetration test')).toBeInTheDocument()
  })

  it('renders engagement cards with status, mode, scope count, and model', () => {
    mockUseEngagements.mockReturnValue({
      data: [
        makeEngagement({
          id: 'eng-1',
          name: 'Acme Q2',
          status: 'planning',
          mode: 'semi_auto',
          in_scope: ['acme.test', 'api.acme.test'],
        }),
        makeEngagement({
          id: 'eng-2',
          name: 'Beta Agentic',
          status: 'active',
          mode: 'agentic',
          description: null,
        }),
      ],
      isLoading: false,
    })

    render(<EngagementsPage />)

    expect(screen.getByText('Acme Q2')).toBeInTheDocument()
    expect(screen.getByText('Planning')).toBeInTheDocument()
    expect(screen.getByText('Semi-Auto')).toBeInTheDocument()
    expect(screen.getByText('2 in-scope targets')).toBeInTheDocument()
    expect(screen.getAllByText('qwen2.5-coder:7b')).toHaveLength(2)
    expect(screen.getByText('Beta Agentic')).toBeInTheDocument()
    expect(screen.getByText('Agentic')).toBeInTheDocument()
  })

  it('navigates back to workspaces from breadcrumb', async () => {
    render(<EngagementsPage />)

    await userEvent.click(screen.getByRole('button', { name: 'Workspaces' }))

    expect(mockNavigate).toHaveBeenCalledWith('/workspaces')
  })

  it('navigates to engagement detail when a card is clicked', async () => {
    mockUseEngagements.mockReturnValue({
      data: [makeEngagement({ id: 'eng-7', name: 'Seven Scan' })],
      isLoading: false,
    })
    render(<EngagementsPage />)

    await userEvent.click(screen.getByRole('button', { name: /seven scan/i }))

    expect(mockNavigate).toHaveBeenCalledWith('/engagements/eng-7')
  })

  it('opens create engagement form', async () => {
    render(<EngagementsPage />)

    await userEvent.click(screen.getByRole('button', { name: /new engagement/i }))

    expect(screen.getByRole('heading', { name: 'New Engagement' })).toBeInTheDocument()
    expect(screen.getByPlaceholderText(/HackerOne/)).toBeInTheDocument()
  })

  it('create form requires name and in-scope target before submit', async () => {
    render(<EngagementsPage />)
    await userEvent.click(screen.getByRole('button', { name: /new engagement/i }))

    expect(screen.getByRole('button', { name: 'Create Engagement' })).toBeDisabled()

    await userEvent.type(screen.getByPlaceholderText(/HackerOne/), 'Acme New')
    expect(screen.getByRole('button', { name: 'Create Engagement' })).toBeDisabled()

    await userEvent.type(screen.getAllByPlaceholderText(/target.com/)[0], 'acme.test')
    expect(screen.getByRole('button', { name: 'Create Engagement' })).not.toBeDisabled()
  })

  it('submits create engagement payload', async () => {
    render(<EngagementsPage />)
    await userEvent.click(screen.getByRole('button', { name: /new engagement/i }))

    await userEvent.type(screen.getByPlaceholderText(/HackerOne/), 'Acme New')
    await userEvent.type(screen.getByPlaceholderText('Optional notes'), 'Quarterly run')
    await userEvent.type(screen.getAllByPlaceholderText(/target.com/)[0], 'acme.test\napi.acme.test')
    await userEvent.type(screen.getByPlaceholderText(/^admin.target.com/), 'admin.acme.test')
    await userEvent.click(screen.getByRole('button', { name: 'Create Engagement' }))

    expect(mockCreate).toHaveBeenCalledWith({
      workspace_id: 'ws-1',
      name: 'Acme New',
      description: 'Quarterly run',
      mode: 'semi_auto',
      in_scope: ['acme.test', 'api.acme.test'],
      out_of_scope: ['admin.acme.test'],
      llm_model: 'qwen2.5-coder:32b',
      opsec_mode: false,
      request_jitter_ms: 0,
    })
  })

  it('shows agentic warning when mode is switched', async () => {
    render(<EngagementsPage />)
    await userEvent.click(screen.getByRole('button', { name: /new engagement/i }))

    await userEvent.selectOptions(screen.getByDisplayValue('Semi-Auto (HITL)'), 'agentic')

    expect(screen.getByText(/Mode Agentic/)).toBeInTheDocument()
  })

  it('imports HackerOne scope into form fields', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({
        program_name: 'Shopify',
        in_scope: ['shopify.test', '*.shopify.test'],
        out_of_scope: ['payments.shopify.test'],
      }),
    }))
    render(<EngagementsPage />)
    await userEvent.click(screen.getByRole('button', { name: /new engagement/i }))

    await userEvent.type(screen.getByPlaceholderText(/Program handle/), 'shopify')
    await userEvent.click(screen.getAllByRole('button', { name: 'Import' })[1])

    expect(await screen.findByDisplayValue('Shopify')).toBeInTheDocument()
    expect(screen.getAllByPlaceholderText(/target.com/)[0]).toHaveValue('shopify.test\n*.shopify.test')
    expect(screen.getByPlaceholderText(/^admin.target.com/)).toHaveValue('payments.shopify.test')
  })

  it('imports an engagement export JSON file', async () => {
    render(<EngagementsPage />)
    const input = document.querySelector('input[type="file"]') as HTMLInputElement
    const file = new File([JSON.stringify({ export_version: '1', findings: [] })], 'engagement.json', {
      type: 'application/json',
    })

    await userEvent.upload(input, file)

    await waitFor(() =>
      expect(mockImport).toHaveBeenCalledWith({ bundle: { export_version: '1', findings: [] } })
    )
  })

  it('alerts when import file is invalid JSON', async () => {
    render(<EngagementsPage />)
    const input = document.querySelector('input[type="file"]') as HTMLInputElement
    const file = new File(['not-json'], 'bad.json', { type: 'application/json' })

    await userEvent.upload(input, file)

    await waitFor(() =>
      expect(globalThis.alert).toHaveBeenCalledWith(
        'Invalid export file — please select a valid Pentra engagement JSON.'
      )
    )
  })
})
