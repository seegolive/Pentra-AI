import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import WorkspacesPage from './WorkspacesPage'
import type { Workspace } from '../lib/types'

const { mockUseWorkspaces, mockCreate, mockNavigate } = vi.hoisted(() => ({
  mockUseWorkspaces: vi.fn(),
  mockCreate: vi.fn(),
  mockNavigate: vi.fn(),
}))

vi.mock('../lib/api', () => ({
  useWorkspaces: mockUseWorkspaces,
  useCreateWorkspace: () => ({ mutateAsync: mockCreate, isPending: false }),
}))

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom')
  return { ...actual, useNavigate: () => mockNavigate }
})

function makeWorkspace(overrides: Partial<Workspace> = {}): Workspace {
  return {
    id: 'ws-1',
    name: 'Bug Bounty',
    description: 'Public program testing',
    owner_id: 'user-1',
    created_at: '2026-06-23T08:00:00Z',
    updated_at: '2026-06-23T08:00:00Z',
    ...overrides,
  }
}

beforeEach(() => {
  mockUseWorkspaces.mockReset()
  mockCreate.mockReset()
  mockNavigate.mockReset()
  mockUseWorkspaces.mockReturnValue({ data: [], isLoading: false })
})

describe('WorkspacesPage', () => {
  it('renders page heading', () => {
    render(<WorkspacesPage />)
    expect(screen.getByRole('heading', { name: 'Workspaces' })).toBeInTheDocument()
  })

  it('shows loading state', () => {
    mockUseWorkspaces.mockReturnValue({ data: undefined, isLoading: true })
    render(<WorkspacesPage />)
    expect(screen.getByText('Loading…')).toBeInTheDocument()
  })

  it('shows empty state when no workspaces exist', () => {
    render(<WorkspacesPage />)
    expect(screen.getByText('No workspaces yet')).toBeInTheDocument()
    expect(screen.getByText('Create one to get started')).toBeInTheDocument()
  })

  it('renders workspace cards', () => {
    mockUseWorkspaces.mockReturnValue({
      data: [
        makeWorkspace(),
        makeWorkspace({ id: 'ws-2', name: 'Client Alpha', description: null }),
      ],
      isLoading: false,
    })

    render(<WorkspacesPage />)

    expect(screen.getByText('Bug Bounty')).toBeInTheDocument()
    expect(screen.getByText('Public program testing')).toBeInTheDocument()
    expect(screen.getByText('Client Alpha')).toBeInTheDocument()
  })

  it('opens create form from New Workspace button', async () => {
    render(<WorkspacesPage />)

    await userEvent.click(screen.getByRole('button', { name: /new workspace/i }))

    expect(screen.getByRole('heading', { name: 'Create Workspace' })).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Workspace name')).toBeInTheDocument()
  })

  it('submits create workspace form', async () => {
    mockCreate.mockResolvedValue(makeWorkspace({ id: 'ws-new', name: 'New Client' }))
    render(<WorkspacesPage />)

    await userEvent.click(screen.getByRole('button', { name: /new workspace/i }))
    await userEvent.type(screen.getByPlaceholderText('Workspace name'), 'New Client')
    await userEvent.type(screen.getByPlaceholderText('Description (optional)'), 'Quarterly pentest')
    await userEvent.click(screen.getByRole('button', { name: 'Create' }))

    expect(mockCreate).toHaveBeenCalledWith({
      name: 'New Client',
      description: 'Quarterly pentest',
    })
  })

  it('navigates to workspace engagements when a card is clicked', async () => {
    mockUseWorkspaces.mockReturnValue({
      data: [makeWorkspace({ id: 'ws-7', name: 'Client Seven' })],
      isLoading: false,
    })
    render(<WorkspacesPage />)

    await userEvent.click(screen.getByRole('button', { name: /client seven/i }))

    expect(mockNavigate).toHaveBeenCalledWith('/workspaces/ws-7/engagements')
  })
})
