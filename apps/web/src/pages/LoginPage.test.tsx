import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import axios from 'axios'
import LoginPage from './LoginPage'
import { useAuthStore } from '../lib/authStore'

const { mockLogin, mockGetMe, mockNavigate } = vi.hoisted(() => ({
  mockLogin: vi.fn(),
  mockGetMe: vi.fn(),
  mockNavigate: vi.fn(),
}))

vi.mock('../lib/api', () => ({
  useLogin: () => ({ mutateAsync: mockLogin, isPending: false }),
  getMeApi: mockGetMe,
}))

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom')
  return { ...actual, useNavigate: () => mockNavigate }
})

vi.mock('axios')

beforeEach(() => {
  mockLogin.mockReset()
  mockGetMe.mockReset()
  mockNavigate.mockReset()
  vi.mocked(axios.get).mockResolvedValue({ data: { requires_setup: false } })
  useAuthStore.setState({
    accessToken: null,
    refreshToken: null,
    user: null,
  })
})

describe('LoginPage', () => {
  it('renders the sign-in heading', () => {
    render(<LoginPage />)
    expect(screen.getByRole('heading', { name: 'Sign in' })).toBeInTheDocument()
  })

  it('renders username and password fields', () => {
    render(<LoginPage />)
    expect(screen.getByLabelText('Username')).toBeInTheDocument()
    expect(screen.getByLabelText('Password')).toBeInTheDocument()
  })

  it('marks both form fields as required', () => {
    render(<LoginPage />)
    expect(screen.getByLabelText('Username')).toBeRequired()
    expect(screen.getByLabelText('Password')).toBeRequired()
  })

  it('submits credentials and redirects after successful login', async () => {
    mockLogin.mockResolvedValue({
      access_token: 'access-123',
      refresh_token: 'refresh-456',
      token_type: 'bearer',
    })
    mockGetMe.mockResolvedValue({
      id: 'user-1',
      username: 'alice',
      email: 'alice@test.local',
      is_admin: false,
    })

    render(<LoginPage />)
    await userEvent.type(screen.getByLabelText('Username'), 'alice')
    await userEvent.type(screen.getByLabelText('Password'), 'hunter2')
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }))

    expect(mockLogin).toHaveBeenCalledWith({ username: 'alice', password: 'hunter2' })
    await waitFor(() => expect(mockNavigate).toHaveBeenCalledWith('/workspaces'))
    expect(useAuthStore.getState().accessToken).toBe('access-123')
    expect(useAuthStore.getState().user?.username).toBe('alice')
  })

  it('shows API error detail when login fails', async () => {
    mockLogin.mockRejectedValue({
      response: { data: { detail: 'Invalid credentials' } },
    })

    render(<LoginPage />)
    await userEvent.type(screen.getByLabelText('Username'), 'alice')
    await userEvent.type(screen.getByLabelText('Password'), 'wrong')
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }))

    expect(await screen.findByText('Invalid credentials')).toBeInTheDocument()
  })

  it('redirects already-authenticated users to workspaces', async () => {
    useAuthStore.setState({ accessToken: 'already-in', refreshToken: 'refresh' })
    render(<LoginPage />)
    await waitFor(() =>
      expect(mockNavigate).toHaveBeenCalledWith('/workspaces', { replace: true })
    )
  })

  it('redirects to setup when first-run setup is required', async () => {
    vi.mocked(axios.get).mockResolvedValue({ data: { requires_setup: true } })
    render(<LoginPage />)
    await waitFor(() =>
      expect(mockNavigate).toHaveBeenCalledWith('/setup', { replace: true })
    )
  })
})
