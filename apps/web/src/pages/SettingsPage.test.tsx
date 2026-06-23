import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import SettingsPage from './SettingsPage'
import { useAuthStore } from '../lib/authStore'

const { mockMutate, mockUseChangePassword, mockUseVersionInfo } = vi.hoisted(() => ({
  mockMutate: vi.fn(),
  mockUseChangePassword: vi.fn(),
  mockUseVersionInfo: vi.fn(),
}))

vi.mock('../lib/api', () => ({
  useChangePassword: mockUseChangePassword,
  useVersionInfo: mockUseVersionInfo,
}))

beforeEach(() => {
  mockMutate.mockReset()
  mockUseChangePassword.mockReset()
  mockUseVersionInfo.mockReset()
  mockUseChangePassword.mockReturnValue({ mutate: mockMutate, isPending: false, error: null })
  mockUseVersionInfo.mockReturnValue({
    data: {
      version: '1.2.3',
      build_date: '2026-06-23',
      phase: 'Sprint 44',
    },
  })
  useAuthStore.setState({
    accessToken: 'token',
    refreshToken: 'refresh',
    user: {
      id: 'user-1',
      username: 'alice',
      email: 'alice@test.local',
      is_admin: false,
    },
  })
})

describe('SettingsPage', () => {
  it('renders page heading and sections', () => {
    render(<SettingsPage />)

    expect(screen.getByRole('heading', { name: 'Settings' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Profile' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Change Password' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'System Information' })).toBeInTheDocument()
  })

  it('renders current user profile information', () => {
    render(<SettingsPage />)

    expect(screen.getByText('alice')).toBeInTheDocument()
    expect(screen.getByText('alice@test.local')).toBeInTheDocument()
    expect(screen.getByText('Operator')).toBeInTheDocument()
  })

  it('renders administrator role for admin user', () => {
    useAuthStore.setState({
      user: {
        id: 'admin-1',
        username: 'root',
        email: 'root@test.local',
        is_admin: true,
      },
    })

    render(<SettingsPage />)

    expect(screen.getByText('Administrator')).toBeInTheDocument()
  })

  it('renders fallback profile placeholders when user is missing', () => {
    useAuthStore.setState({ user: null })

    render(<SettingsPage />)

    expect(screen.getAllByText('—')).toHaveLength(2)
    expect(screen.getByText('Operator')).toBeInTheDocument()
  })

  it('renders API version info from API hook', () => {
    render(<SettingsPage />)

    expect(screen.getByText('1.2.3')).toBeInTheDocument()
    expect(screen.getByText('2026-06-23')).toBeInTheDocument()
    expect(screen.getByText('Sprint 44')).toBeInTheDocument()
  })

  it('renders password fields as required', () => {
    render(<SettingsPage />)

    expect(screen.getByLabelText('Current Password')).toBeRequired()
    expect(screen.getByLabelText('New Password')).toBeRequired()
    expect(screen.getByLabelText('Confirm New Password')).toBeRequired()
  })

  it('shows local error when new password is too short', async () => {
    render(<SettingsPage />)

    await userEvent.type(screen.getByLabelText('Current Password'), 'oldpass123')
    await userEvent.type(screen.getByLabelText('New Password'), 'short')
    await userEvent.type(screen.getByLabelText('Confirm New Password'), 'short')
    await userEvent.click(screen.getByRole('button', { name: /update password/i }))

    expect(screen.getByText('New password must be at least 8 characters.')).toBeInTheDocument()
    expect(mockMutate).not.toHaveBeenCalled()
  })

  it('shows local error when new password confirmation differs', async () => {
    render(<SettingsPage />)

    await userEvent.type(screen.getByLabelText('Current Password'), 'oldpass123')
    await userEvent.type(screen.getByLabelText('New Password'), 'newpass123')
    await userEvent.type(screen.getByLabelText('Confirm New Password'), 'different123')
    await userEvent.click(screen.getByRole('button', { name: /update password/i }))

    expect(screen.getByText('New passwords do not match.')).toBeInTheDocument()
    expect(mockMutate).not.toHaveBeenCalled()
  })

  it('submits password change mutation and shows success callback state', async () => {
    mockMutate.mockImplementation((_payload, options) => options.onSuccess())
    render(<SettingsPage />)

    await userEvent.type(screen.getByLabelText('Current Password'), 'oldpass123')
    await userEvent.type(screen.getByLabelText('New Password'), 'newpass123')
    await userEvent.type(screen.getByLabelText('Confirm New Password'), 'newpass123')
    await userEvent.click(screen.getByRole('button', { name: /update password/i }))

    expect(mockMutate).toHaveBeenCalledWith(
      { current_password: 'oldpass123', new_password: 'newpass123' },
      expect.objectContaining({ onSuccess: expect.any(Function) })
    )
    expect(screen.getByText('Password changed successfully.')).toBeInTheDocument()
    expect(screen.getByLabelText('Current Password')).toHaveValue('')
  })

  it('shows API error from change-password hook', () => {
    mockUseChangePassword.mockReturnValue({
      mutate: mockMutate,
      isPending: false,
      error: new Error('Current password is invalid'),
    })

    render(<SettingsPage />)

    expect(screen.getByText('Current password is invalid')).toBeInTheDocument()
  })

  it('disables update button while mutation is pending', () => {
    mockUseChangePassword.mockReturnValue({ mutate: mockMutate, isPending: true, error: null })

    render(<SettingsPage />)

    expect(screen.getByRole('button', { name: /update password/i })).toBeDisabled()
  })
})
