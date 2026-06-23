import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useNotificationStore } from '../hooks/useNotifications'
import { NotificationBell } from './NotificationBell'

// Stub out NotificationPanel — too heavy to render in isolation
vi.mock('./NotificationPanel', () => ({
  NotificationPanel: ({ open }: { open: boolean }) =>
    open ? <div data-testid="notification-panel">Panel</div> : null,
}))

beforeEach(() => {
  useNotificationStore.setState({ items: [], unreadCount: 0 })
})

describe('NotificationBell', () => {
  it('renders the bell button', () => {
    render(<NotificationBell />)
    expect(screen.getByRole('button', { name: 'Notifications' })).toBeInTheDocument()
  })

  it('does not show badge when unreadCount is 0', () => {
    render(<NotificationBell />)
    // badge is only rendered when unreadCount > 0
    expect(screen.queryByText('0')).not.toBeInTheDocument()
  })

  it('shows unread count badge when > 0', () => {
    useNotificationStore.setState({ unreadCount: 3 })
    render(<NotificationBell />)
    expect(screen.getByText('3')).toBeInTheDocument()
  })

  it('shows "99+" when unreadCount > 99', () => {
    useNotificationStore.setState({ unreadCount: 150 })
    render(<NotificationBell />)
    expect(screen.getByText('99+')).toBeInTheDocument()
  })

  it('shows "99" for exactly 99 unread (not capped)', () => {
    useNotificationStore.setState({ unreadCount: 99 })
    render(<NotificationBell />)
    expect(screen.getByText('99')).toBeInTheDocument()
  })

  it('opens notification panel when bell is clicked', async () => {
    render(<NotificationBell />)
    expect(screen.queryByTestId('notification-panel')).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Notifications' }))
    expect(screen.getByTestId('notification-panel')).toBeInTheDocument()
  })

  it('closes panel when bell is clicked again (toggle)', async () => {
    render(<NotificationBell />)
    const btn = screen.getByRole('button', { name: 'Notifications' })
    await userEvent.click(btn)
    expect(screen.getByTestId('notification-panel')).toBeInTheDocument()
    await userEvent.click(btn)
    expect(screen.queryByTestId('notification-panel')).not.toBeInTheDocument()
  })

  it('closes panel on outside click', async () => {
    render(
      <div>
        <NotificationBell />
        <div data-testid="outside">Outside</div>
      </div>
    )
    await userEvent.click(screen.getByRole('button', { name: 'Notifications' }))
    expect(screen.getByTestId('notification-panel')).toBeInTheDocument()

    await userEvent.click(screen.getByTestId('outside'))
    expect(screen.queryByTestId('notification-panel')).not.toBeInTheDocument()
  })
})
