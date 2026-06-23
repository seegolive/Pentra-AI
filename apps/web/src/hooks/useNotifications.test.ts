import { describe, it, expect, beforeEach } from 'vitest'
import { useNotificationStore } from './useNotifications'

// Reset Zustand store state before every test to avoid leakage
beforeEach(() => {
  useNotificationStore.setState({ items: [], unreadCount: 0 })
})

const makeNotif = (overrides = {}) => ({
  type: 'INFO' as const,
  title: 'Test notification',
  ...overrides,
})

describe('useNotificationStore', () => {
  // ── addNotification ──────────────────────────────────────────────────────

  it('adds a notification item', () => {
    useNotificationStore.getState().addNotification(makeNotif())
    expect(useNotificationStore.getState().items).toHaveLength(1)
  })

  it('sets id, read=false, and timestamp on added item', () => {
    useNotificationStore.getState().addNotification(makeNotif({ title: 'Hello' }))
    const item = useNotificationStore.getState().items[0]
    expect(item.id).toBeTruthy()
    expect(item.read).toBe(false)
    expect(item.timestamp).toBeTruthy()
    expect(new Date(item.timestamp).toISOString()).toBe(item.timestamp)
  })

  it('increments unreadCount on each add', () => {
    useNotificationStore.getState().addNotification(makeNotif())
    useNotificationStore.getState().addNotification(makeNotif())
    expect(useNotificationStore.getState().unreadCount).toBe(2)
  })

  it('prepends new item (newest first)', () => {
    useNotificationStore.getState().addNotification(makeNotif({ title: 'First' }))
    useNotificationStore.getState().addNotification(makeNotif({ title: 'Second' }))
    const items = useNotificationStore.getState().items
    expect(items[0].title).toBe('Second')
    expect(items[1].title).toBe('First')
  })

  it('caps items list at 100', () => {
    for (let i = 0; i < 110; i++) {
      useNotificationStore.getState().addNotification(makeNotif({ title: `Notif ${i}` }))
    }
    expect(useNotificationStore.getState().items).toHaveLength(100)
  })

  it('preserves notification type on added item', () => {
    useNotificationStore.getState().addNotification(makeNotif({ type: 'AGENT_ERROR' }))
    expect(useNotificationStore.getState().items[0].type).toBe('AGENT_ERROR')
  })

  it('preserves description and engagementId', () => {
    useNotificationStore.getState().addNotification(
      makeNotif({ description: 'desc', engagementId: 'eng-1' })
    )
    const item = useNotificationStore.getState().items[0]
    expect(item.description).toBe('desc')
    expect(item.engagementId).toBe('eng-1')
  })

  // ── markAllRead ──────────────────────────────────────────────────────────

  it('markAllRead sets all items to read', () => {
    useNotificationStore.getState().addNotification(makeNotif())
    useNotificationStore.getState().addNotification(makeNotif())
    useNotificationStore.getState().markAllRead()
    const items = useNotificationStore.getState().items
    expect(items.every((i) => i.read)).toBe(true)
  })

  it('markAllRead resets unreadCount to 0', () => {
    useNotificationStore.getState().addNotification(makeNotif())
    useNotificationStore.getState().addNotification(makeNotif())
    useNotificationStore.getState().markAllRead()
    expect(useNotificationStore.getState().unreadCount).toBe(0)
  })

  it('markAllRead on empty list does not throw', () => {
    expect(() => useNotificationStore.getState().markAllRead()).not.toThrow()
    expect(useNotificationStore.getState().unreadCount).toBe(0)
  })

  // ── clearAll ─────────────────────────────────────────────────────────────

  it('clearAll empties items', () => {
    useNotificationStore.getState().addNotification(makeNotif())
    useNotificationStore.getState().clearAll()
    expect(useNotificationStore.getState().items).toHaveLength(0)
  })

  it('clearAll resets unreadCount to 0', () => {
    useNotificationStore.getState().addNotification(makeNotif())
    useNotificationStore.getState().clearAll()
    expect(useNotificationStore.getState().unreadCount).toBe(0)
  })

  it('state is independent between adds and clears', () => {
    useNotificationStore.getState().addNotification(makeNotif({ title: 'One' }))
    useNotificationStore.getState().clearAll()
    useNotificationStore.getState().addNotification(makeNotif({ title: 'Two' }))
    const state = useNotificationStore.getState()
    expect(state.items).toHaveLength(1)
    expect(state.items[0].title).toBe('Two')
    expect(state.unreadCount).toBe(1)
  })
})
