import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { act, renderHook, waitFor } from '@testing-library/react'
import { useEngagementFeed } from './useEngagementFeed'
import { useAuthStore } from '../lib/authStore'

const { mockAddNotification } = vi.hoisted(() => ({
  mockAddNotification: vi.fn(),
}))

vi.mock('./useNotifications', () => ({
  addNotification: mockAddNotification,
}))

class MockWebSocket {
  static instances: MockWebSocket[] = []

  url: string
  onmessage: ((e: MessageEvent) => void) | null = null
  onopen: (() => void) | null = null
  onclose: (() => void) | null = null
  onerror: (() => void) | null = null
  close = vi.fn()
  send = vi.fn()

  constructor(url: string) {
    this.url = url
    MockWebSocket.instances.push(this)
  }

  emit(data: object) {
    this.onmessage?.({ data: JSON.stringify(data) } as MessageEvent)
  }
}

beforeEach(() => {
  MockWebSocket.instances = []
  mockAddNotification.mockReset()
  vi.stubGlobal('WebSocket', MockWebSocket)
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
    ok: true,
    json: () => Promise.resolve([]),
  }))
  useAuthStore.setState({ accessToken: 'access-token', refreshToken: null, user: null })
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('useEngagementFeed', () => {
  it('connects to WebSocket on mount', () => {
    renderHook(() => useEngagementFeed('eng-1'))
    expect(MockWebSocket.instances).toHaveLength(1)
    expect(MockWebSocket.instances[0].url).toContain('/api/v1/ws/engagements/eng-1/feed')
  })

  it('sets connected true on open and false on close', async () => {
    const { result } = renderHook(() => useEngagementFeed('eng-1'))

    act(() => MockWebSocket.instances[0].onopen?.())
    expect(result.current.connected).toBe(true)

    act(() => MockWebSocket.instances[0].onclose?.())
    expect(result.current.connected).toBe(false)
  })

  it('disconnects on unmount', () => {
    const { unmount } = renderHook(() => useEngagementFeed('eng-1'))
    const ws = MockWebSocket.instances[0]
    unmount()
    expect(ws.close).toHaveBeenCalledOnce()
  })

  it('parses incoming JSON events into newest-first state', async () => {
    const { result } = renderHook(() => useEngagementFeed('eng-1'))

    act(() => {
      MockWebSocket.instances[0].emit({ type: 'NODE_START', message: 'Recon started' })
      MockWebSocket.instances[0].emit({ type: 'NODE_COMPLETE', message: 'Recon done' })
    })

    await waitFor(() => expect(result.current.events).toHaveLength(2))
    expect(result.current.events[0].message).toBe('Recon done')
    expect(result.current.events[1].message).toBe('Recon started')
  })

  it('ignores ping events for message state', async () => {
    const { result } = renderHook(() => useEngagementFeed('eng-1'))

    act(() => MockWebSocket.instances[0].emit({ type: 'ping' }))

    await waitFor(() => expect(result.current.events).toHaveLength(0))
  })

  it('handles AGENT_ERROR-style events as feed messages', async () => {
    const { result } = renderHook(() => useEngagementFeed('eng-1'))

    act(() => MockWebSocket.instances[0].emit({ type: 'AGENT_ERROR', message: 'Agent failed' }))

    await waitFor(() => expect(result.current.events[0].type).toBe('AGENT_ERROR'))
    expect(result.current.events[0].message).toBe('Agent failed')
  })

  it('handles lower-case error events by adding an agent-error notification', async () => {
    renderHook(() => useEngagementFeed('eng-1'))

    act(() => MockWebSocket.instances[0].emit({ type: 'error', message: 'Agent failed' }))

    await waitFor(() =>
      expect(mockAddNotification).toHaveBeenCalledWith({
        type: 'AGENT_ERROR',
        title: 'Agent Error',
        description: 'Agent failed',
        engagementId: 'eng-1',
      })
    )
  })

  it('sets pendingApproval on AWAITING_APPROVAL events', async () => {
    const { result } = renderHook(() => useEngagementFeed('eng-1'))

    act(() =>
      MockWebSocket.instances[0].emit({
        type: 'AWAITING_APPROVAL',
        data: { phase: 'recon', proposed_actions: ['crawl'] },
      })
    )

    await waitFor(() => expect(result.current.pendingApproval).toMatchObject({ phase: 'recon' }))
    expect(mockAddNotification).toHaveBeenCalledWith({
      type: 'AWAITING_APPROVAL',
      title: 'Approval Required',
      description: 'recon',
      engagementId: 'eng-1',
    })
  })

  it('restores completed status from fetched history', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve([{ type: 'ENGAGEMENT_COMPLETED', message: 'Done' }]),
    }))

    const { result } = renderHook(() => useEngagementFeed('eng-1'))

    await waitFor(() => expect(result.current.agentStatus).toBe('completed'))
    expect(result.current.events[0].type).toBe('ENGAGEMENT_COMPLETED')
  })
})
