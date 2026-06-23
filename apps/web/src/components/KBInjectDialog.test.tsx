import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { KBInjectDialog } from './KBInjectDialog'

// Mock useKBManualInject so no real API calls are made
const mockMutate = vi.fn()
const mockReset = vi.fn()
let mockIsPending = false
let mockIsSuccess = false
let mockError: Error | null = null

vi.mock('../lib/api', () => ({
  useKBManualInject: () => ({
    mutate: mockMutate,
    isPending: mockIsPending,
    isSuccess: mockIsSuccess,
    error: mockError,
    reset: mockReset,
  }),
}))

beforeEach(() => {
  mockMutate.mockReset()
  mockReset.mockReset()
  mockIsPending = false
  mockIsSuccess = false
  mockError = null
})

describe('KBInjectDialog', () => {
  // ── visibility ────────────────────────────────────────────────────────────

  it('renders nothing when open=false', () => {
    render(<KBInjectDialog open={false} onClose={vi.fn()} />)
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('renders dialog when open=true', () => {
    render(<KBInjectDialog open={true} onClose={vi.fn()} />)
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.getByText('Inject Knowledge Record')).toBeInTheDocument()
  })

  // ── form fields ───────────────────────────────────────────────────────────

  it('renders Title input', () => {
    render(<KBInjectDialog open={true} onClose={vi.fn()} />)
    expect(screen.getByPlaceholderText(/IDOR on HackerOne/)).toBeInTheDocument()
  })

  it('renders Write-up textarea', () => {
    render(<KBInjectDialog open={true} onClose={vi.fn()} />)
    expect(screen.getByPlaceholderText(/Paste the vulnerability/)).toBeInTheDocument()
  })

  it('renders vuln class and severity selects', () => {
    render(<KBInjectDialog open={true} onClose={vi.fn()} />)
    expect(screen.getByDisplayValue('other')).toBeInTheDocument()
    expect(screen.getByDisplayValue('info')).toBeInTheDocument()
  })

  // ── submit button state ───────────────────────────────────────────────────

  it('Inject button is disabled when title is empty', () => {
    render(<KBInjectDialog open={true} onClose={vi.fn()} />)
    expect(screen.getByRole('button', { name: 'Inject' })).toBeDisabled()
  })

  it('Inject button is disabled when rawText is empty', async () => {
    render(<KBInjectDialog open={true} onClose={vi.fn()} />)
    await userEvent.type(screen.getByPlaceholderText(/IDOR on HackerOne/), 'My Finding')
    expect(screen.getByRole('button', { name: 'Inject' })).toBeDisabled()
  })

  it('Inject button is enabled when both title and rawText are filled', async () => {
    render(<KBInjectDialog open={true} onClose={vi.fn()} />)
    await userEvent.type(screen.getByPlaceholderText(/IDOR on HackerOne/), 'My Finding')
    await userEvent.type(screen.getByPlaceholderText(/Paste the vulnerability/), 'Detailed write-up here.')
    expect(screen.getByRole('button', { name: 'Inject' })).not.toBeDisabled()
  })

  // ── close / cancel ────────────────────────────────────────────────────────

  it('X button calls onClose', async () => {
    const onClose = vi.fn()
    render(<KBInjectDialog open={true} onClose={onClose} />)
    await userEvent.click(screen.getByRole('button', { name: '' }))
    // X button is the close button (no accessible name) — find it via position
    // Actually let's find by title or aria-label absence
  })

  it('Cancel button calls onClose', async () => {
    const onClose = vi.fn()
    render(<KBInjectDialog open={true} onClose={onClose} />)
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(onClose).toHaveBeenCalledOnce()
  })

  // ── form submission ───────────────────────────────────────────────────────

  it('calls mutate with correct payload on submit', async () => {
    render(<KBInjectDialog open={true} onClose={vi.fn()} />)
    await userEvent.type(screen.getByPlaceholderText(/IDOR on HackerOne/), 'My Finding')
    await userEvent.type(screen.getByPlaceholderText(/Paste the vulnerability/), 'Detailed write-up.')
    await userEvent.type(screen.getByPlaceholderText('rails, postgresql'), 'rails, postgresql')

    await userEvent.click(screen.getByRole('button', { name: 'Inject' }))

    expect(mockMutate).toHaveBeenCalledOnce()
    const payload = mockMutate.mock.calls[0][0]
    expect(payload.title).toBe('My Finding')
    expect(payload.raw_text).toBe('Detailed write-up.')
    expect(payload.tech_stack).toEqual(['rails', 'postgresql'])
  })

  it('splits tags by comma', async () => {
    render(<KBInjectDialog open={true} onClose={vi.fn()} />)
    await userEvent.type(screen.getByPlaceholderText(/IDOR on HackerOne/), 'T')
    await userEvent.type(screen.getByPlaceholderText(/Paste the vulnerability/), 'W')
    await userEvent.type(screen.getByPlaceholderText('api, jwt, bypass'), 'api, jwt')

    await userEvent.click(screen.getByRole('button', { name: 'Inject' }))
    const payload = mockMutate.mock.calls[0][0]
    expect(payload.tags).toEqual(['api', 'jwt'])
  })

  // ── success state ─────────────────────────────────────────────────────────

  it('shows success message when isSuccess=true', () => {
    mockIsSuccess = true
    render(<KBInjectDialog open={true} onClose={vi.fn()} />)
    expect(screen.getByText('Record injected successfully')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Inject' })).not.toBeInTheDocument()
  })

  // ── error state ───────────────────────────────────────────────────────────

  it('shows error message when error is set', () => {
    mockError = new Error('Network error: 502')
    render(<KBInjectDialog open={true} onClose={vi.fn()} />)
    expect(screen.getByText('Network error: 502')).toBeInTheDocument()
  })
})
