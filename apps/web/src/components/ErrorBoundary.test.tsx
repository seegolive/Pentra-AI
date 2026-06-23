import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ErrorBoundary } from './ErrorBoundary'

// Component that throws on demand
function Bomb({ shouldThrow }: { shouldThrow: boolean }) {
  if (shouldThrow) throw new Error('boom')
  return <div>Safe child</div>
}

// Suppress console.error from React's error boundary machinery
let consoleErrorSpy: ReturnType<typeof vi.spyOn>

beforeEach(() => {
  consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
})

afterEach(() => {
  consoleErrorSpy.mockRestore()
})

describe('ErrorBoundary', () => {
  it('renders children when no error occurs', () => {
    render(
      <ErrorBoundary>
        <Bomb shouldThrow={false} />
      </ErrorBoundary>
    )
    expect(screen.getByText('Safe child')).toBeInTheDocument()
  })

  it('renders default error UI when child throws', () => {
    render(
      <ErrorBoundary>
        <Bomb shouldThrow={true} />
      </ErrorBoundary>
    )
    expect(screen.getByText('Something went wrong')).toBeInTheDocument()
  })

  it('shows error message in default UI', () => {
    render(
      <ErrorBoundary>
        <Bomb shouldThrow={true} />
      </ErrorBoundary>
    )
    expect(screen.getByText('boom')).toBeInTheDocument()
  })

  it('renders custom fallback when fallback prop is provided', () => {
    render(
      <ErrorBoundary fallback={<div>Custom fallback</div>}>
        <Bomb shouldThrow={true} />
      </ErrorBoundary>
    )
    expect(screen.getByText('Custom fallback')).toBeInTheDocument()
    expect(screen.queryByText('Something went wrong')).not.toBeInTheDocument()
  })

  it('shows "Try again" button in default error UI', () => {
    render(
      <ErrorBoundary>
        <Bomb shouldThrow={true} />
      </ErrorBoundary>
    )
    expect(screen.getByRole('button', { name: /try again/i })).toBeInTheDocument()
  })

  it('resets to children after clicking "Try again"', async () => {
    // To test reset, we need a component that can stop throwing
    let shouldThrow = true

    function FlipBomb() {
      if (shouldThrow) throw new Error('initial error')
      return <div>Recovered</div>
    }

    const { rerender } = render(
      <ErrorBoundary>
        <FlipBomb />
      </ErrorBoundary>
    )

    expect(screen.getByText('Something went wrong')).toBeInTheDocument()

    // Stop throwing before clicking reset
    shouldThrow = false
    await userEvent.click(screen.getByRole('button', { name: /try again/i }))

    // Trigger re-render after state reset
    rerender(
      <ErrorBoundary>
        <FlipBomb />
      </ErrorBoundary>
    )

    expect(screen.getByText('Recovered')).toBeInTheDocument()
  })
})
