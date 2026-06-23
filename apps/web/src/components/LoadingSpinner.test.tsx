import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { LoadingSpinner } from './LoadingSpinner'

describe('LoadingSpinner', () => {
  it('renders without crashing', () => {
    const { container } = render(<LoadingSpinner />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('renders label text when provided', () => {
    render(<LoadingSpinner label="Loading data…" />)
    expect(screen.getByText('Loading data…')).toBeInTheDocument()
  })

  it('does not render label when omitted', () => {
    render(<LoadingSpinner />)
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
    expect(document.querySelector('span')).not.toBeInTheDocument()
  })

  it('applies sm size class', () => {
    const { container } = render(<LoadingSpinner size="sm" />)
    const svg = container.querySelector('svg')
    const cls = svg?.getAttribute('class') ?? ''
    expect(cls).toContain('h-3')
    expect(cls).toContain('w-3')
  })

  it('applies md size class by default', () => {
    const { container } = render(<LoadingSpinner />)
    const svg = container.querySelector('svg')
    const cls = svg?.getAttribute('class') ?? ''
    expect(cls).toContain('h-5')
    expect(cls).toContain('w-5')
  })

  it('applies lg size class', () => {
    const { container } = render(<LoadingSpinner size="lg" />)
    const svg = container.querySelector('svg')
    const cls = svg?.getAttribute('class') ?? ''
    expect(cls).toContain('h-8')
    expect(cls).toContain('w-8')
  })

  it('applies animate-spin class to the icon', () => {
    const { container } = render(<LoadingSpinner />)
    const svg = container.querySelector('svg')
    const cls = svg?.getAttribute('class') ?? ''
    expect(cls).toContain('animate-spin')
  })

  it('applies custom className to wrapper', () => {
    const { container } = render(<LoadingSpinner className="my-custom" />)
    expect(container.firstChild).toHaveClass('my-custom')
  })
})
