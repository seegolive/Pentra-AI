import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { EmptyState } from './EmptyState'

describe('EmptyState', () => {
  it('renders the title', () => {
    render(<EmptyState title="Nothing here yet" />)
    expect(screen.getByText('Nothing here yet')).toBeInTheDocument()
  })

  it('renders description when provided', () => {
    render(<EmptyState title="Empty" description="Start by creating an engagement." />)
    expect(screen.getByText('Start by creating an engagement.')).toBeInTheDocument()
  })

  it('does not render description when omitted', () => {
    render(<EmptyState title="Empty" />)
    expect(screen.queryByText(/Start by/)).not.toBeInTheDocument()
  })

  it('renders icon when provided', () => {
    render(<EmptyState title="Empty" icon={<span data-testid="custom-icon">★</span>} />)
    expect(screen.getByTestId('custom-icon')).toBeInTheDocument()
  })

  it('does not render icon slot when icon is omitted', () => {
    const { container } = render(<EmptyState title="Empty" />)
    expect(container.querySelector('.opacity-20')).not.toBeInTheDocument()
  })

  it('renders action button with correct label', () => {
    render(<EmptyState title="Empty" action={{ label: 'Add item', onClick: vi.fn() }} />)
    expect(screen.getByRole('button', { name: 'Add item' })).toBeInTheDocument()
  })

  it('calls action.onClick when button is clicked', async () => {
    const onClick = vi.fn()
    render(<EmptyState title="Empty" action={{ label: 'Click me', onClick }} />)
    await userEvent.click(screen.getByRole('button'))
    expect(onClick).toHaveBeenCalledOnce()
  })

  it('does not render button when action is omitted', () => {
    render(<EmptyState title="Empty" />)
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })

  it('applies custom className to wrapper', () => {
    const { container } = render(<EmptyState title="Empty" className="custom-class" />)
    expect(container.firstChild).toHaveClass('custom-class')
  })
})
