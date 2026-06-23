import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { KnowledgeCard } from './KnowledgeCard'
import type { KnowledgeSummary } from '../lib/types'

function makeRecord(overrides: Partial<KnowledgeSummary> = {}): KnowledgeSummary {
  return {
    id: 'rec-001',
    title: 'SQL Injection via login form',
    vuln_class: 'sqli',
    severity: 'critical',
    program: 'Acme Corp',
    tech_stack: ['django', 'postgresql'],
    key_insight: 'Blind time-based injection in username field.',
    bounty_usd: 2500,
    source: 'h1_public',
    source_url: 'https://hackerone.com/reports/123',
    ...overrides,
  }
}

describe('KnowledgeCard', () => {
  it('renders the record title', () => {
    render(<KnowledgeCard record={makeRecord()} onClick={vi.fn()} />)
    expect(screen.getByText('SQL Injection via login form')).toBeInTheDocument()
  })

  it('renders the severity badge', () => {
    render(<KnowledgeCard record={makeRecord()} onClick={vi.fn()} />)
    expect(screen.getByText('critical')).toBeInTheDocument()
  })

  it('renders the vuln_class label', () => {
    render(<KnowledgeCard record={makeRecord()} onClick={vi.fn()} />)
    expect(screen.getByText('SQLi')).toBeInTheDocument()
  })

  it('renders the program name', () => {
    render(<KnowledgeCard record={makeRecord()} onClick={vi.fn()} />)
    expect(screen.getByText('Acme Corp')).toBeInTheDocument()
  })

  it('renders formatted bounty when provided', () => {
    render(<KnowledgeCard record={makeRecord({ bounty_usd: 2500 })} onClick={vi.fn()} />)
    expect(screen.getByText('$2.5k')).toBeInTheDocument()
  })

  it('does not render bounty when null', () => {
    render(<KnowledgeCard record={makeRecord({ bounty_usd: null })} onClick={vi.fn()} />)
    expect(screen.queryByText(/\$/)).not.toBeInTheDocument()
  })

  it('renders key_insight text', () => {
    render(<KnowledgeCard record={makeRecord()} onClick={vi.fn()} />)
    expect(screen.getByText('Blind time-based injection in username field.')).toBeInTheDocument()
  })

  it('does not render insight section when key_insight is empty', () => {
    render(<KnowledgeCard record={makeRecord({ key_insight: '' })} onClick={vi.fn()} />)
    expect(screen.queryByText('Blind')).not.toBeInTheDocument()
  })

  it('renders up to 4 tech stack chips', () => {
    const record = makeRecord({ tech_stack: ['python', 'django', 'postgresql', 'redis'] })
    render(<KnowledgeCard record={record} onClick={vi.fn()} />)
    expect(screen.getByText('python')).toBeInTheDocument()
    expect(screen.getByText('redis')).toBeInTheDocument()
  })

  it('shows +N when tech_stack has more than 4 entries', () => {
    const record = makeRecord({ tech_stack: ['a', 'b', 'c', 'd', 'e', 'f'] })
    render(<KnowledgeCard record={record} onClick={vi.fn()} />)
    expect(screen.getByText('+2')).toBeInTheDocument()
  })

  it('renders no tech chips when tech_stack is empty', () => {
    const { container } = render(
      <KnowledgeCard record={makeRecord({ tech_stack: [] })} onClick={vi.fn()} />
    )
    // no .bg-accent chip elements besides the outer card
    const chips = container.querySelectorAll('.bg-accent.text-accent-foreground')
    expect(chips).toHaveLength(0)
  })

  it('renders ExternalLink when source_url is set', () => {
    render(<KnowledgeCard record={makeRecord()} onClick={vi.fn()} />)
    expect(screen.getByRole('link', { name: 'Open source' })).toBeInTheDocument()
  })

  it('does not render ExternalLink when source_url is null', () => {
    render(<KnowledgeCard record={makeRecord({ source_url: null })} onClick={vi.fn()} />)
    expect(screen.queryByRole('link')).not.toBeInTheDocument()
  })

  it('calls onClick with record id when card is clicked', async () => {
    const onClick = vi.fn()
    render(<KnowledgeCard record={makeRecord()} onClick={onClick} />)
    await userEvent.click(screen.getByRole('button'))
    expect(onClick).toHaveBeenCalledOnce()
    expect(onClick).toHaveBeenCalledWith('rec-001')
  })

  it('clicking ExternalLink does not bubble to card onClick', async () => {
    const onClick = vi.fn()
    render(<KnowledgeCard record={makeRecord()} onClick={onClick} />)
    await userEvent.click(screen.getByRole('link', { name: 'Open source' }))
    expect(onClick).not.toHaveBeenCalled()
  })

  it('renders unknown vuln_class raw value when not in label map', () => {
    const record = makeRecord({ vuln_class: 'custom_class' as never })
    render(<KnowledgeCard record={record} onClick={vi.fn()} />)
    expect(screen.getByText('custom_class')).toBeInTheDocument()
  })
})
