import { describe, it, expect, beforeEach } from 'vitest'
import { useToastStore, toast, toastSuccess, toastError, toastWarning } from './toast'

beforeEach(() => {
  useToastStore.setState({ toasts: [] })
})

describe('useToastStore', () => {
  it('adds a toast with id, title, variant', () => {
    useToastStore.getState().add({ title: 'Hello', variant: 'info' })
    const toasts = useToastStore.getState().toasts
    expect(toasts).toHaveLength(1)
    expect(toasts[0].title).toBe('Hello')
    expect(toasts[0].variant).toBe('info')
    expect(toasts[0].id).toBeTruthy()
  })

  it('adds description when provided', () => {
    useToastStore.getState().add({ title: 'T', description: 'Detail', variant: 'success' })
    expect(useToastStore.getState().toasts[0].description).toBe('Detail')
  })

  it('caps toasts at 5', () => {
    for (let i = 0; i < 8; i++) {
      useToastStore.getState().add({ title: `Toast ${i}`, variant: 'info' })
    }
    expect(useToastStore.getState().toasts).toHaveLength(5)
  })

  it('removes a toast by id', () => {
    useToastStore.getState().add({ title: 'A', variant: 'info' })
    useToastStore.getState().add({ title: 'B', variant: 'info' })
    const id = useToastStore.getState().toasts[0].id
    useToastStore.getState().remove(id)
    expect(useToastStore.getState().toasts).toHaveLength(1)
    expect(useToastStore.getState().toasts[0].title).toBe('B')
  })

  it('remove with unknown id does not crash', () => {
    useToastStore.getState().add({ title: 'A', variant: 'info' })
    useToastStore.getState().remove('nonexistent-id')
    expect(useToastStore.getState().toasts).toHaveLength(1)
  })
})

describe('imperative helpers', () => {
  it('toast() defaults to info variant', () => {
    toast('Test')
    expect(useToastStore.getState().toasts[0].variant).toBe('info')
  })

  it('toast() accepts custom variant', () => {
    toast('Test', { variant: 'warning' })
    expect(useToastStore.getState().toasts[0].variant).toBe('warning')
  })

  it('toastSuccess() uses success variant', () => {
    toastSuccess('Done')
    expect(useToastStore.getState().toasts[0].variant).toBe('success')
    expect(useToastStore.getState().toasts[0].title).toBe('Done')
  })

  it('toastError() uses error variant', () => {
    toastError('Failed', 'Something broke')
    const t = useToastStore.getState().toasts[0]
    expect(t.variant).toBe('error')
    expect(t.description).toBe('Something broke')
  })

  it('toastWarning() uses warning variant', () => {
    toastWarning('Heads up')
    expect(useToastStore.getState().toasts[0].variant).toBe('warning')
  })
})
