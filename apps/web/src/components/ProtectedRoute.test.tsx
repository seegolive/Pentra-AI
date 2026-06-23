import { describe, it, expect, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { useAuthStore } from '../lib/authStore'
import ProtectedRoute from './ProtectedRoute'

// Reset auth store before every test
beforeEach(() => {
  useAuthStore.setState({
    accessToken: null,
    refreshToken: null,
    user: null,
  })
})

function renderWithRouter(initialPath = '/dashboard') {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <Routes>
        <Route path="/login" element={<div>Login Page</div>} />
        <Route element={<ProtectedRoute />}>
          <Route path="/dashboard" element={<div>Dashboard</div>} />
          <Route path="/settings" element={<div>Settings</div>} />
        </Route>
      </Routes>
    </MemoryRouter>
  )
}

describe('ProtectedRoute', () => {
  it('redirects unauthenticated user to /login', () => {
    renderWithRouter('/dashboard')
    expect(screen.getByText('Login Page')).toBeInTheDocument()
    expect(screen.queryByText('Dashboard')).not.toBeInTheDocument()
  })

  it('renders the protected outlet when authenticated', () => {
    useAuthStore.setState({ accessToken: 'tok-abc', refreshToken: 'ref-xyz' })
    renderWithRouter('/dashboard')
    expect(screen.getByText('Dashboard')).toBeInTheDocument()
    expect(screen.queryByText('Login Page')).not.toBeInTheDocument()
  })

  it('renders nested protected routes when authenticated', () => {
    useAuthStore.setState({ accessToken: 'tok-abc', refreshToken: 'ref-xyz' })
    renderWithRouter('/settings')
    expect(screen.getByText('Settings')).toBeInTheDocument()
  })

  it('redirects from any protected path when not authenticated', () => {
    renderWithRouter('/settings')
    expect(screen.getByText('Login Page')).toBeInTheDocument()
  })

  it('null token is treated as unauthenticated', () => {
    useAuthStore.setState({ accessToken: null })
    renderWithRouter('/dashboard')
    expect(screen.getByText('Login Page')).toBeInTheDocument()
  })
})
