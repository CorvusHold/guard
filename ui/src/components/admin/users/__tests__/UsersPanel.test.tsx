import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import UsersPanel from '../UsersPanel'

vi.mock('@/lib/sdk', () => {
  return {
    getClient: () => ({
      listUsers: vi
        .fn()
        .mockResolvedValue({ meta: { status: 200 }, data: { users: [] } }),
      updateUserNames: vi.fn().mockResolvedValue({ meta: { status: 204 } }),
      blockUser: vi.fn().mockResolvedValue({ meta: { status: 204 } }),
      unblockUser: vi.fn().mockResolvedValue({ meta: { status: 204 } })
    })
  }
})

describe('UsersPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders empty state and refreshes', async () => {
    render(<UsersPanel tenantId="tenant_1" />)
    // empty state will show after initial auto-load completes
    await waitFor(() =>
      expect(screen.getByText(/no users found/i)).toBeInTheDocument()
    )

    const refresh = screen.getByTestId('users-refresh')
    fireEvent.click(refresh)
    await waitFor(() =>
      expect(screen.getByText(/no users found/i)).toBeInTheDocument()
    )
  })
})
