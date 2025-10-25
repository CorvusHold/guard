import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import GroupsPanel from '../GroupsPanel'

const listGroups = vi
  .fn()
  .mockResolvedValue({ meta: { status: 200 }, data: { groups: [] } })
const createGroup = vi
  .fn()
  .mockResolvedValue({ meta: { status: 201 }, data: { id: 'g1' } })

vi.mock('@/lib/sdk', () => ({
  getClient: () => ({ fgaListGroups: listGroups, fgaCreateGroup: createGroup })
}))

vi.mock('@/lib/toast', () => ({ useToast: () => ({ show: () => {} }) }))

describe('GroupsPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders and creates a group', async () => {
    render(<GroupsPanel tenantId="t1" />)
    await waitFor(() => expect(listGroups).toHaveBeenCalled())

    fireEvent.change(screen.getByTestId('fga-group-name'), {
      target: { value: 'team' }
    })
    fireEvent.click(screen.getByTestId('fga-group-create'))

    await waitFor(() => expect(createGroup).toHaveBeenCalled())
  })
})
