import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import ACLPanel from '../ACLPanel';

const createAcl = vi.fn();
const deleteAcl = vi.fn();

vi.mock('@/lib/sdk', () => ({
  getClient: () => ({ fgaCreateAclTuple: createAcl, fgaDeleteAclTuple: deleteAcl })
}));

vi.mock('@/lib/toast', () => ({ useToast: () => ({ show: () => {} }) }));

describe('ACLPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    createAcl.mockResolvedValue({ meta: { status: 201 }, data: { id: 't1' } });
    deleteAcl.mockResolvedValue({ meta: { status: 204 } });
  });

  it('creates and deletes ACL tuple (happy path)', async () => {
    render(<ACLPanel tenantId="ten1" />);

    fireEvent.change(screen.getByTestId('fga-acl-subject-id'), { target: { value: 'u1' } });
    fireEvent.change(screen.getByTestId('fga-acl-permission-key'), { target: { value: 'users.read' } });
    fireEvent.change(screen.getByTestId('fga-acl-object-type'), { target: { value: 'tenant' } });
    fireEvent.change(screen.getByTestId('fga-acl-object-id'), { target: { value: 'ten1' } });

    fireEvent.click(screen.getByTestId('fga-acl-create'));
    await waitFor(() => expect(createAcl).toHaveBeenCalled());

    fireEvent.click(screen.getByTestId('fga-acl-delete'));
    await waitFor(() => expect(deleteAcl).toHaveBeenCalled());
  });

  it('handles error from create', async () => {
    createAcl.mockResolvedValueOnce({ meta: { status: 400 } });
    render(<ACLPanel tenantId="ten1" />);

    fireEvent.change(screen.getByTestId('fga-acl-subject-id'), { target: { value: 'u1' } });
    fireEvent.change(screen.getByTestId('fga-acl-permission-key'), { target: { value: 'users.read' } });
    fireEvent.change(screen.getByTestId('fga-acl-object-type'), { target: { value: 'tenant' } });

    fireEvent.click(screen.getByTestId('fga-acl-create'));
    await waitFor(() => expect(screen.getByTestId('fga-acl-error')).toBeInTheDocument());
  });
});
