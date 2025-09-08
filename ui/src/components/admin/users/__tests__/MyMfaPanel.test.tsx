import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import MyMfaPanel from '../MyMfaPanel';

const startTotp = vi.fn();
const activateTotp = vi.fn();
const disableTotp = vi.fn();
const generateBackup = vi.fn();
const countBackup = vi.fn();

vi.mock('@/lib/sdk', () => ({
  getClient: () => ({
    mfaStartTotp: startTotp,
    mfaActivateTotp: activateTotp,
    mfaDisableTotp: disableTotp,
    mfaGenerateBackupCodes: generateBackup,
    mfaCountBackupCodes: countBackup,
  }),
}));

vi.mock('@/lib/toast', () => ({ useToast: () => ({ show: () => {} }) }));

describe('MyMfaPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    startTotp.mockResolvedValue({ meta: { status: 200 }, data: { secret: 'S', otpauth_url: 'otpauth://test' } });
    activateTotp.mockResolvedValue({ meta: { status: 200 } });
    disableTotp.mockResolvedValue({ meta: { status: 200 } });
    generateBackup.mockResolvedValue({ meta: { status: 200 }, data: { codes: ['A','B'] } });
    countBackup.mockResolvedValue({ meta: { status: 200 }, data: { count: 2 } });
  });

  it('happy path flows', async () => {
    render(<MyMfaPanel />);

    // Count fetch on mount
    await waitFor(() => expect(countBackup).toHaveBeenCalled());

    // Start TOTP
    fireEvent.click(screen.getByTestId('mfa-start'));
    await waitFor(() => expect(startTotp).toHaveBeenCalled());
    expect(screen.getByTestId('mfa-secret')).toHaveTextContent('S');

    // Activate TOTP
    fireEvent.change(screen.getByTestId('mfa-code'), { target: { value: '123456' } });
    fireEvent.click(screen.getByTestId('mfa-activate'));
    await waitFor(() => expect(activateTotp).toHaveBeenCalled());

    // Generate backup codes
    fireEvent.click(screen.getByTestId('mfa-generate-backup'));
    await waitFor(() => expect(generateBackup).toHaveBeenCalled());

    // Disable TOTP
    fireEvent.click(screen.getByTestId('mfa-disable'));
    await waitFor(() => expect(disableTotp).toHaveBeenCalled());
  });

  it('error path for startTOTP shows banner', async () => {
    startTotp.mockResolvedValueOnce({ meta: { status: 500 } });
    render(<MyMfaPanel />);
    fireEvent.click(screen.getByTestId('mfa-start'));
    await waitFor(() => expect(screen.getByTestId('my-mfa-error')).toBeInTheDocument());
  });
});
