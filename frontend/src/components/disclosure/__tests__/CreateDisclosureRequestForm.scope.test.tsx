import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { CreateDisclosureRequestForm } from '../CreateDisclosureRequestForm';

// A scope button renders the selected styling (bg-primary-50) when picked.
const isSelected = (btn: HTMLElement) => btn.className.includes('bg-primary-50');

const renderForm = () =>
  render(<CreateDisclosureRequestForm onSubmit={vi.fn().mockResolvedValue(undefined)} />);

describe('CreateDisclosureRequestForm — scope mutual exclusivity (RD-1072)', () => {
  afterEach(cleanup);

  it('selecting Full Disclosure clears the narrow scopes', async () => {
    const user = userEvent.setup();
    renderForm();

    const activity = screen.getByRole('button', { name: /Activity Logs/ });
    const txHistory = screen.getByRole('button', { name: /Transaction History/ });
    const full = screen.getByRole('button', { name: /Full Disclosure/ });

    await user.click(activity);
    await user.click(txHistory);
    expect(isSelected(activity)).toBe(true);
    expect(isSelected(txHistory)).toBe(true);

    await user.click(full);
    expect(isSelected(full)).toBe(true);
    expect(isSelected(activity)).toBe(false);
    expect(isSelected(txHistory)).toBe(false);
  });

  it('selecting a narrow scope clears Full Disclosure', async () => {
    const user = userEvent.setup();
    renderForm();

    const activity = screen.getByRole('button', { name: /Activity Logs/ });
    const full = screen.getByRole('button', { name: /Full Disclosure/ });

    await user.click(full);
    expect(isSelected(full)).toBe(true);

    await user.click(activity);
    expect(isSelected(activity)).toBe(true);
    expect(isSelected(full)).toBe(false);
  });

  it('allows the two narrow scopes together', async () => {
    const user = userEvent.setup();
    renderForm();

    const activity = screen.getByRole('button', { name: /Activity Logs/ });
    const txHistory = screen.getByRole('button', { name: /Transaction History/ });

    await user.click(activity);
    await user.click(txHistory);

    expect(isSelected(activity)).toBe(true);
    expect(isSelected(txHistory)).toBe(true);
  });
});
