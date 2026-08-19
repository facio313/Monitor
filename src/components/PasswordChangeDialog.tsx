import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent as ReactKeyboardEvent } from 'react';
import { ApiError, changePassword } from '../api';
import { Icon } from './Icon';

const MIN_PASSWORD_LENGTH = 16;
const MAX_PASSWORD_BYTES = 256;

function unicodeLength(value: string): number {
  return [...value].length;
}

function utf8Length(value: string): number {
  return new TextEncoder().encode(value).length;
}

interface PasswordChangeDialogProps {
  open: boolean;
  onClose: () => void;
  onPasswordChanged: () => void;
  onUnauthorized: () => void;
}

export function PasswordChangeDialog({ open, onClose, onPasswordChanged, onUnauthorized }: PasswordChangeDialogProps) {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const dialogRef = useRef<HTMLDivElement>(null);
  const currentPasswordRef = useRef<HTMLInputElement>(null);
  const onCloseRef = useRef(onClose);
  const submittingRef = useRef(submitting);
  onCloseRef.current = onClose;
  submittingRef.current = submitting;

  const newPasswordLength = unicodeLength(newPassword);
  const newPasswordBytes = utf8Length(newPassword);
  const newPasswordTooShort = newPasswordLength > 0 && newPasswordLength < MIN_PASSWORD_LENGTH;
  const newPasswordTooLong = newPasswordBytes > MAX_PASSWORD_BYTES;
  const newPasswordUnchanged = newPassword.length > 0 && newPassword === currentPassword;
  const newPasswordInvalid = newPasswordTooShort || newPasswordTooLong || newPasswordUnchanged;
  const confirmationMismatch = confirmation.length > 0 && confirmation !== newPassword;
  const formValid = Boolean(
    currentPassword
      && newPasswordLength >= MIN_PASSWORD_LENGTH
      && newPasswordBytes <= MAX_PASSWORD_BYTES
      && !newPasswordUnchanged
      && confirmation === newPassword
  );
  const canSubmit = formValid && !submitting;

  useEffect(() => {
    if (!open) return;

    const previouslyFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const focusFrame = window.requestAnimationFrame(() => currentPasswordRef.current?.focus());

    function handleDocumentKeyDown(event: globalThis.KeyboardEvent) {
      if (event.key === 'Escape' && !submittingRef.current) {
        event.preventDefault();
        onCloseRef.current();
      }
    }

    document.addEventListener('keydown', handleDocumentKeyDown);
    return () => {
      window.cancelAnimationFrame(focusFrame);
      document.removeEventListener('keydown', handleDocumentKeyDown);
      document.body.style.overflow = previousOverflow;
      previouslyFocused?.focus();
    };
  }, [open]);

  useEffect(() => {
    if (open) return;
    setCurrentPassword('');
    setNewPassword('');
    setConfirmation('');
    setError(null);
    setSubmitting(false);
  }, [open]);

  function handleDialogKeyDown(event: ReactKeyboardEvent<HTMLDivElement>) {
    if (event.key !== 'Tab') return;
    const focusable = Array.from(
      dialogRef.current?.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled)') ?? [],
    );
    if (!focusable.length) return;

    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canSubmit) return;

    setSubmitting(true);
    setError(null);
    try {
      await changePassword(currentPassword, newPassword);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmation('');
      onPasswordChanged();
    } catch (requestError) {
      if (requestError instanceof ApiError && requestError.status === 401) {
        setCurrentPassword('');
        setNewPassword('');
        setConfirmation('');
        onUnauthorized();
        return;
      }
      setError(requestError instanceof Error ? requestError.message : 'Password change failed. Please try again.');
      currentPasswordRef.current?.focus();
    } finally {
      setSubmitting(false);
    }
  }

  if (!open) return null;

  return (
    <div
      className="dialog-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && !submitting) onClose();
      }}
    >
      <div
        ref={dialogRef}
        className="password-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="password-dialog-title"
        aria-describedby="password-dialog-description"
        onKeyDown={handleDialogKeyDown}
      >
        <header className="password-dialog-header">
          <span className="password-dialog-icon"><Icon name="lock" size={20} /></span>
          <div>
            <h2 id="password-dialog-title">Change password</h2>
            <p id="password-dialog-description">You will be signed out after the password is changed.</p>
          </div>
          <button
            className="dialog-close-button"
            type="button"
            aria-label="Close password change dialog"
            onClick={onClose}
            disabled={submitting}
          >
            <span aria-hidden="true">×</span>
          </button>
        </header>

        <form className="password-change-form" onSubmit={handleSubmit} aria-busy={submitting}>
          {error && (
            <div className="notice notice-error password-change-error" role="alert">
              <Icon name="alert" size={17} />
              <span>{error}</span>
            </div>
          )}

          <div className="form-field">
            <label htmlFor="current-monitor-password">Current password</label>
            <div className="password-field">
              <Icon name="lock" size={17} />
              <input
                ref={currentPasswordRef}
                id="current-monitor-password"
                name="currentPassword"
                type="password"
                autoComplete="current-password"
                value={currentPassword}
                onChange={(event) => setCurrentPassword(event.target.value)}
                placeholder="Enter current password"
                required
                disabled={submitting}
              />
            </div>
          </div>

          <div className="form-field">
            <label htmlFor="new-monitor-password">New password</label>
            <div className={`password-field${newPasswordInvalid ? ' field-invalid' : ''}`}>
              <Icon name="shield" size={17} />
              <input
                id="new-monitor-password"
                name="newPassword"
                type="password"
                autoComplete="new-password"
                value={newPassword}
                onChange={(event) => setNewPassword(event.target.value)}
                placeholder="Enter new password"
                required
                disabled={submitting}
                aria-describedby="new-password-requirement"
                aria-invalid={newPasswordInvalid}
              />
            </div>
            <p
              id="new-password-requirement"
              className={`field-hint${newPasswordInvalid ? ' field-hint-error' : ''}`}
            >
              {newPasswordTooLong
                ? `Password must be at most ${MAX_PASSWORD_BYTES} UTF-8 bytes (currently ${newPasswordBytes}).`
                : newPasswordTooShort
                  ? `Use at least ${MIN_PASSWORD_LENGTH} characters (currently ${newPasswordLength}).`
                  : newPasswordUnchanged
                    ? 'New password must be different from the current password.'
                  : `Use at least ${MIN_PASSWORD_LENGTH} characters and at most ${MAX_PASSWORD_BYTES} UTF-8 bytes.`}
            </p>
          </div>

          <div className="form-field">
            <label htmlFor="confirm-monitor-password">Confirm new password</label>
            <div className={`password-field${confirmationMismatch ? ' field-invalid' : ''}`}>
              <Icon name="check" size={17} />
              <input
                id="confirm-monitor-password"
                name="newPasswordConfirmation"
                type="password"
                autoComplete="new-password"
                value={confirmation}
                onChange={(event) => setConfirmation(event.target.value)}
                placeholder="Enter new password again"
                required
                disabled={submitting}
                aria-describedby={confirmationMismatch ? 'password-confirmation-error' : undefined}
                aria-invalid={confirmationMismatch}
              />
            </div>
            {confirmationMismatch && (
              <p id="password-confirmation-error" className="field-hint field-hint-error">
                Passwords do not match.
              </p>
            )}
          </div>

          <div className="password-dialog-actions">
            <button className="secondary-button" type="button" onClick={onClose} disabled={submitting}>
              Cancel
            </button>
            <button
              className="primary-button"
              type="submit"
              disabled={!formValid}
              aria-disabled={!canSubmit}
            >
              {submitting ? <span className="spinner" aria-hidden="true" /> : <Icon name="shield" size={17} />}
              {submitting ? 'Changing…' : 'Change password'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
