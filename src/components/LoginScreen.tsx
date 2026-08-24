import { useEffect, useRef, useState, type FormEvent } from 'react';
import { login } from '../api';
import { BonifacioReturnLink } from './BonifacioReturnLink';
import { Icon } from './Icon';

interface LoginScreenProps {
  onAuthenticated: () => void;
  sessionMessage?: string | null;
}
export function LoginScreen({ onAuthenticated, sessionMessage }: LoginScreenProps) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => inputRef.current?.focus(), []);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (!password || submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      await login(password);
      setPassword('');
      onAuthenticated();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Sign in failed. Please try again.');
      inputRef.current?.focus();
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="login-shell">
      <BonifacioReturnLink />
      <div className="login-ambient login-ambient-one" />
      <div className="login-ambient login-ambient-two" />
      <section className="login-card" aria-labelledby="login-title">
        <div className="brand-mark brand-mark-large"><Icon name="activity" size={26} /></div>
        <div className="login-heading">
          <span className="eyebrow">Private telemetry</span>
          <h1 id="login-title">Host Monitor</h1>
          <p>Sign in to view live system health and recent activity.</p>
        </div>

        {sessionMessage && <div className="notice notice-info" role="status"><Icon name="info" size={17} />{sessionMessage}</div>}
        {error && <div className="notice notice-error" role="alert"><Icon name="alert" size={17} />{error}</div>}

        <form onSubmit={handleSubmit} className="login-form">
          <label htmlFor="monitor-password">Dashboard password</label>
          <div className="password-field">
            <Icon name="lock" size={18} />
            <input
              ref={inputRef}
              id="monitor-password"
              name="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="Enter password"
              required
              disabled={submitting}
            />
          </div>
          <button className="primary-button" type="submit" disabled={submitting || !password}>
            {submitting ? <span className="spinner" aria-hidden="true" /> : <Icon name="shield" size={18} />}
            {submitting ? 'Signing in…' : 'Open dashboard'}
          </button>
        </form>

        <p className="login-footnote"><Icon name="lock" size={13} />Credentials are sent only to this host.</p>
      </section>
    </main>
  );
}
