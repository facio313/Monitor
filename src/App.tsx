import { useCallback, useEffect, useState } from 'react';
import { getSession, logout } from './api';
import { Dashboard } from './components/Dashboard';
import { Icon } from './components/Icon';
import { LoginScreen } from './components/LoginScreen';

type SessionState = 'checking' | 'authenticated' | 'anonymous';

export default function App() {
  const [session, setSession] = useState<SessionState>('checking');
  const [sessionMessage, setSessionMessage] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    getSession(controller.signal)
      .then((authenticated) => setSession(authenticated ? 'authenticated' : 'anonymous'))
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === 'AbortError') return;
        setSessionMessage('Could not verify the current session. You can still try signing in.');
        setSession('anonymous');
      });
    return () => controller.abort();
  }, []);

  const handleUnauthorized = useCallback(() => {
    setSessionMessage('Your session expired. Sign in again to continue.');
    setSession('anonymous');
  }, []);

  async function handleLogout() {
    try {
      await logout();
    } finally {
      setSessionMessage('You have been signed out.');
      setSession('anonymous');
    }
  }

  if (session === 'checking') {
    return (
      <main className="boot-screen" aria-live="polite">
        <div className="brand-mark brand-mark-large"><Icon name="activity" size={26} /></div>
        <div className="boot-pulse" aria-hidden="true" />
        <p>Securing dashboard…</p>
      </main>
    );
  }

  if (session === 'anonymous') {
    return <LoginScreen sessionMessage={sessionMessage} onAuthenticated={() => { setSessionMessage(null); setSession('authenticated'); }} />;
  }

  return <Dashboard onLogout={handleLogout} onUnauthorized={handleUnauthorized} />;
}
