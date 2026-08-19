import { useCallback, useEffect, useState } from 'react';
import { getSession, logout } from './api';
import { Dashboard } from './components/Dashboard';
import { Icon } from './components/Icon';
import { LoginScreen } from './components/LoginScreen';
import type { MonitorPage } from './types';

type SessionState = 'checking' | 'authenticated' | 'anonymous';

function pageFromLocation(): MonitorPage {
  return /^\/monitor\/details\/?$/.test(window.location.pathname) ? 'details' : 'overview';
}

export default function App() {
  const [session, setSession] = useState<SessionState>('checking');
  const [sessionMessage, setSessionMessage] = useState<string | null>(null);
  const [page, setPage] = useState<MonitorPage>(pageFromLocation);
  const [navigationVersion, setNavigationVersion] = useState(0);

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

  useEffect(() => {
    const syncLocation = () => {
      setPage(pageFromLocation());
      setNavigationVersion((current) => current + 1);
    };
    window.addEventListener('popstate', syncLocation);
    window.addEventListener('hashchange', syncLocation);
    return () => {
      window.removeEventListener('popstate', syncLocation);
      window.removeEventListener('hashchange', syncLocation);
    };
  }, []);

  const handleNavigate = useCallback((nextPage: MonitorPage, hash = '') => {
    const pathname = nextPage === 'details' ? '/monitor/details' : '/monitor/';
    const target = `${pathname}${hash}`;
    if (`${window.location.pathname}${window.location.hash}` !== target) {
      window.history.pushState(null, '', target);
    }
    setPage(nextPage);
    setNavigationVersion((current) => current + 1);
  }, []);

  const handleUnauthorized = useCallback(() => {
    setSessionMessage('Your session expired. Sign in again to continue.');
    setSession('anonymous');
  }, []);

  const handlePasswordChanged = useCallback(() => {
    setSessionMessage('Password changed. Sign in with your new password.');
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

  return (
    <Dashboard
      page={page}
      navigationVersion={navigationVersion}
      onNavigate={handleNavigate}
      onLogout={handleLogout}
      onPasswordChanged={handlePasswordChanged}
      onUnauthorized={handleUnauthorized}
    />
  );
}
