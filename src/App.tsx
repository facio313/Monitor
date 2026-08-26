import { useCallback, useEffect, useState } from 'react';
import { getSession, logout, type SessionInfo } from './api';
import { BonifacioReturnLink } from './components/BonifacioReturnLink';
import { MonitorDashboard } from './components/MonitorDashboard';
import { Icon } from './components/Icon';
import { LoginScreen } from './components/LoginScreen';
import { monitorPageFromPath, monitorPathForPage } from './dashboard-model';
import type { MonitorPage } from './types';

type SessionState = 'checking' | 'authenticated' | 'anonymous';

function pageFromLocation(): MonitorPage {
  return monitorPageFromPath(window.location.pathname);
}

export default function App() {
  const [session, setSession] = useState<SessionState>('checking');
  const [authMode, setAuthMode] = useState<'local' | 'sso'>('local');
  const [viewer, setViewer] = useState<SessionInfo | null>(null);
  const [sessionMessage, setSessionMessage] = useState<string | null>(null);
  const [page, setPage] = useState<MonitorPage>(pageFromLocation);
  const [navigationVersion, setNavigationVersion] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    getSession(controller.signal)
      .then((result) => {
        setAuthMode(result.mode);
        setViewer(result);
        if (!result.authenticated && result.mode === 'sso') {
          window.location.assign(`/sso/?rd=${encodeURIComponent(window.location.href)}`);
          return;
        }
        setSession(result.authenticated ? 'authenticated' : 'anonymous');
      })
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

  const handleNavigate = useCallback((nextPage: MonitorPage) => {
    const target = monitorPathForPage(nextPage);
    if (window.location.pathname !== target || window.location.hash) {
      window.history.pushState(null, '', target);
    }
    setPage(nextPage);
    setNavigationVersion((current) => current + 1);
  }, []);

  const handleUnauthorized = useCallback(() => {
    if (authMode === 'sso') {
      window.location.assign(`/sso/?rd=${encodeURIComponent(window.location.href)}`);
      return;
    }
    setSessionMessage('Your session expired. Sign in again to continue.');
    setSession('anonymous');
  }, [authMode]);

  const handlePasswordChanged = useCallback(() => {
    setSessionMessage('Password changed. Sign in with your new password.');
    setSession('anonymous');
  }, []);

  async function handleLogout() {
    try {
      await logout();
    } finally {
      if (authMode === 'sso') {
        window.location.assign(`/sso/logout?rd=${encodeURIComponent(`${window.location.origin}/sso/`)}`);
        return;
      }
      setSessionMessage('You have been signed out.');
      setSession('anonymous');
    }
  }

  if (session === 'checking') {
    return (
      <main className="boot-screen" aria-live="polite" lang="ko">
        <BonifacioReturnLink />
        <div className="brand-mark brand-mark-large"><Icon name="activity" size={26} /></div>
        <div className="boot-pulse" aria-hidden="true" />
        <p>보안 세션과 계기판을 확인하는 중…</p>
      </main>
    );
  }

  if (session === 'anonymous') {
    return <LoginScreen sessionMessage={sessionMessage} onAuthenticated={() => { setSessionMessage(null); setSession('authenticated'); }} />;
  }

  return (
    <MonitorDashboard
      page={page}
      navigationVersion={navigationVersion}
      onNavigate={handleNavigate}
      onLogout={handleLogout}
      onPasswordChanged={handlePasswordChanged}
      onUnauthorized={handleUnauthorized}
      ssoEnabled={authMode === 'sso'}
      viewer={viewer}
    />
  );
}
