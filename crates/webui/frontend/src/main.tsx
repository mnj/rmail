import React, { useCallback, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Activity, ChevronRight, FolderTree, Gauge, LockKeyhole, LogOut, Menu, Network, Send, Server, SlidersHorizontal, Users, X } from 'lucide-react';
import { api, errorMessage, onUnauthorized, Session } from './api';
import { FeedbackProvider, Field } from './ui';
import { OverviewPage } from './pages/Overview';
import { AccountsPage } from './pages/Accounts';
import { RoutingPage } from './pages/Routing';
import { DeliveryPage } from './pages/Delivery';
import { SettingsPage } from './pages/Settings';
import { CertificatesPage } from './pages/Certificates';
import { OrganizationPage } from './pages/Organization';
import { ObservabilityPage } from './pages/Observability';
import { AdminCredentialsForm, SystemPage } from './pages/System';
import './style.css';

export type Page = 'overview' | 'accounts' | 'routing' | 'delivery' | 'organization' | 'settings' | 'certificates' | 'observability' | 'system';

const pageMeta: Record<Page, { path: string; label: string; eyebrow: string; description: string; icon: React.ElementType }> = {
  overview: { path: '/', label: 'Overview', eyebrow: 'Command center', description: 'Health, storage and delivery at a glance.', icon: Gauge },
  accounts: { path: '/accounts', label: 'Mailboxes', eyebrow: 'Identity & storage', description: 'Create mailboxes, reset passwords and manage quotas.', icon: Users },
  routing: { path: '/routing', label: 'Routing', eyebrow: 'Mail flow', description: 'Aliases and per-domain catchalls.', icon: Network },
  delivery: { path: '/delivery', label: 'Delivery', eyebrow: 'Outbound operations', description: 'Inspect and recover the outbound queue.', icon: Send },
  organization: { path: '/organization', label: 'Organization', eyebrow: 'Local AI', description: 'Download, choose and test the local models that suggest folders for new mail.', icon: FolderTree },
  settings: { path: '/settings', label: 'Settings', eyebrow: 'Configuration', description: 'Listeners, TLS, authentication, limits and filtering. Stored in the database.', icon: SlidersHorizontal },
  certificates: { path: '/certificates', label: 'Certificates', eyebrow: 'TLS', description: 'Automatic certificates from Let\'s Encrypt or another ACME CA, renewed and reloaded without restarts.', icon: LockKeyhole },
  observability: { path: '/observability', label: 'Logs & metrics', eyebrow: 'Diagnostics', description: 'Daemon logs and Prometheus telemetry.', icon: Activity },
  system: { path: '/system', label: 'System', eyebrow: 'Services & access', description: 'Dependency readiness, running services and the admin account.', icon: Server },
};

const navGroups: { label: string; pages: Page[] }[] = [
  { label: 'Workspace', pages: ['overview'] },
  { label: 'Mail', pages: ['accounts', 'routing', 'delivery', 'organization'] },
  { label: 'Server', pages: ['settings', 'certificates', 'observability', 'system'] },
];

function pageFromPath(path: string): Page {
  return (Object.entries(pageMeta).find(([, value]) => value.path === path)?.[0] as Page | undefined) || 'overview';
}

function AuthScreen({ children, title, subtitle }: { children: React.ReactNode; title: string; subtitle: string }) {
  return (
    <main className="authShell">
      <div className="authCard">
        <div className="brand dark"><div className="logo">rM</div><div><strong>rMail</strong><span>Admin console</span></div></div>
        <h1>{title}</h1>
        <p>{subtitle}</p>
        {children}
      </div>
    </main>
  );
}

function LoginScreen({ onLogin }: { onLogin: (session: Session) => void }) {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      await api('/api/login', 'POST', { username, password });
      onLogin(await api<Session>('/api/session'));
    } catch (err) {
      setError(errorMessage(err));
      setPassword('');
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthScreen title="Sign in" subtitle="Use the admin account for this server.">
      <form className="formStack" onSubmit={submit}>
        <Field label="Username"><input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" required /></Field>
        <Field label="Password"><input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" autoFocus required /></Field>
        {error && <div className="banner">{error}</div>}
        <button className="button primary" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
      </form>
    </AuthScreen>
  );
}

function SetupScreen({ session, onDone }: { session: Session; onDone: (session: Session) => void }) {
  if (!session.settings_managed) {
    return (
      <AuthScreen title="Finish setting up" subtitle="No admin credentials are configured.">
        <p>This console is only reachable from this machine until you set <code>web_admin_user</code> and <code>web_admin_password_hash</code> in the configuration file (generate the hash with <code>rmail_ctl hash</code>), or configure a <code>db_path</code> to manage settings here.</p>
        <button className="button primary" onClick={() => onDone({ ...session, setup_required: false })}>Continue without a password</button>
      </AuthScreen>
    );
  }
  return (
    <AuthScreen title="Create the admin account" subtitle="No admin account exists yet. Choose the credentials you will use to sign in.">
      <AdminCredentialsForm setup session={session} onChanged={(user) => onDone({ ...session, user, authenticated: true, setup_required: false })} />
    </AuthScreen>
  );
}

function Console({ session, setSession }: { session: Session; setSession: (session: Session | null) => void }) {
  const [page, setPage] = useState<Page>(() => pageFromPath(window.location.pathname));
  const [mobileNav, setMobileNav] = useState(false);

  useEffect(() => {
    const onPopState = () => setPage(pageFromPath(window.location.pathname));
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

  useEffect(() => {
    document.title = `${pageMeta[page].label} · rMail Admin`;
  }, [page]);

  const navigate = useCallback((next: Page) => {
    window.history.pushState({}, '', pageMeta[next].path);
    setPage(next);
    setMobileNav(false);
    window.scrollTo({ top: 0 });
  }, []);

  async function logout() {
    await api('/api/logout', 'POST').catch(() => undefined);
    setSession(null);
  }

  const meta = pageMeta[page];
  return (
    <main className="shell">
      {mobileNav && <button className="navScrim" aria-label="Close navigation" onClick={() => setMobileNav(false)} />}
      <aside className={`sidebar ${mobileNav ? 'open' : ''}`}>
        <div className="brand"><div className="logo">rM</div><div><strong>rMail</strong><span>Admin console</span></div></div>
        <button className="closeNav" onClick={() => setMobileNav(false)} aria-label="Close navigation"><X size={20} /></button>
        <nav>
          {navGroups.map((group) => (
            <div className="navGroup" key={group.label}>
              <div className="navLabel">{group.label}</div>
              {group.pages.map((key) => {
                const item = pageMeta[key];
                const Icon = item.icon;
                return <a key={key} href={item.path} className={page === key ? 'active' : ''} aria-current={page === key ? 'page' : undefined} onClick={(event) => { event.preventDefault(); navigate(key); }}><Icon size={18} /><span>{item.label}</span><ChevronRight size={15} /></a>;
              })}
            </div>
          ))}
        </nav>
        <div className="account">
          <div><strong>{session.user || 'Local access'}</strong><span>{session.user ? 'Administrator' : 'No admin password set'}</span></div>
          {session.user && <button className="iconButton ghost" title="Sign out" onClick={logout}><LogOut size={16} /></button>}
        </div>
      </aside>
      <section className="content">
        <header className="topbar">
          <button className="menuButton" onClick={() => setMobileNav(true)} aria-label="Open navigation"><Menu size={20} /></button>
          <div className="pageTitle"><span>{meta.eyebrow}</span><h1>{meta.label}</h1><p>{meta.description}</p></div>
        </header>
        {page === 'overview' && <OverviewPage navigate={navigate} />}
        {page === 'accounts' && <AccountsPage />}
        {page === 'routing' && <RoutingPage />}
        {page === 'delivery' && <DeliveryPage />}
        {page === 'organization' && <OrganizationPage />}
        {page === 'settings' && <SettingsPage />}
        {page === 'certificates' && <CertificatesPage />}
        {page === 'observability' && <ObservabilityPage />}
        {page === 'system' && <SystemPage session={session} onSessionChange={setSession} />}
      </section>
    </main>
  );
}

function App() {
  const [session, setSession] = useState<Session | null | undefined>(undefined);
  const [error, setError] = useState('');

  const loadSession = useCallback(() => {
    api<Session>('/api/session').then(setSession).catch((err) => setError(errorMessage(err)));
  }, []);

  useEffect(() => {
    loadSession();
    onUnauthorized(() => setSession((current) => (current ? { ...current, authenticated: false, user: null } : current)));
  }, [loadSession]);

  if (error) return <AuthScreen title="Admin console unavailable" subtitle={error}><button className="button" onClick={() => { setError(''); loadSession(); }}>Retry</button></AuthScreen>;
  if (session === undefined) return <div className="bootSplash">Loading…</div>;
  if (session === null || (!session.authenticated && !session.setup_required)) return <LoginScreen onLogin={setSession} />;
  if (session.setup_required) return <SetupScreen session={session} onDone={setSession} />;
  return <Console session={session} setSession={(next) => (next ? setSession(next) : setSession({ ...session, authenticated: false, user: null }))} />;
}

createRoot(document.getElementById('root')!).render(<FeedbackProvider><App /></FeedbackProvider>);
