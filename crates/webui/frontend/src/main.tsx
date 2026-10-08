import React, { useCallback, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Activity, FolderTree, Gauge, Globe, LockKeyhole, LogOut, Menu, Monitor, Moon, Network, Send, Server, SlidersHorizontal, Sun, Users, X } from 'lucide-react';
import { api, errorMessage, onUnauthorized, QueueSummary, Session, SettingsView } from './api';
import { confirmLeave, FeedbackProvider, Field, useResource } from './ui';
import { OverviewPage } from './pages/Overview';
import { AccountsPage } from './pages/Accounts';
import { RoutingPage } from './pages/Routing';
import { DomainsPage } from './pages/Domains';
import { DeliveryPage } from './pages/Delivery';
import { SettingsPage } from './pages/Settings';
import { CertificatesPage } from './pages/Certificates';
import { OrganizationPage } from './pages/Organization';
import { ObservabilityPage } from './pages/Observability';
import { AdminCredentialsForm, SystemPage } from './pages/System';
import './style.css';

export type Page = 'overview' | 'accounts' | 'routing' | 'domains' | 'delivery' | 'organization' | 'settings' | 'certificates' | 'observability' | 'system';

const pageMeta: Record<Page, { path: string; label: string; description: string; icon: React.ElementType }> = {
  overview: { path: '/', label: 'Overview', description: 'Health, storage and delivery at a glance.', icon: Gauge },
  accounts: { path: '/accounts', label: 'Mailboxes', description: 'Create mailboxes, reset passwords and manage quotas.', icon: Users },
  routing: { path: '/routing', label: 'Routing', description: 'Aliases and per-domain catchalls.', icon: Network },
  domains: { path: '/domains', label: 'Domains & DNS', description: 'DKIM signing keys and the DNS records to publish for each domain.', icon: Globe },
  delivery: { path: '/delivery', label: 'Delivery', description: 'Inspect and recover the outbound queue.', icon: Send },
  organization: { path: '/organization', label: 'Organization', description: 'Choose, download and test the local or hosted models that suggest folders for new mail.', icon: FolderTree },
  settings: { path: '/settings', label: 'Settings', description: 'Listeners, TLS, authentication, limits and filtering. Stored in the database.', icon: SlidersHorizontal },
  certificates: { path: '/certificates', label: 'Certificates', description: 'Automatic certificates from Let\'s Encrypt or another ACME CA, renewed and reloaded without restarts.', icon: LockKeyhole },
  observability: { path: '/observability', label: 'Logs & metrics', description: 'Daemon logs and Prometheus telemetry.', icon: Activity },
  system: { path: '/system', label: 'System', description: 'Dependency readiness, running services and the admin account.', icon: Server },
};

const navGroups: { label: string; pages: Page[] }[] = [
  { label: 'Workspace', pages: ['overview'] },
  { label: 'Mail', pages: ['accounts', 'routing', 'domains', 'delivery', 'organization'] },
  { label: 'Server', pages: ['settings', 'certificates', 'observability', 'system'] },
];

function pageFromPath(path: string): Page {
  return (Object.entries(pageMeta).find(([, value]) => value.path === path)?.[0] as Page | undefined) || 'overview';
}

// ---------------------------------------------------------------------------
// Theme: follows the OS unless the viewer picks one; the choice is per browser.

type Theme = 'system' | 'light' | 'dark';
const themeKey = 'rmail-admin-theme';

function storedTheme(): Theme {
  try {
    const value = localStorage.getItem(themeKey);
    return value === 'light' || value === 'dark' ? value : 'system';
  } catch {
    return 'system';
  }
}

function applyTheme(theme: Theme) {
  if (theme === 'system') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', theme);
}

applyTheme(storedTheme());

function ThemeSwitch() {
  const [theme, setTheme] = useState<Theme>(storedTheme);
  const choose = (next: Theme) => {
    setTheme(next);
    applyTheme(next);
    try {
      if (next === 'system') localStorage.removeItem(themeKey);
      else localStorage.setItem(themeKey, next);
    } catch {
      // storage unavailable: the choice lasts for this page load
    }
  };
  const options: { id: Theme; label: string; icon: React.ElementType }[] = [
    { id: 'light', label: 'Light theme', icon: Sun },
    { id: 'system', label: 'Match system theme', icon: Monitor },
    { id: 'dark', label: 'Dark theme', icon: Moon },
  ];
  return (
    <div className="themeSwitch" role="group" aria-label="Theme">
      {options.map(({ id, label, icon: Icon }) => (
        <button key={id} type="button" aria-pressed={theme === id} aria-label={label} title={label} onClick={() => choose(id)}><Icon size={15} /></button>
      ))}
    </div>
  );
}

/** Counts shown next to sidebar entries so problems are visible from any page. */
function useNavBadges(): Partial<Record<Page, { count: number; tone: 'warn' | 'error'; label: string }>> {
  const queue = useResource(() => api<QueueSummary>('/api/queue/summary'), [], 60000, 'queue');
  const settings = useResource(() => api<SettingsView>('/api/settings'), [], 60000, 'settings');
  const badges: ReturnType<typeof useNavBadges> = {};
  if (queue.data?.failed) badges.delivery = { count: queue.data.failed, tone: 'error', label: `${queue.data.failed} failed` };
  const view = settings.data;
  const restarts = view ? view.services.filter((service) => service.restart_required).length : 0;
  if (restarts) badges.settings = { count: restarts, tone: 'warn', label: `${restarts} service${restarts === 1 ? '' : 's'} need a restart` };
  return badges;
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
  return (
    <AuthScreen title="Create the admin account" subtitle="No admin account exists yet. Choose the credentials you will use to sign in.">
      <AdminCredentialsForm setup session={session} onChanged={(user) => onDone({ ...session, user, authenticated: true, setup_required: false })} />
    </AuthScreen>
  );
}

function Console({ session, setSession }: { session: Session; setSession: (session: Session | null) => void }) {
  const [page, setPage] = useState<Page>(() => pageFromPath(window.location.pathname));
  const [mobileNav, setMobileNav] = useState(false);

  const badges = useNavBadges();
  const pageRef = React.useRef(page);
  pageRef.current = page;

  useEffect(() => {
    const onPopState = async () => {
      const next = pageFromPath(window.location.pathname);
      if (next === pageRef.current) return;
      // The URL already changed; put it back unless the page agrees to leave.
      if (!await confirmLeave()) {
        window.history.pushState({}, '', pageMeta[pageRef.current].path);
        return;
      }
      setPage(next);
    };
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

  useEffect(() => {
    document.title = `${pageMeta[page].label} · rMail Admin`;
  }, [page]);

  const navigate = useCallback(async (next: Page) => {
    setMobileNav(false);
    if (next === pageRef.current) return;
    if (!await confirmLeave()) return;
    window.history.pushState({}, '', pageMeta[next].path);
    setPage(next);
    setMobileNav(false);
    window.scrollTo({ top: 0 });
  }, []);

  async function logout() {
    if (!await confirmLeave()) return;
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
                const badge = badges[key];
                return (
                  <a key={key} href={item.path} className={page === key ? 'active' : ''} aria-current={page === key ? 'page' : undefined} onClick={(event) => { event.preventDefault(); navigate(key); }}>
                    <Icon size={18} /><span>{item.label}</span>
                    {badge ? <span className={`navBadge ${badge.tone}`} title={badge.label}>{badge.count}<span className="visuallyHidden">: {badge.label}</span></span> : <span />}
                  </a>
                );
              })}
            </div>
          ))}
        </nav>
        <div className="sidebarFoot">
          <ThemeSwitch />
          <div className="account">
            <div><strong>{session.user || 'Local access'}</strong><span>{session.user ? 'Administrator' : 'No admin password set'}</span></div>
            {session.user && <button className="iconButton ghost" aria-label="Sign out" title="Sign out" onClick={logout}><LogOut size={16} /></button>}
          </div>
        </div>
      </aside>
      <section className="content">
        <header className="topbar">
          <button className="menuButton" onClick={() => setMobileNav(true)} aria-label="Open navigation"><Menu size={20} /></button>
          <div className="pageTitle"><h1>{meta.label}</h1><p>{meta.description}</p></div>
        </header>
        {page === 'overview' && <OverviewPage navigate={navigate} />}
        {page === 'accounts' && <AccountsPage />}
        {page === 'routing' && <RoutingPage />}
        {page === 'domains' && <DomainsPage />}
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
