import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Activity, AlertTriangle, BarChart3, CheckCircle2, ChevronRight, Database, Gauge, Mail, Menu, Network, Plus, RefreshCw, RotateCcw, Route, Send, Server, Shield, Trash2, Users, X, Zap } from 'lucide-react';
import './style.css';

type Stats = { mailboxes: number; total_messages: number; delivered_count: number; outbound_pending: number };
type Account = { address: string; auth: string; folders: number; messages: number; unseen: number; used_bytes: number; quota_bytes: number | null };
type QueueSummary = { queued: number; inflight: number; sent: number; failed: number };
type Overview = {
  accounts: number;
  folders: number;
  total_messages: number;
  unseen_messages: number;
  aliases: number;
  catchalls: number;
  domains: { domain: string; accounts: number; messages: number; unseen: number }[];
  top_mailboxes: { address: string; messages: number; unseen: number; folders: number }[];
  queue: QueueSummary;
};
type QueueItem = { name: string; control?: { attempts?: number; priority?: number; next_try?: number | null; last_error?: string | null } };
type DmarcRow = { domain: string; events: number };
type Routing = { aliases: { address: string; targets: string[] }[]; catchalls: { domain: string; target: string }[] };

const numberFmt = new Intl.NumberFormat();
const formatBytes = (value: number) => value >= 1024 * 1024 * 1024 ? `${(value / (1024 * 1024 * 1024)).toFixed(1)} GiB` : value >= 1024 * 1024 ? `${(value / (1024 * 1024)).toFixed(1)} MiB` : `${Math.ceil(value / 1024)} KiB`;
type Page = 'overview' | 'accounts' | 'routing' | 'delivery' | 'observability';
const pageMeta: Record<Page, { path: string; label: string; eyebrow: string; description: string; icon: React.ElementType }> = {
  overview: { path: '/', label: 'Overview', eyebrow: 'Command center', description: 'System health, storage activity, and delivery pressure at a glance.', icon: Gauge },
  accounts: { path: '/accounts', label: 'Accounts', eyebrow: 'Identity & storage', description: 'Provision mailboxes and inspect account storage and authentication state.', icon: Users },
  routing: { path: '/routing', label: 'Routing', eyebrow: 'Mail flow', description: 'Manage aliases, catchalls, and domain-level recipient routing.', icon: Network },
  delivery: { path: '/delivery', label: 'Delivery', eyebrow: 'Outbound operations', description: 'Inspect queue pressure, recover messages, and review DMARC activity.', icon: Send },
  observability: { path: '/observability', label: 'Observability', eyebrow: 'Diagnostics', description: 'Review daemon telemetry and live operational logs.', icon: Activity },
};

function pageFromPath(path: string): Page {
  return (Object.entries(pageMeta).find(([, value]) => value.path === path)?.[0] as Page | undefined) || 'overview';
}

async function api<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(url, options);
  if (!res.ok) throw new Error(`${url} returned ${res.status}`);
  return res.json() as Promise<T>;
}

async function text(url: string): Promise<string> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url} returned ${res.status}`);
  return res.text();
}

function Kpi({ label, value, detail, icon: Icon }: { label: string; value: string; detail: string; icon: React.ElementType }) {
  return <section className="kpi"><div><span>{label}</span><strong>{value}</strong></div><Icon size={22} /><small>{detail}</small></section>;
}

function BarRow({ label, value, max, detail }: { label: string; value: number; max: number; detail: string }) {
  const width = max > 0 ? Math.max(4, Math.round((value / max) * 100)) : 0;
  return <div className="barRow"><div><span>{label}</span><strong>{numberFmt.format(value)}</strong></div><div className="barTrack"><i style={{ width: `${width}%` }} /></div><small>{detail}</small></div>;
}

function App() {
  const [page, setPage] = useState<Page>(() => pageFromPath(window.location.pathname));
  const [mobileNav, setMobileNav] = useState(false);
  const [stats, setStats] = useState<Stats | null>(null);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [queueSummary, setQueueSummary] = useState<QueueSummary | null>(null);
  const [queue, setQueue] = useState<QueueItem[]>([]);
  const [metrics, setMetrics] = useState<string[]>([]);
  const [dmarc, setDmarc] = useState<DmarcRow[]>([]);
  const [routing, setRouting] = useState<Routing>({ aliases: [], catchalls: [] });
  const [logComponent, setLogComponent] = useState('smtpd');
  const [logs, setLogs] = useState('');
  const [target, setTarget] = useState('');
  const [newAccount, setNewAccount] = useState({ address: '', password: '', quota_mib: '' });
  const [aliasForm, setAliasForm] = useState({ address: '', targets: '' });
  const [catchallForm, setCatchallForm] = useState({ domain: '', target: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const health = useMemo(() => {
    if (!stats || !queueSummary) return { label: 'Loading', detail: 'Waiting for daemon data', icon: Activity };
    if (queueSummary.failed > 0) return { label: 'Attention', detail: `${queueSummary.failed} failed outbound messages`, icon: AlertTriangle };
    if (stats.outbound_pending > 0) return { label: 'Backlog', detail: `${stats.outbound_pending} messages pending delivery`, icon: Zap };
    return { label: 'Nominal', detail: 'No visible queue pressure', icon: CheckCircle2 };
  }, [stats, queueSummary]);

  async function refresh(component = logComponent) {
    setLoading(true);
    setError('');
    const failures: string[] = [];
    const capture = (err: unknown) => failures.push(err instanceof Error ? err.message : String(err));
    await Promise.all([
      api<Stats>('/stats').then(setStats).catch(capture),
      api<Overview>('/api/overview').then((data) => {
        setOverview(data);
        setQueueSummary(data.queue);
      }).catch(capture),
      api<Account[]>('/api/accounts').then(setAccounts).catch(capture),
      api<QueueSummary>('/api/queue/summary').then(setQueueSummary).catch(capture),
      api<{ queued: QueueItem[] }>('/api/queue').then((data) => setQueue(data.queued || [])).catch(capture),
      text('/metrics').then((raw) => setMetrics(raw.split('\n').filter((line) => line && !line.startsWith('#')).slice(0, 9))).catch(capture),
      text(`/logs?component=${component}&lines=180`).then((raw) => setLogs(raw || 'No log lines available.')).catch(capture),
      api<Routing>('/api/routing').then(setRouting).catch(capture),
      api<DmarcRow[]>('/dmarc').then(setDmarc).catch(() => setDmarc([])),
    ]);
    if (failures.length) setError(`Some admin endpoints are unavailable: ${failures.slice(0, 2).join(', ')}`);
    setLoading(false);
  }

  async function saveAccount(event: React.FormEvent) {
    event.preventDefault();
    if (!newAccount.address.trim()) return;
    await api('/api/accounts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address: newAccount.address.trim(), password: newAccount.password || undefined, quota_mib: newAccount.quota_mib === '' ? undefined : Number(newAccount.quota_mib) }),
    });
    setNewAccount({ address: '', password: '', quota_mib: '' });
    await refresh();
  }

  async function deleteAccount(address: string) {
    await api('/api/accounts', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address }),
    });
    await refresh();
  }

  async function saveAlias(event: React.FormEvent) {
    event.preventDefault();
    if (!aliasForm.address.trim()) return;
    const targets = aliasForm.targets.split(',').map((item) => item.trim()).filter(Boolean);
    await api('/api/routing/alias', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address: aliasForm.address.trim(), targets }),
    });
    setAliasForm({ address: '', targets: '' });
    await refresh();
  }

  async function saveCatchall(event: React.FormEvent) {
    event.preventDefault();
    if (!catchallForm.domain.trim()) return;
    await api('/api/routing/catchall', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain: catchallForm.domain.trim(), target: catchallForm.target.trim() || undefined }),
    });
    setCatchallForm({ domain: '', target: '' });
    await refresh();
  }

  async function queueAction(action: 'requeue' | 'promote' | 'delete') {
    const value = target.trim();
    if (!value) return;
    const body: Record<string, unknown> = value.includes('*') ? { pattern: value } : { name: value };
    body.action = action;
    if (action === 'promote') body.priority = 10;
    await api('/api/queue/action', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    setTarget('');
    await refresh();
  }

  useEffect(() => {
    refresh();
    const id = window.setInterval(() => refresh(), 30000);
    return () => window.clearInterval(id);
  }, []);

  useEffect(() => {
    text(`/logs?component=${logComponent}&lines=180`).then(setLogs).catch((err) => setLogs(err.message));
  }, [logComponent]);

  useEffect(() => {
    const onPopState = () => setPage(pageFromPath(window.location.pathname));
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

  function navigate(next: Page) {
    window.history.pushState({}, '', pageMeta[next].path);
    setPage(next);
    setMobileNav(false);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  const HealthIcon = health.icon;
  const domainMax = Math.max(0, ...(overview?.domains.map((domain) => domain.messages) || []));
  const mailboxMax = Math.max(0, ...(overview?.top_mailboxes.map((mailbox) => mailbox.messages) || []));
  const queueMax = Math.max(1, ...(queueSummary ? [queueSummary.queued, queueSummary.inflight, queueSummary.sent, queueSummary.failed] : [0]));

  return (
    <main className="shell">
      {mobileNav && <button className="navScrim" aria-label="Close navigation" onClick={() => setMobileNav(false)} />}
      <aside className={`sidebar ${mobileNav ? 'open' : ''}`}>
        <div className="brand"><div className="logo">rM</div><div><strong>rMail</strong><span>Admin console</span></div></div>
        <button className="closeNav" onClick={() => setMobileNav(false)} aria-label="Close navigation"><X size={20} /></button>
        <div className="navLabel">Workspace</div>
        <nav>{(Object.entries(pageMeta) as [Page, typeof pageMeta[Page]][]).map(([key, item]) => { const Icon = item.icon; return <a key={key} href={item.path} className={page === key ? 'active' : ''} onClick={(event) => { event.preventDefault(); navigate(key); }}><Icon size={18} /><span>{item.label}</span><ChevronRight size={15} /></a>; })}</nav>
        <div className="health"><HealthIcon size={18} /><div><strong>{health.label}</strong><span>{health.detail}</span></div></div>
      </aside>
      <section className="content">
        <header className="topbar">
          <button className="menuButton" onClick={() => setMobileNav(true)} aria-label="Open navigation"><Menu size={20} /></button>
          <div className="pageTitle"><span>{pageMeta[page].eyebrow}</span><h1>{pageMeta[page].label}</h1><p>{pageMeta[page].description}</p></div>
          <div className="topActions"><span className="refreshState"><i className={loading ? 'loading' : ''} />{loading ? 'Refreshing' : 'Auto-refresh · 30s'}</span><button className="button primary" onClick={() => refresh()} disabled={loading}><RefreshCw size={16} />Refresh</button></div>
        </header>
        {error && <div className="banner">{error}</div>}
        <section className="kpis" id="overview" hidden={page !== 'overview'}>
          <Kpi label="Mailboxes" value={numberFmt.format(overview?.accounts ?? stats?.mailboxes ?? 0)} detail={`${overview?.folders ?? 0} folders tracked`} icon={Users} />
          <Kpi label="Stored Messages" value={numberFmt.format(overview?.total_messages ?? stats?.total_messages ?? 0)} detail={`${numberFmt.format(overview?.unseen_messages ?? 0)} unseen messages`} icon={Mail} />
          <Kpi label="Delivered" value={numberFmt.format(stats?.delivered_count || 0)} detail="Runtime delivery counter" icon={Send} />
          <Kpi label="Pending" value={numberFmt.format(stats?.outbound_pending || queueSummary?.queued || 0)} detail={`${queueSummary?.inflight || 0} inflight, ${queueSummary?.failed || 0} failed`} icon={Server} />
        </section>
        <section className="grid analytics" id="analytics" hidden={page !== 'overview'}>
          <article className="panel">
            <div className="panelHead"><h2>Domain Distribution</h2><span>{overview ? `${overview.domains.length} domains` : 'Loading'}</span></div>
            <div className="barList">{overview?.domains.length ? overview.domains.slice(0, 8).map((domain) => <BarRow key={domain.domain} label={domain.domain} value={domain.messages} max={domainMax} detail={`${domain.accounts} accounts, ${domain.unseen} unseen`} />) : <div className="empty">No domain activity yet.</div>}</div>
          </article>
          <article className="panel">
            <div className="panelHead"><h2>Operations Snapshot</h2><BarChart3 size={18} /></div>
            <div className="snapshotGrid">
              <div><span>Aliases</span><strong>{numberFmt.format(overview?.aliases || 0)}</strong></div>
              <div><span>Catchalls</span><strong>{numberFmt.format(overview?.catchalls || 0)}</strong></div>
              <div><span>Unread</span><strong>{numberFmt.format(overview?.unseen_messages || 0)}</strong></div>
              <div><span>Folders</span><strong>{numberFmt.format(overview?.folders || 0)}</strong></div>
            </div>
            <div className="barList compact">
              {queueSummary && <>
                <BarRow label="Queued" value={queueSummary.queued} max={queueMax} detail="waiting delivery" />
                <BarRow label="Inflight" value={queueSummary.inflight} max={queueMax} detail="worker-owned" />
                <BarRow label="Sent" value={queueSummary.sent} max={queueMax} detail="retained sent spool" />
                <BarRow label="Failed" value={queueSummary.failed} max={queueMax} detail="needs action" />
              </>}
            </div>
          </article>
          <article className="panel wide">
            <div className="panelHead"><h2>Mailbox Load</h2><span>{overview ? `${overview.top_mailboxes.length} busiest` : 'Loading'}</span></div>
            <div className="barList twoCol">{overview?.top_mailboxes.length ? overview.top_mailboxes.map((mailbox) => <BarRow key={mailbox.address} label={mailbox.address} value={mailbox.messages} max={mailboxMax} detail={`${mailbox.folders} folders, ${mailbox.unseen} unseen`} />) : <div className="empty">No mailbox messages found.</div>}</div>
          </article>
        </section>
        <section className="grid accountPage" hidden={page !== 'accounts'}>
          <article className="panel wide" id="accounts">
            <div className="panelHead"><h2>Account Management</h2><span>{accounts.length} accounts</span></div>
            <form className="inlineForm" onSubmit={saveAccount}><input value={newAccount.address} onChange={(e) => setNewAccount({ ...newAccount, address: e.target.value })} placeholder="mailbox@example.com" /><input value={newAccount.password} onChange={(e) => setNewAccount({ ...newAccount, password: e.target.value })} placeholder="New password" type="password" /><input value={newAccount.quota_mib} onChange={(e) => setNewAccount({ ...newAccount, quota_mib: e.target.value })} placeholder="Quota MiB (0 = none)" type="number" min="0" /><button className="button primary"><Plus size={16} />Save mailbox</button></form>
            <table><thead><tr><th>Mailbox</th><th>Auth</th><th>Storage</th><th>Folders</th><th>Messages</th><th>Unseen</th><th></th></tr></thead><tbody>{accounts.length ? accounts.map((a) => <tr key={a.address}><td><strong>{a.address}</strong><small>{a.unseen ? 'Unread activity' : 'No unread mail'}</small></td><td><span className="pill">{a.auth}</span></td><td>{formatBytes(a.used_bytes)} / {a.quota_bytes == null ? 'Unlimited' : formatBytes(a.quota_bytes)}</td><td>{a.folders}</td><td>{a.messages}</td><td>{a.unseen}</td><td><button className="iconButton danger" onClick={() => deleteAccount(a.address)} title="Delete mailbox"><Trash2 size={15} /></button></td></tr>) : <tr><td colSpan={7} className="empty">No DB-backed accounts found.</td></tr>}</tbody></table>
          </article>
          <article className="panel accountSummary">
            <div className="panelHead"><h2>Storage Summary</h2><Database size={18} /></div>
            <div className="snapshotGrid"><div><span>Accounts</span><strong>{overview?.accounts || 0}</strong></div><div><span>Folders</span><strong>{overview?.folders || 0}</strong></div><div><span>Messages</span><strong>{overview?.total_messages || 0}</strong></div><div><span>Unseen</span><strong>{overview?.unseen_messages || 0}</strong></div></div>
          </article>
        </section>
        <section className="grid" id="routing" hidden={page !== 'routing'}>
          <article className="panel">
            <div className="panelHead"><h2>Aliases</h2><Route size={18} /></div>
            <form className="stackForm" onSubmit={saveAlias}><input value={aliasForm.address} onChange={(e) => setAliasForm({ ...aliasForm, address: e.target.value })} placeholder="alias@example.com" /><input value={aliasForm.targets} onChange={(e) => setAliasForm({ ...aliasForm, targets: e.target.value })} placeholder="target1@example.com, target2@example.com" /><button className="button primary"><Plus size={16} />Save alias</button></form>
            <div className="metricList">{routing.aliases.length ? routing.aliases.map((alias) => <div className="metric" key={alias.address}><span>{alias.address}</span><strong>{alias.targets.join(', ')}</strong></div>) : <div className="empty">No aliases configured.</div>}</div>
          </article>
          <article className="panel">
            <div className="panelHead"><h2>Catchalls</h2><Shield size={18} /></div>
            <form className="stackForm" onSubmit={saveCatchall}><input value={catchallForm.domain} onChange={(e) => setCatchallForm({ ...catchallForm, domain: e.target.value })} placeholder="example.com" /><input value={catchallForm.target} onChange={(e) => setCatchallForm({ ...catchallForm, target: e.target.value })} placeholder="target@example.com" /><button className="button primary"><Plus size={16} />Save catchall</button></form>
            <div className="metricList">{routing.catchalls.length ? routing.catchalls.map((row) => <div className="metric" key={row.domain}><span>@{row.domain}</span><strong>{row.target}</strong></div>) : <div className="empty">No catchalls configured.</div>}</div>
          </article>
        </section>
        <section className="grid" hidden={page !== 'delivery'}>
          <article className="panel wide" id="queue">
            <div className="panelHead"><h2>Outbound Queue</h2><span>{queueSummary ? `${queueSummary.queued} queued, ${queueSummary.failed} failed` : 'Loading'}</span></div>
            <div className="queueTools"><input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="Message name or wildcard pattern" /><button className="button" onClick={() => queueAction('requeue')}><RotateCcw size={16} />Requeue</button><button className="button primary" onClick={() => queueAction('promote')}><Zap size={16} />Promote</button><button className="button danger" onClick={() => queueAction('delete')}><Trash2 size={16} />Delete</button></div>
            <table><thead><tr><th>Message</th><th>Attempts</th><th>Priority</th><th>Next Try</th><th>Error</th></tr></thead><tbody>{queue.length ? queue.slice(0, 12).map((item) => <tr key={item.name}><td><strong>{item.name}</strong></td><td>{item.control?.attempts ?? 0}</td><td>{item.control?.priority ?? 0}</td><td>{item.control?.next_try ?? '-'}</td><td className="muted">{item.control?.last_error || '-'}</td></tr>) : <tr><td colSpan={5} className="empty">No queued outbound messages.</td></tr>}</tbody></table>
          </article>
          <article className="panel">
            <div className="panelHead"><h2>DMARC</h2><Shield size={18} /></div>
            <div className="metricList">{dmarc.length ? dmarc.map((row) => <div className="metric" key={row.domain}><span>{row.domain}</span><strong>{row.events} events</strong></div>) : <div className="empty">No unreported DMARC events.</div>}</div>
          </article>
        </section>
        <section className="grid observability" hidden={page !== 'observability'}>
          <article className="panel" id="metrics">
            <div className="panelHead"><div><h2>Prometheus Metrics</h2><small>Latest cross-service samples</small></div><BarChart3 size={18} /></div>
            <div className="metricList">{metrics.length ? metrics.map((line) => <div className="metric" key={line}><span>{line.split(/\s+/)[0]}</span><strong>{line.split(/\s+/).slice(1).join(' ')}</strong></div>) : <div className="empty">No metrics emitted yet.</div>}</div>
          </article>
          <article className="panel diagnosticCard"><div className="panelHead"><h2>Service Diagnostics</h2><Shield size={18} /></div><div className="diagnosticBody"><CheckCircle2 size={28} /><strong>{health.label}</strong><p>{health.detail}</p><span>Readiness and dependency checks are available at <code>/readyz</code>.</span></div></article>
        </section>
        <article className="panel" id="logs" hidden={page !== 'observability'}>
          <div className="panelHead"><h2>Daemon Logs</h2><div className="tabs">{['smtpd', 'imapd', 'outbound', 'web'].map((name) => <button key={name} className={name === logComponent ? 'active' : ''} onClick={() => setLogComponent(name)}>{name}</button>)}</div></div>
          <pre>{logs}</pre>
        </article>
        <footer><Database size={15} /> API-backed admin UI served by rMail web daemon.</footer>
      </section>
    </main>
  );
}

createRoot(document.getElementById('root')!).render(<App />);
