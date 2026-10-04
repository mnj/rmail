import React, { useState } from 'react';
import { KeyRound, RefreshCw, Server } from 'lucide-react';
import { api, readiness, Session, SettingsView } from '../api';
import { Empty, ErrorBanner, Field, formatDate, formatRelative, Panel, useFeedback, useResource } from '../ui';

const serviceLabels: Record<string, string> = {
  smtpd: 'SMTP ingress & submission',
  imapd: 'IMAP access',
  outbound: 'Outbound delivery',
  web: 'Admin console',
  webmail: 'Webmail',
  classifier: 'Mail organization',
};

export function AdminCredentialsForm({ session, onChanged, setup }: { session: Session; onChanged: (user: string) => void; setup?: boolean }) {
  const { run } = useFeedback();
  const [username, setUsername] = useState(session.user || 'admin');
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirmNext, setConfirmNext] = useState('');
  const mismatch = confirmNext !== '' && next !== confirmNext;

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (mismatch) return;
    const ok = await run(async () => {
      const result = await api<{ user: string }>('/api/admin/credentials', 'POST', { username, current_password: setup ? undefined : current, new_password: next });
      onChanged(result.user);
    }, setup ? 'Admin account created' : 'Admin credentials updated');
    if (ok) {
      setCurrent('');
      setNext('');
      setConfirmNext('');
    }
  }

  return (
    <form className="formStack padded" onSubmit={submit}>
      <Field label="Username"><input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" required /></Field>
      {!setup && <Field label="Current password"><input type="password" value={current} onChange={(event) => setCurrent(event.target.value)} autoComplete="current-password" required /></Field>}
      <Field label="New password" hint="Must satisfy the admin password policy (Settings → Authentication). Changing it signs out other admin sessions."><input type="password" value={next} onChange={(event) => setNext(event.target.value)} autoComplete="new-password" required /></Field>
      <Field label="Repeat new password" hint={mismatch ? <span className="errorText">Passwords do not match</span> : undefined}><input type="password" value={confirmNext} onChange={(event) => setConfirmNext(event.target.value)} autoComplete="new-password" required /></Field>
      <button className="button primary" disabled={mismatch || next.length < 10}><KeyRound size={16} />{setup ? 'Create admin account' : 'Update credentials'}</button>
    </form>
  );
}

export function SystemPage({ session, onSessionChange }: { session: Session; onSessionChange: (session: Session) => void }) {
  const ready = useResource(readiness, []);
  const settings = useResource(() => api<SettingsView>('/api/settings'), [], 30000);
  const view = settings.data;
  const services = view && view.managed ? view.services : [];

  return (
    <div className="systemPage">
      <div className="systemHero">
        <div><span className={`statusDot ${ready.data?.ready ? 'ok' : 'error'}`} /><strong>{ready.data ? (ready.data.ready ? 'All required dependencies ready' : 'System needs attention') : 'Checking…'}</strong><p>Readiness is evaluated by the admin daemon against live storage, network and security settings.</p></div>
        <button className="button" onClick={() => ready.reload()}><RefreshCw size={16} className={ready.loading ? 'spin' : ''} />Run checks</button>
      </div>
      <div className="serviceGrid">
        {Object.entries(ready.data?.checks || {}).map(([name, check]) => (
          <article className="serviceCard" key={name}>
            <div className={`serviceIcon ${check.status}`}><Server size={18} /></div>
            <div><span>{name.replaceAll('_', ' ')}</span><strong>{check.status === 'ok' ? 'Operational' : check.status === 'skipped' ? 'Not configured' : 'Unavailable'}</strong><p>{check.error || (check.status === 'ok' ? 'Live check completed successfully.' : check.status === 'skipped' ? 'Optional dependency is disabled.' : 'The readiness probe reported a failure.')}</p></div>
            <span className={`statusBadge ${check.status}`}>{check.status}</span>
          </article>
        ))}
        {!ready.data && <Empty>Waiting for readiness data.</Empty>}
      </div>
      <section className="grid systemDetails">
        <Panel title="Services" subtitle="Last start recorded by each daemon">
          <ErrorBanner error={settings.error} />
          {services.length ? (
            <table>
              <thead><tr><th>Service</th><th>Started</th><th>Process</th><th>Settings</th></tr></thead>
              <tbody>
                {services.map((service) => (
                  <tr key={service.service}>
                    <td><strong>{serviceLabels[service.service] || service.service}</strong><small><code>{service.service}</code></small></td>
                    <td title={formatDate(service.started_at)}>{formatRelative(service.started_at)}</td>
                    <td>pid {service.pid}{service.host ? <small>{service.host}</small> : null}</td>
                    <td>{service.restart_required
                      ? <span className="pill warn" title={service.pending_changes.join(', ')}>Restart needed</span>
                      : <span className="pill ok">Current (rev {service.settings_revision})</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <Empty>{view && !view.managed ? 'Service tracking needs a settings database (db_path).' : 'No service has recorded a start yet.'}</Empty>}
        </Panel>
        <Panel title="Admin account" subtitle={session.user ? `Signed in as ${session.user}` : undefined}>
          {session.settings_managed
            ? <AdminCredentialsForm session={session} onChanged={(user) => onSessionChange({ ...session, user, authenticated: true, setup_required: false })} />
            : <Empty>Admin credentials come from <code>web_admin_user</code> and <code>web_admin_password_hash</code> in the configuration file.</Empty>}
        </Panel>
      </section>
      <Panel title="Operator endpoints">
        <div className="endpointList">
          <div><code>/healthz</code><span>Process liveness (no authentication)</span></div>
          <div><code>/readyz</code><span>Dependency readiness (no authentication)</span></div>
          <div><code>/metrics</code><span>Prometheus telemetry (Basic authentication)</span></div>
          <div><code>/api/*</code><span>JSON API; state changes need the <code>X-Rmail-Admin: 1</code> header</span></div>
        </div>
      </Panel>
    </div>
  );
}
