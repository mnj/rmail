import React, { useState } from 'react';
import { KeyRound, RefreshCw } from 'lucide-react';
import { api, readiness, ReadinessCheck, Session, SettingsView } from '../api';
import { defaultPasswordPolicy, Empty, ErrorBanner, Field, formatDate, formatRelative, Panel, PasswordRules, passwordRules, SkeletonRows, useFeedback, useResource } from '../ui';

const serviceLabels: Record<string, string> = {
  smtpd: 'SMTP ingress & submission',
  imapd: 'IMAP access',
  outbound: 'Outbound delivery',
  web: 'Admin console',
  webmail: 'Webmail',
  classifier: 'Mail organization',
};

const checkOrder: Record<ReadinessCheck['status'], number> = { error: 0, ok: 1, skipped: 2 };

export function AdminCredentialsForm({ session, onChanged, setup }: { session: Session; onChanged: (user: string) => void; setup?: boolean }) {
  const { run } = useFeedback();
  const [username, setUsername] = useState(session.user || 'admin');
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirmNext, setConfirmNext] = useState('');
  const mismatch = confirmNext !== '' && next !== confirmNext;
  const rules = passwordRules(session.password_policy ?? defaultPasswordPolicy, username, next);
  const valid = rules.every((rule) => rule.met) && next === confirmNext && username.trim() !== '';

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!valid) return;
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
      <Field label="New password" hint={<>{!setup && 'Changing it signs out other admin sessions. '}The policy is set under Settings → Authentication.</>}>
        <input type="password" value={next} onChange={(event) => setNext(event.target.value)} autoComplete="new-password" required />
      </Field>
      {next !== '' && <PasswordRules rules={rules} />}
      <Field label="Repeat new password" hint={mismatch ? <span className="errorText">Passwords do not match</span> : undefined}><input type="password" value={confirmNext} onChange={(event) => setConfirmNext(event.target.value)} autoComplete="new-password" required /></Field>
      <button className="button primary" disabled={!valid}><KeyRound size={16} />{setup ? 'Create admin account' : 'Update credentials'}</button>
    </form>
  );
}

export function SystemPage({ session, onSessionChange }: { session: Session; onSessionChange: (session: Session) => void }) {
  const ready = useResource(readiness, [], 60000);
  const settings = useResource(() => api<SettingsView>('/api/settings'), [], 30000, 'settings');
  const view = settings.data;
  const services = view && view.managed ? view.services : [];
  const checks = Object.entries(ready.data?.checks || {}).sort(([a, x], [b, y]) => checkOrder[x.status] - checkOrder[y.status] || a.localeCompare(b));
  const failing = checks.filter(([, check]) => check.status === 'error').length;

  return (
    <div className="systemPage">
      <div className="systemHero">
        <div>
          <span className={`statusDot ${!ready.data ? 'off' : ready.data.ready ? 'ok' : 'error'}`} />
          <strong>{ready.data ? (ready.data.ready ? 'All required dependencies ready' : `${failing || 'A'} readiness check${failing === 1 ? '' : 's'} failing`) : 'Checking…'}</strong>
          <p>Readiness is evaluated by the admin daemon against live storage, network and security settings.</p>
        </div>
        <button className="button" onClick={() => ready.reload()} disabled={ready.loading}><RefreshCw size={16} className={ready.loading ? 'spin' : ''} />Run checks</button>
      </div>

      <section className="grid systemDetails">
        <Panel title="Readiness checks" subtitle={ready.data ? `${checks.filter(([, check]) => check.status === 'ok').length} of ${checks.length} operational` : undefined}>
          <ErrorBanner error={ready.error} />
          <div className="checkList">
            {checks.map(([name, check]) => (
              <div className={`checkRow ${check.status}`} key={name}>
                <span className={`statusDot ${check.status}`} />
                <div>
                  <strong>{name.replaceAll('_', ' ')}</strong>
                  {check.status === 'error' && <p className="errorText">{check.error || 'The readiness probe reported a failure.'}</p>}
                  {check.status === 'skipped' && <p>Optional; not configured.</p>}
                </div>
                <span className={`statusBadge ${check.status}`}>{check.status === 'ok' ? 'ok' : check.status === 'skipped' ? 'off' : 'failing'}</span>
              </div>
            ))}
            {!ready.data && !ready.error && <Empty>Running checks…</Empty>}
          </div>
        </Panel>
        <Panel title="Admin account" subtitle={session.user ? `Signed in as ${session.user}` : undefined}>
          {session.settings_managed
            ? <AdminCredentialsForm session={session} onChanged={(user) => onSessionChange({ ...session, user, authenticated: true, setup_required: false })} />
            : <Empty>Admin credentials come from <code>web_admin_user</code> and <code>web_admin_password_hash</code> in the configuration file.</Empty>}
        </Panel>
      </section>

      <Panel title="Services" subtitle="Last start recorded by each daemon">
        <ErrorBanner error={settings.error} />
        <div className="tableScroll">
          <table>
            <thead><tr><th>Service</th><th>Started</th><th>Process</th><th>Settings</th></tr></thead>
            <tbody>
              {!view && !settings.error && <SkeletonRows rows={3} cols={4} />}
              {services.map((service) => (
                <tr key={service.service}>
                  <td><strong>{serviceLabels[service.service] || service.service}</strong><small><code>{service.service}</code></small></td>
                  <td className="nowrap" title={formatDate(service.started_at)}>{formatRelative(service.started_at)}</td>
                  <td className="nowrap">pid {service.pid}{service.host ? <span className="muted"> · {service.host}</span> : null}</td>
                  <td>{service.restart_required
                    ? <span className="pill warn" title={service.pending_changes.join(', ')}>Restart needed</span>
                    : <span className="pill ok">Current · rev {service.settings_revision}</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {view && !services.length && <Empty>{!view.managed ? 'Service tracking needs a settings database (db_path).' : 'No service has recorded a start yet.'}</Empty>}
      </Panel>

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
