import { useEffect, useState } from 'react';
import { AlertTriangle, FlaskConical, RefreshCw, Save, ServerCog, ShieldCheck } from 'lucide-react';
import { api, Certificates, Setting, SettingsView } from '../api';
import { Empty, ErrorBanner, formatDate, formatRelative, Panel, useFeedback, useResource } from '../ui';
import { RestartNotice, SettingControl } from './Settings';

type Drafts = Record<string, unknown>;

const caLabels: Record<string, string> = {
  letsencrypt: "Let's Encrypt",
  'letsencrypt-staging': "Let's Encrypt (staging, untrusted)",
  zerossl: 'ZeroSSL',
  custom: 'Custom ACME CA',
};

const providerLabels: Record<string, string> = {
  cloudflare: 'Cloudflare',
  digitalocean: 'DigitalOcean',
  desec: 'deSEC',
  gandi: 'Gandi LiveDNS',
  route53: 'Amazon Route 53',
  rfc2136: 'RFC 2136 (BIND, PowerDNS, Knot…)',
};

const choiceLabels: Record<string, Record<string, string>> = {
  'acme.ca': caLabels,
  'acme.dns.provider': providerLabels,
  'acme.challenge': { 'http-01': 'HTTP (http-01, port 80)', 'dns-01': 'DNS (dns-01, TXT record)' },
  'acme.dns.tsig_algorithm': { 'hmac-sha256': 'HMAC-SHA256', 'hmac-sha512': 'HMAC-SHA512' },
};

/** Which acme.* settings apply given the current choices. */
function visibleKeys(value: (key: string) => unknown): string[] {
  const keys = ['acme.enabled', 'acme.domains', 'acme.email', 'acme.ca'];
  const ca = value('acme.ca');
  if (ca === 'custom') keys.push('acme.directory_url');
  if (ca === 'custom' || ca === 'zerossl') keys.push('acme.eab_kid', 'acme.eab_hmac_key');
  keys.push('acme.challenge');
  if (value('acme.challenge') === 'dns-01') {
    keys.push('acme.dns.provider');
    const provider = value('acme.dns.provider');
    if (provider === 'route53') keys.push('acme.dns.aws_access_key_id', 'acme.dns.aws_secret_access_key');
    else if (provider === 'rfc2136') keys.push('acme.dns.rfc2136_server', 'acme.dns.tsig_key_name', 'acme.dns.tsig_secret', 'acme.dns.tsig_algorithm');
    else if (provider) keys.push('acme.dns.api_token');
    keys.push('acme.dns.zone', 'acme.dns.propagation_timeout_seconds');
  }
  return keys;
}

function daysLeft(notAfter: number): number {
  return Math.floor((notAfter - Date.now() / 1000) / 86400);
}

function CertificateSummary({ view }: { view: Certificates }) {
  const cert = view.certificate;
  if (!cert) {
    return <Empty>{view.certificate_error || 'No TLS certificate is installed. Mail clients and web browsers connect without encryption until one is.'}</Empty>;
  }
  const days = daysLeft(cert.not_after);
  const tone = days < 7 ? 'error' : days < 21 ? 'warn' : 'ok';
  return (
    <div className="certSummary">
      <div className="certNames">{cert.names.map((name) => <code key={name}>{name}</code>)}</div>
      <dl className="certFacts">
        <div><dt>Expires</dt><dd title={formatDate(cert.not_after)}><span className={`pill ${tone}`}>{days < 0 ? 'Expired' : `${days} days left`}</span> {formatDate(cert.not_after)}</dd></div>
        <div><dt>Issuer</dt><dd>{cert.self_signed ? 'Self-signed' : cert.issuer}</dd></div>
        <div><dt>Issued</dt><dd>{formatDate(cert.not_before)}</dd></div>
        <div><dt>Files</dt><dd><code>{view.cert_path}</code><br /><code>{view.key_path}</code></dd></div>
      </dl>
    </div>
  );
}

function RunLog({ view }: { view: Certificates }) {
  const run = view.status.last_run;
  if (!run) return <Empty>No certificate has been requested yet.</Empty>;
  const state = run.ok === null ? (view.running ? 'running' : 'interrupted') : run.ok ? 'succeeded' : 'failed';
  return (
    <>
      <div className="runHead">
        <span className={`statusBadge ${run.ok ? 'ok' : run.ok === null ? 'skipped' : ''}`}>{state}</span>
        <span>{run.dry_run ? 'Test run' : 'Certificate request'} · {run.trigger} · started {formatRelative(run.started_at)}</span>
      </div>
      {run.error && <div className="banner runError">{run.error}</div>}
      <div className="logView">
        {run.log.map((line, index) => (
          <div className={`logLine plain ${line.message.startsWith('Warning:') ? 'warn' : ''} ${line.message.startsWith('Failed:') ? 'error' : ''}`} key={index}>
            <time>{new Date(line.at * 1000).toLocaleTimeString()}</time> {line.message}
          </div>
        ))}
      </div>
    </>
  );
}

export function CertificatesPage() {
  const { run, confirm, notify } = useFeedback();
  const overview = useResource(() => api<Certificates>('/api/certificates'), [], 30000);
  const settingsView = useResource(() => api<SettingsView>('/api/settings'), []);
  const [drafts, setDrafts] = useState<Drafts>({});
  const [saving, setSaving] = useState(false);
  const view = overview.data;
  const running = Boolean(view?.running);

  // Follow a run while it is in progress; when it ends, a first certificate
  // may have pointed the TLS settings at new files, which needs a restart.
  useEffect(() => {
    if (!running) return;
    const id = window.setInterval(() => overview.reload(), 2000);
    return () => {
      window.clearInterval(id);
      settingsView.reload();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [running]);

  if (overview.error) return <ErrorBanner error={overview.error} />;
  if (!view) return <Empty>Loading certificates…</Empty>;
  if (!view.managed) {
    return (
      <article className="panel callout">
        <ServerCog size={28} />
        <div>
          <h2>Automatic certificates need the settings database</h2>
          <p>Set <code>db_path</code> in the configuration file to request and renew certificates from Let's Encrypt here.</p>
        </div>
      </article>
    );
  }

  const settings = settingsView.data && settingsView.data.managed ? settingsView.data.settings.filter((setting) => setting.group === 'acme') : [];
  const byKey = new Map(settings.map((setting) => [setting.key, setting]));
  const value = (key: string) => {
    if (key in drafts) return drafts[key] ?? byKey.get(key)?.default;
    const setting = byKey.get(key);
    return setting?.value ?? setting?.default;
  };
  const shown = visibleKeys(value).map((key) => byKey.get(key)).filter((setting): setting is Setting => Boolean(setting));
  const dirtyKeys = Object.keys(drafts);

  const change = (setting: Setting, next: unknown) => {
    setDrafts((current) => {
      const updated = { ...current };
      const original = setting.kind.type === 'secret' ? undefined : setting.value;
      if (JSON.stringify(next) === JSON.stringify(original) || (setting.kind.type === 'secret' && next === '')) delete updated[setting.key];
      else updated[setting.key] = next;
      return updated;
    });
  };

  async function save() {
    setSaving(true);
    const changes = Object.fromEntries(dirtyKeys.map((key) => [key, drafts[key]]));
    const ok = await run(async () => {
      const updated = await api<SettingsView>('/api/settings', 'PUT', { changes });
      settingsView.setData(updated);
      setDrafts({});
    }, 'Certificate settings saved');
    setSaving(false);
    if (ok) overview.reload();
  }

  async function issue(dryRun: boolean) {
    if (!dryRun && view?.renewal && !view.renewal.due) {
      const go = await confirm({
        title: 'Request a new certificate now?',
        message: <>The current certificate is not due for renewal yet ({view.renewal.reason}). CAs limit how many certificates you can request for the same names, so only do this after changing names or keys.</>,
        confirmLabel: 'Request now',
      });
      if (!go) return;
    }
    const ok = await run(() => api('/api/certificates/issue', 'POST', { dry_run: dryRun }));
    if (ok) {
      notify('info', dryRun ? 'Test run started' : 'Certificate request started');
      window.setTimeout(() => overview.reload(), 500);
    }
  }

  const renewal = view.renewal;
  const status = view.status;
  return (
    <div className="certificatesPage">
      <div className="systemHero">
        <div>
          <span className={`statusDot ${!view.certificate ? 'error' : view.enabled ? 'ok' : 'off'}`} />
          <strong>{view.enabled ? `Automatic certificates for ${view.names.join(', ') || '—'}` : 'Automatic certificates are off'}</strong>
          <p>
            {view.enabled
              ? renewal?.due ? `Renewal due: ${renewal.reason}.` : renewal?.reason
              : 'Turn them on below to get a free certificate from Let\'s Encrypt and renew it automatically.'}
            {status.retry_after && status.retry_after > Date.now() / 1000 && ` Retrying ${formatRelative(status.retry_after)} after ${status.consecutive_failures} failed attempt${status.consecutive_failures === 1 ? '' : 's'}.`}
          </p>
        </div>
        <div className="heroActions">
          <button className="button" onClick={() => issue(true)} disabled={running || dirtyKeys.length > 0} title={dirtyKeys.length ? 'Save your changes first' : 'Issue a test certificate without installing it'}><FlaskConical size={16} />Test</button>
          <button className="button primary" onClick={() => issue(false)} disabled={running || !view.enabled || dirtyKeys.length > 0} title={dirtyKeys.length ? 'Save your changes first' : undefined}><RefreshCw size={16} className={running ? 'spin' : ''} />{running ? 'Requesting…' : view.certificate ? 'Renew now' : 'Request certificate'}</button>
        </div>
      </div>

      {settingsView.data && <RestartNotice view={settingsView.data} onRestarted={settingsView.reload} />}
      {view.names_error && view.enabled && <div className="banner"><AlertTriangle size={16} /> {view.names_error}</div>}
      {view.warnings.map((warning) => (
        <div className="notice warn" key={warning}><AlertTriangle size={18} /><p>{warning}</p></div>
      ))}

      <section className="grid even">
        <Panel title="Installed certificate" subtitle="Shared by SMTP, IMAP, admin and webmail. Services reload it when the files change.">
          <CertificateSummary view={view} />
        </Panel>
        <Panel title="Last request" subtitle={status.last_success_at ? `Last successful renewal ${formatRelative(status.last_success_at)}` : undefined}>
          <RunLog view={view} />
        </Panel>
      </section>

      <Panel title="Configuration" subtitle="Changes apply to the next request; no restart needed." actions={<ShieldCheck size={18} className="muted" />}>
        <ErrorBanner error={settingsView.error} />
        <div className="settingRows">
          {shown.map((setting) => {
            const draft = setting.key in drafts;
            let help = setting.help;
            if (setting.key === 'acme.challenge' && value('acme.challenge') === 'http-01') {
              help = view.http_listeners.length
                ? `${help} Plain HTTP is served on ${view.http_listeners.join(', ')}.`
                : `${help} No plain HTTP listener is configured (Settings → Listeners → Plain HTTP).`;
            }
            const domains = value('acme.domains');
            if (setting.key === 'acme.domains' && (!Array.isArray(domains) || domains.length === 0)) {
              help = `${help} Currently: ${view.names.join(', ') || 'the system hostname'}.`;
            }
            return (
              <div className={`settingRow ${draft ? 'dirty' : ''}`} key={setting.key}>
                <div className="settingInfo">
                  <strong>{setting.label}{draft && <span className="badge dirty">unsaved</span>}</strong>
                  {help && <p>{help}</p>}
                </div>
                <div className="settingControl">
                  <SettingControl setting={setting} value={draft ? (drafts[setting.key] ?? undefined) : (setting.value ?? undefined)} onChange={(next) => change(setting, next)} labels={choiceLabels[setting.key]} />
                  {draft && <button className="linkButton" onClick={() => setDrafts((all) => { const next = { ...all }; delete next[setting.key]; return next; })}>Undo</button>}
                </div>
              </div>
            );
          })}
        </div>
      </Panel>

      {dirtyKeys.length > 0 && (
        <div className="saveBar">
          <span><strong>{dirtyKeys.length}</strong> unsaved change{dirtyKeys.length === 1 ? '' : 's'}</span>
          <button className="button" onClick={() => setDrafts({})} disabled={saving}>Discard</button>
          <button className="button primary" onClick={save} disabled={saving}><Save size={16} />{saving ? 'Saving…' : 'Save changes'}</button>
        </div>
      )}
    </div>
  );
}
