import React from 'react';
import { AlertTriangle, CheckCircle2, HardDrive, LockKeyhole, RefreshCw, Send, Users } from 'lucide-react';
import { api, Certificates, Overview, readiness, SettingsView, Stats } from '../api';
import { Empty, ErrorBanner, formatBytes, numberFmt, Panel, plural, useResource } from '../ui';
import type { Page } from '../main';

type Tone = 'ok' | 'warn' | 'error';

function Kpi({ label, value, detail, icon: Icon, tone, onClick }: { label: string; value: string; detail: string; icon: React.ElementType; tone?: Tone; onClick: () => void }) {
  return (
    <button type="button" className={`kpi ${tone && tone !== 'ok' ? tone : ''}`} onClick={onClick}>
      <div><span>{label}</span><strong>{value}</strong></div>
      <Icon size={22} aria-hidden="true" />
      <small>{detail}</small>
    </button>
  );
}

export function BarRow({ label, value, max, detail, tone }: { label: string; value: number; max: number; detail: string; tone?: Tone }) {
  const width = max > 0 && value > 0 ? Math.max(4, Math.round((value / max) * 100)) : 0;
  return <div className={`barRow ${tone || ''}`}><div><span title={label}>{label}</span><strong>{numberFmt.format(value)}</strong></div><div className="barTrack"><i style={{ width: `${width}%` }} /></div><small>{detail}</small></div>;
}

function daysLeft(epochSeconds: number): number {
  return Math.floor((epochSeconds - Date.now() / 1000) / 86400);
}

type Attention = { key: string; tone: 'warn' | 'error'; text: React.ReactNode; page: Page };

export function OverviewPage({ navigate }: { navigate: (page: Page) => void }) {
  const overview = useResource(() => api<Overview>('/api/overview'), [], 30000);
  const stats = useResource(() => api<Stats>('/stats'), [], 30000);
  const ready = useResource(readiness, [], 60000);
  const settings = useResource(() => api<SettingsView>('/api/settings').catch(() => null), [], 60000, 'settings');
  const certs = useResource(() => api<Certificates>('/api/certificates').catch(() => null), [], 300000);

  const data = overview.data;
  const queue = data?.queue;
  const cert = certs.data?.certificate ?? null;
  const certDays = cert ? daysLeft(cert.not_after) : null;

  const attention: Attention[] = [];
  if (queue && queue.failed > 0) attention.push({ key: 'failed', tone: 'error', text: <>{plural(queue.failed, 'outbound message')} failed permanently</>, page: 'delivery' });
  if (queue && queue.queued > 25) attention.push({ key: 'backlog', tone: 'warn', text: <>{numberFmt.format(queue.queued)} messages are waiting for delivery</>, page: 'delivery' });
  for (const [name, check] of Object.entries(ready.data?.checks || {})) {
    if (check.status === 'error') attention.push({ key: `ready-${name}`, tone: 'error', text: <>{name.replaceAll('_', ' ')} check failing: {check.error}</>, page: 'system' });
  }
  const view = settings.data;
  if (view) {
    for (const service of view.services.filter((item) => item.restart_required)) {
      attention.push({ key: `restart-${service.service}`, tone: 'warn', text: <>Restart <code>{service.service}</code> to apply {plural(service.pending_changes.length, 'changed setting')}</>, page: 'settings' });
    }
  }
  if (certs.data) {
    if (!cert) attention.push({ key: 'cert-missing', tone: 'error', text: <>No TLS certificate is installed</>, page: 'certificates' });
    else if (certDays !== null && certDays < 14) attention.push({ key: 'cert-expiry', tone: certDays < 7 ? 'error' : 'warn', text: certDays < 0 ? <>The TLS certificate has expired</> : <>The TLS certificate expires in {plural(certDays, 'day')}</>, page: 'certificates' });
    else if (cert.self_signed) attention.push({ key: 'cert-self-signed', tone: 'warn', text: <>The TLS certificate is self-signed; mail clients will warn about it</>, page: 'certificates' });
    if (certs.data.enabled && certs.data.status.consecutive_failures > 0) attention.push({ key: 'cert-renewal', tone: 'warn', text: <>Certificate renewal has failed {plural(certs.data.status.consecutive_failures, 'time')} in a row</>, page: 'certificates' });
  }
  for (const mailbox of data?.near_quota || []) {
    const percent = Math.round((mailbox.used_bytes / mailbox.quota_bytes) * 100);
    attention.push({ key: `quota-${mailbox.address}`, tone: percent >= 100 ? 'error' : 'warn', text: <><strong>{mailbox.address}</strong> is at {percent}% of its {formatBytes(mailbox.quota_bytes)} quota</>, page: 'accounts' });
  }

  const domainMax = Math.max(0, ...(data?.domains.map((domain) => domain.messages) || []));
  const mailboxMax = Math.max(0, ...(data?.top_mailboxes.map((mailbox) => mailbox.messages) || []));
  const queueMax = Math.max(1, ...(queue ? [queue.queued, queue.inflight, queue.sent, queue.failed] : [0]));
  const loading = (value: number | undefined, format: (n: number) => string = numberFmt.format) => (value === undefined ? '—' : format(value));

  return (
    <>
      <ErrorBanner error={overview.error} />
      <section className="kpis">
        <Kpi label="Mailboxes" value={loading(data?.accounts ?? stats.data?.mailboxes)} detail={data ? `${plural(data.total_messages, 'message')}, ${numberFmt.format(data.unseen_messages)} unseen` : 'Loading…'} icon={Users} onClick={() => navigate('accounts')} />
        <Kpi label="Storage used" value={loading(data?.used_bytes, formatBytes)} detail={data ? (data.near_quota.length ? `${plural(data.near_quota.length, 'mailbox', 'mailboxes')} near quota` : `${plural(data.folders, 'folder')} across all mailboxes`) : 'Loading…'} tone={data?.near_quota.length ? 'warn' : undefined} icon={HardDrive} onClick={() => navigate('accounts')} />
        <Kpi label="Outbound pending" value={loading(queue?.queued ?? stats.data?.outbound_pending)} detail={queue ? `${numberFmt.format(queue.inflight)} in flight, ${numberFmt.format(queue.failed)} failed · ${numberFmt.format(stats.data?.delivered_count || 0)} delivered` : 'Loading…'} tone={queue?.failed ? 'error' : undefined} icon={Send} onClick={() => navigate('delivery')} />
        <Kpi
          label="TLS certificate"
          value={!certs.data ? '—' : certDays === null ? 'None' : certDays < 0 ? 'Expired' : `${certDays} days`}
          detail={!certs.data ? (certs.loading ? 'Loading…' : 'Unavailable') : !cert ? 'Clients connect without encryption' : cert.self_signed ? 'Self-signed' : certs.data.enabled ? 'Renews automatically' : `Issued by ${cert.issuer}`}
          tone={!certs.data ? undefined : certDays === null || certDays < 7 ? 'error' : certDays < 21 || cert?.self_signed ? 'warn' : 'ok'}
          icon={LockKeyhole}
          onClick={() => navigate('certificates')}
        />
      </section>

      <Panel title="Needs attention" subtitle="Problems that need an operator" actions={ready.loading || overview.loading ? <RefreshCw size={16} className="spin muted" aria-label="Refreshing" /> : undefined}>
        {attention.length ? (
          <ul className="attentionList">
            {attention.map((item) => (
              <li key={item.key} className={item.tone}>
                <AlertTriangle size={16} aria-label={item.tone === 'error' ? 'Error' : 'Warning'} />
                <span>{item.text}</span>
                <button className="linkButton" onClick={() => navigate(item.page)}>Open</button>
              </li>
            ))}
          </ul>
        ) : data && ready.data ? (
          <div className="allClear"><CheckCircle2 size={20} /> Everything looks healthy.</div>
        ) : (
          <Empty>Checking…</Empty>
        )}
      </Panel>

      <section className="grid">
        <Panel title="Domains" subtitle={data ? `${plural(data.domains.length, 'domain')} by stored messages` : 'Loading'}>
          <div className="barList">{data?.domains.length ? data.domains.slice(0, 8).map((domain) => <BarRow key={domain.domain} label={domain.domain} value={domain.messages} max={domainMax} detail={`${plural(domain.accounts, 'mailbox', 'mailboxes')}, ${numberFmt.format(domain.unseen)} unseen`} />) : data ? <Empty>No domain activity yet.</Empty> : null}</div>
        </Panel>
        <Panel title="Outbound queue" subtitle="Messages in each spool">
          <div className="barList">
            {queue && <>
              <BarRow label="Queued" value={queue.queued} max={queueMax} detail="Waiting for delivery" tone={queue.queued > 25 ? 'warn' : undefined} />
              <BarRow label="In flight" value={queue.inflight} max={queueMax} detail="Owned by a worker" />
              <BarRow label="Failed" value={queue.failed} max={queueMax} detail={queue.failed ? 'Needs action' : 'Nothing has failed'} tone={queue.failed ? 'error' : undefined} />
              <BarRow label="Sent" value={queue.sent} max={queueMax} detail="Retained sent spool" />
            </>}
          </div>
          {data && (
            <div className="panelLinks">
              <span><strong>{numberFmt.format(data.aliases)}</strong> {data.aliases === 1 ? 'alias' : 'aliases'}</span>
              <span><strong>{numberFmt.format(data.catchalls)}</strong> {data.catchalls === 1 ? 'catchall' : 'catchalls'}</span>
              <button className="linkButton" onClick={() => navigate('routing')}>Manage routing</button>
            </div>
          )}
        </Panel>
        <Panel title="Busiest mailboxes" subtitle={data ? `Top ${data.top_mailboxes.length} by stored messages` : 'Loading'} className="wide">
          <div className="barList twoCol">{data?.top_mailboxes.length ? data.top_mailboxes.map((mailbox) => <BarRow key={mailbox.address} label={mailbox.address} value={mailbox.messages} max={mailboxMax} detail={`${plural(mailbox.folders, 'folder')}, ${numberFmt.format(mailbox.unseen)} unseen`} />) : data ? <Empty>No mailbox messages found.</Empty> : null}</div>
        </Panel>
      </section>
    </>
  );
}
