import React from 'react';
import { AlertTriangle, BarChart3, CheckCircle2, Mail, RefreshCw, Send, Server, Users } from 'lucide-react';
import { api, Overview, readiness, SettingsView, Stats } from '../api';
import { Empty, ErrorBanner, numberFmt, Panel, useResource } from '../ui';
import type { Page } from '../main';

function Kpi({ label, value, detail, icon: Icon }: { label: string; value: string; detail: string; icon: React.ElementType }) {
  return <section className="kpi"><div><span>{label}</span><strong>{value}</strong></div><Icon size={22} /><small>{detail}</small></section>;
}

export function BarRow({ label, value, max, detail }: { label: string; value: number; max: number; detail: string }) {
  const width = max > 0 ? Math.max(4, Math.round((value / max) * 100)) : 0;
  return <div className="barRow"><div><span>{label}</span><strong>{numberFmt.format(value)}</strong></div><div className="barTrack"><i style={{ width: `${width}%` }} /></div><small>{detail}</small></div>;
}

type Attention = { key: string; tone: 'warn' | 'error'; text: React.ReactNode; page: Page };

export function OverviewPage({ navigate }: { navigate: (page: Page) => void }) {
  const overview = useResource(() => api<Overview>('/api/overview'), [], 30000);
  const stats = useResource(() => api<Stats>('/stats'), [], 30000);
  const ready = useResource(readiness, [], 60000);
  const settings = useResource(() => api<SettingsView>('/api/settings').catch(() => null), [], 60000);

  const data = overview.data;
  const queue = data?.queue;
  const attention: Attention[] = [];
  if (queue && queue.failed > 0) attention.push({ key: 'failed', tone: 'error', text: <>{queue.failed} outbound message{queue.failed === 1 ? '' : 's'} failed permanently</>, page: 'delivery' });
  if (queue && queue.queued > 25) attention.push({ key: 'backlog', tone: 'warn', text: <>{queue.queued} messages are waiting for delivery</>, page: 'delivery' });
  for (const [name, check] of Object.entries(ready.data?.checks || {})) {
    if (check.status === 'error') attention.push({ key: `ready-${name}`, tone: 'error', text: <>{name.replaceAll('_', ' ')} check failing: {check.error}</>, page: 'system' });
  }
  const view = settings.data;
  if (view && view.managed) {
    for (const service of view.services.filter((item) => item.restart_required)) {
      attention.push({ key: `restart-${service.service}`, tone: 'warn', text: <>Restart <code>{service.service}</code> to apply {service.pending_changes.length} changed setting{service.pending_changes.length === 1 ? '' : 's'}</>, page: 'settings' });
    }
  }

  const domainMax = Math.max(0, ...(data?.domains.map((domain) => domain.messages) || []));
  const mailboxMax = Math.max(0, ...(data?.top_mailboxes.map((mailbox) => mailbox.messages) || []));
  const queueMax = Math.max(1, ...(queue ? [queue.queued, queue.inflight, queue.sent, queue.failed] : [0]));

  return (
    <>
      <ErrorBanner error={overview.error} />
      <section className="kpis">
        <Kpi label="Mailboxes" value={numberFmt.format(data?.accounts ?? stats.data?.mailboxes ?? 0)} detail={`${data?.folders ?? 0} folders tracked`} icon={Users} />
        <Kpi label="Stored messages" value={numberFmt.format(data?.total_messages ?? stats.data?.total_messages ?? 0)} detail={`${numberFmt.format(data?.unseen_messages ?? 0)} unseen`} icon={Mail} />
        <Kpi label="Delivered" value={numberFmt.format(stats.data?.delivered_count || 0)} detail="Since the counter was last reset" icon={Send} />
        <Kpi label="Outbound pending" value={numberFmt.format(queue?.queued ?? stats.data?.outbound_pending ?? 0)} detail={`${queue?.inflight || 0} in flight, ${queue?.failed || 0} failed`} icon={Server} />
      </section>

      <Panel title="Needs attention" subtitle="Problems that need an operator" actions={ready.loading ? <RefreshCw size={16} className="spin" /> : undefined}>
        {attention.length ? (
          <ul className="attentionList">
            {attention.map((item) => (
              <li key={item.key} className={item.tone}>
                <AlertTriangle size={16} />
                <span>{item.text}</span>
                <button className="linkButton" onClick={() => navigate(item.page)}>Open</button>
              </li>
            ))}
          </ul>
        ) : (
          <div className="allClear"><CheckCircle2 size={20} /> Everything looks healthy.</div>
        )}
      </Panel>

      <section className="grid analytics">
        <Panel title="Domain distribution" subtitle={data ? `${data.domains.length} domains` : 'Loading'}>
          <div className="barList">{data?.domains.length ? data.domains.slice(0, 8).map((domain) => <BarRow key={domain.domain} label={domain.domain} value={domain.messages} max={domainMax} detail={`${domain.accounts} accounts, ${domain.unseen} unseen`} />) : <Empty>No domain activity yet.</Empty>}</div>
        </Panel>
        <Panel title="Delivery pipeline" actions={<BarChart3 size={18} />}>
          <div className="snapshotGrid">
            <div><span>Aliases</span><strong>{numberFmt.format(data?.aliases || 0)}</strong></div>
            <div><span>Catchalls</span><strong>{numberFmt.format(data?.catchalls || 0)}</strong></div>
            <div><span>Unread</span><strong>{numberFmt.format(data?.unseen_messages || 0)}</strong></div>
            <div><span>Folders</span><strong>{numberFmt.format(data?.folders || 0)}</strong></div>
          </div>
          <div className="barList compact">
            {queue && <>
              <BarRow label="Queued" value={queue.queued} max={queueMax} detail="waiting for delivery" />
              <BarRow label="In flight" value={queue.inflight} max={queueMax} detail="owned by a worker" />
              <BarRow label="Sent" value={queue.sent} max={queueMax} detail="retained sent spool" />
              <BarRow label="Failed" value={queue.failed} max={queueMax} detail="needs action" />
            </>}
          </div>
        </Panel>
        <Panel title="Busiest mailboxes" subtitle={data ? `${data.top_mailboxes.length} busiest` : 'Loading'} className="wide">
          <div className="barList twoCol">{data?.top_mailboxes.length ? data.top_mailboxes.map((mailbox) => <BarRow key={mailbox.address} label={mailbox.address} value={mailbox.messages} max={mailboxMax} detail={`${mailbox.folders} folders, ${mailbox.unseen} unseen`} />) : <Empty>No mailbox messages found.</Empty>}</div>
        </Panel>
      </section>
    </>
  );
}
