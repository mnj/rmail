import { useState } from 'react';
import { ArrowUpToLine, RefreshCw, RotateCcw, Trash2, Wand2 } from 'lucide-react';
import { api, BlocklistResult, DmarcRow, DnsChecks, DnsStatus, OutboundAddress, QueueItem, QueueSummary, Reach, Spool } from '../api';
import { FeedbackPanel } from './FeedbackReports';
import { Empty, ErrorBanner, formatRelative, IconButton, invalidate, numberFmt, Panel, SkeletonRows, useFeedback, useResource } from '../ui';

const spools: { id: Spool; label: string; help: string }[] = [
  { id: 'queue', label: 'Queued', help: 'Waiting for the next delivery attempt' },
  { id: 'inflight', label: 'In flight', help: 'Currently owned by a delivery worker' },
  { id: 'failed', label: 'Failed', help: 'Gave up after the retry limit; requeue to try again' },
  { id: 'sent', label: 'Sent', help: 'Retained copies of delivered messages' },
];

type Action = 'requeue' | 'promote' | 'delete';

function ReachRow({ label, reach }: { label: string; reach: Reach }) {
  const [tone, text, note] =
    reach.state === 'open' ? ['ok', 'Open', `Reached ${reach.target}`]
    : reach.state === 'blocked' ? ['error', 'Blocked', reach.error]
    : reach.state === 'unavailable' ? ['', 'Not in use', 'This server has no connectivity of this kind']
    : ['', 'Not checked', reach.error];
  return <div className="metric"><span>{label}<small>{note}</small></span><strong><span className={`pill ${tone}`}>{text}</span></strong></div>;
}

const sourceLabel: Record<OutboundAddress['source'], string> = {
  seen: 'As the receiving server saw it',
  local: "This server's own address",
  dns: "From the host name's DNS record",
};
const reverseLabel: Record<DnsStatus, [string, string]> = {
  ok: ['ok', 'OK'], improve: ['warn', 'Can improve'], missing: ['error', 'Missing'], different: ['error', 'Wrong'], problem: ['error', 'Problem'], unknown: ['', 'Not checked'],
};
const listTone: Record<BlocklistResult['status'], string> = { clean: 'ok', listed: 'error', unknown: '' };

/** How the server looks from outside: can it reach port 25, and is its address trusted. */
function DeliverabilityPanel() {
  const { run } = useFeedback();
  const dns = useResource(() => api<DnsChecks>('/api/dns-checks'), [], 300000, 'dns-checks');
  const [rechecking, setRechecking] = useState(false);
  const checking = dns.loading || rechecking;
  const outbound = dns.data?.outbound;

  async function recheck() {
    setRechecking(true);
    await run(async () => dns.setData(await api<DnsChecks>('/api/dns-checks', 'POST')), 'Checked again');
    setRechecking(false);
  }

  return (
    <Panel
      title="Deliverability"
      subtitle={dns.data ? `How this server looks to the servers it sends to · checked ${formatRelative(dns.data.checked_at)}` : 'How this server looks to the servers it sends to'}
      actions={<button className="button" onClick={recheck} disabled={checking}><RefreshCw size={16} className={checking ? 'spin' : undefined} />Check again</button>}
    >
      {!dns.data ? <Empty>{dns.error ? `Could not be checked: ${dns.error}` : 'Checking…'}</Empty>
        : !outbound ? <Empty>Outgoing mail leaves through the smarthost, so receivers see its address rather than this server's. There is nothing to check here.</Empty>
        : (
          <>
            <div className="metricList">
              <ReachRow label="Port 25 over IPv4" reach={outbound.port25.v4} />
              <ReachRow label="Port 25 over IPv6" reach={outbound.port25.v6} />
            </div>
            {outbound.addresses.length > 0 ? (
              <div className="tableScroll">
                <table className="outboundTable">
                  <thead><tr><th>Sending address</th><th>Reverse DNS</th><th>Blocklists</th></tr></thead>
                  <tbody>
                    {outbound.addresses.map((entry) => {
                      const [tone, label] = reverseLabel[entry.reverse.status];
                      const listed = entry.blocklists.filter((list) => list.status === 'listed');
                      return (
                        <tr key={entry.address}>
                          <td><code>{entry.address}</code><small>{sourceLabel[entry.source]}</small></td>
                          <td>
                            <span className={`pill ${tone}`}>{label}</span>
                            {entry.reverse.names.map((name) => <code key={name} className="ptrName">{name}</code>)}
                            {entry.reverse.detail && <small>{entry.reverse.detail}</small>}
                          </td>
                          <td>
                            <div className="tagList">{entry.blocklists.map((list) => <span key={list.zone} className={`pill ${listTone[list.status]}`} title={list.detail || list.zone}>{list.name}: {list.status === 'clean' ? 'not listed' : list.status === 'listed' ? 'listed' : 'not checked'}</span>)}</div>
                            {listed.map((list) => <small key={list.zone}>{list.detail}</small>)}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            ) : <p className="panelNote">The address this server sends from could not be determined, so its reverse DNS and reputation were not checked.</p>}
          </>
        )}
    </Panel>
  );
}

export function DeliveryPage() {
  const { run, confirm } = useFeedback();
  const [spool, setSpool] = useState<Spool>('queue');
  const [pattern, setPattern] = useState('');
  const summary = useResource(() => api<QueueSummary>('/api/queue/summary'), [], 15000);
  const listing = useResource(() => api<{ entries: QueueItem[] }>(`/api/queue?spool=${spool}`), [spool], 15000);
  const dmarc = useResource(() => api<DmarcRow[]>('/dmarc').catch(() => [] as DmarcRow[]), []);

  const refresh = () => {
    summary.reload();
    listing.reload();
    invalidate('queue');
  };

  async function act(action: Action, target: { name: string } | { pattern: string }) {
    const label = 'name' in target ? target.name : `messages matching “${target.pattern}”`;
    if (action === 'delete' && !await confirm({ title: 'Delete messages?', message: <>Permanently delete {label}? This cannot be undone.</>, confirmLabel: 'Delete', danger: true })) return;
    if ('pattern' in target && action !== 'delete' && !await confirm({ title: `${action === 'requeue' ? 'Requeue' : 'Promote'} messages?`, message: <>Apply to every spool entry matching “{target.pattern}”.</>, confirmLabel: 'Apply' })) return;
    const verb = action === 'requeue' ? 'Requeued' : action === 'promote' ? 'Promoted' : 'Deleted';
    await run(async () => {
      const result = await api<{ affected?: number }>('/api/queue/action', 'POST', { action, ...target, priority: action === 'promote' ? 10 : undefined });
      return result;
    }, `${verb} ${label}`);
    refresh();
  }

  const entries = listing.data?.entries || [];
  const counts: Record<Spool, number> = { queue: summary.data?.queued ?? 0, inflight: summary.data?.inflight ?? 0, failed: summary.data?.failed ?? 0, sent: summary.data?.sent ?? 0 };

  return (
    <>
      <ErrorBanner error={listing.error || summary.error} />
      <Panel
        title="Outbound queue"
        subtitle={spools.find((item) => item.id === spool)?.help}
        actions={<div className="tabs">{spools.map((item) => <button key={item.id} className={spool === item.id ? 'active' : ''} onClick={() => setSpool(item.id)}>{item.label}<small>{numberFmt.format(counts[item.id])}</small></button>)}</div>}
      >
        <div className="tableScroll">
          <table className="queueTable">
            <colgroup><col className="queueName" /><col className="queueNum" /><col className="queueNum" /><col className="queueNext" /><col className="queueError" /><col className="queueActions" /></colgroup>
            <thead><tr><th>Message</th><th className="num">Attempts</th><th className="num">Priority</th><th>Next attempt</th><th>Last error</th><th><span className="visuallyHidden">Actions</span></th></tr></thead>
            <tbody>
              {listing.data === null && !listing.error && <SkeletonRows cols={6} />}
              {entries.map((item) => (
                <tr key={item.name}>
                  <td className="queueNameCell"><code title={item.name}>{item.name}</code></td>
                  <td className="num">{item.control?.attempts ?? 0}{item.control?.max_attempts ? ` / ${item.control.max_attempts}` : ''}</td>
                  <td className="num">{item.control?.priority ?? 0}</td>
                  <td className="nowrap" title={item.control?.next_try ? new Date(item.control.next_try * 1000).toLocaleString() : ''}>{item.control?.next_try ? formatRelative(item.control.next_try) : 'now'}</td>
                  <td className="muted"><span className="clampText" title={item.control?.last_error || undefined}>{item.control?.last_error || '—'}</span></td>
                  <td className="rowActions">
                    {spool !== 'inflight' && <IconButton label="Requeue now (resets attempts)" onClick={() => act('requeue', { name: item.name })}><RotateCcw size={15} /></IconButton>}
                    {spool === 'queue' && <IconButton label="Promote (deliver first)" onClick={() => act('promote', { name: item.name })}><ArrowUpToLine size={15} /></IconButton>}
                    {spool !== 'inflight' && <IconButton danger label="Delete" onClick={() => act('delete', { name: item.name })}><Trash2 size={15} /></IconButton>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {listing.data !== null && entries.length === 0 && <Empty>No messages in this spool.</Empty>}
      </Panel>

      <DeliverabilityPanel />

      <section className="grid">
        <Panel title="Bulk actions" subtitle="Apply an action to every spool entry whose name matches a pattern (* wildcards).">
          {/* Enter requeues: the one bulk action that never loses mail. It still asks first. */}
          <form className="queueTools" onSubmit={(event) => { event.preventDefault(); if (pattern.trim()) act('requeue', { pattern: pattern.trim() }); }}>
            <input value={pattern} onChange={(event) => setPattern(event.target.value)} placeholder="e.g. 1714*" aria-label="Spool entry name pattern" />
            <button type="submit" className="button" disabled={!pattern.trim()}><RotateCcw size={16} />Requeue</button>
            <button type="button" className="button" disabled={!pattern.trim()} onClick={() => act('promote', { pattern: pattern.trim() })}><Wand2 size={16} />Promote</button>
            <button type="button" className="button danger" disabled={!pattern.trim()} onClick={() => act('delete', { pattern: pattern.trim() })}><Trash2 size={16} />Delete</button>
          </form>
        </Panel>
        <Panel title="DMARC reports" subtitle="Domains with events not yet reported">
          <div className="metricList">{dmarc.data?.length ? dmarc.data.map((row) => <div className="metric" key={row.domain}><span>{row.domain}</span><strong>{row.events} events</strong></div>) : <Empty>No unreported DMARC events.</Empty>}</div>
        </Panel>
      </section>

      <FeedbackPanel />
    </>
  );
}
