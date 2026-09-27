import { useState } from 'react';
import { ArrowUpToLine, RotateCcw, Trash2, Wand2 } from 'lucide-react';
import { api, DmarcRow, QueueItem, QueueSummary, Spool } from '../api';
import { Empty, ErrorBanner, formatRelative, numberFmt, Panel, useFeedback, useResource } from '../ui';

const spools: { id: Spool; label: string; help: string }[] = [
  { id: 'queue', label: 'Queued', help: 'Waiting for the next delivery attempt' },
  { id: 'inflight', label: 'In flight', help: 'Currently owned by a delivery worker' },
  { id: 'failed', label: 'Failed', help: 'Gave up after the retry limit; requeue to try again' },
  { id: 'sent', label: 'Sent', help: 'Retained copies of delivered messages' },
];

type Action = 'requeue' | 'promote' | 'delete';

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
            <thead><tr><th>Message</th><th>Attempts</th><th>Priority</th><th>Next attempt</th><th>Last error</th><th /></tr></thead>
            <tbody>
              {entries.map((item) => (
                <tr key={item.name}>
                  <td className="queueNameCell"><code title={item.name}>{item.name}</code></td>
                  <td>{item.control?.attempts ?? 0}{item.control?.max_attempts ? ` / ${item.control.max_attempts}` : ''}</td>
                  <td>{item.control?.priority ?? 0}</td>
                  <td title={item.control?.next_try ? new Date(item.control.next_try * 1000).toLocaleString() : ''}>{item.control?.next_try ? formatRelative(item.control.next_try) : 'now'}</td>
                  <td className="muted"><span className="clampText" title={item.control?.last_error || undefined}>{item.control?.last_error || '—'}</span></td>
                  <td className="rowActions">
                    {spool !== 'inflight' && <button className="iconButton" title="Requeue now (resets attempts)" onClick={() => act('requeue', { name: item.name })}><RotateCcw size={15} /></button>}
                    {spool === 'queue' && <button className="iconButton" title="Promote (deliver first)" onClick={() => act('promote', { name: item.name })}><ArrowUpToLine size={15} /></button>}
                    {spool !== 'inflight' && <button className="iconButton danger" title="Delete" onClick={() => act('delete', { name: item.name })}><Trash2 size={15} /></button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!listing.loading && entries.length === 0 && <Empty>No messages in this spool.</Empty>}
      </Panel>

      <section className="grid">
        <Panel title="Bulk actions" subtitle="Apply an action to every spool entry whose name matches a pattern (* wildcards).">
          <form className="queueTools" onSubmit={(event) => { event.preventDefault(); }}>
            <input value={pattern} onChange={(event) => setPattern(event.target.value)} placeholder="e.g. 1714*" />
            <button type="button" className="button" disabled={!pattern.trim()} onClick={() => act('requeue', { pattern: pattern.trim() })}><RotateCcw size={16} />Requeue</button>
            <button type="button" className="button" disabled={!pattern.trim()} onClick={() => act('promote', { pattern: pattern.trim() })}><Wand2 size={16} />Promote</button>
            <button type="button" className="button danger" disabled={!pattern.trim()} onClick={() => act('delete', { pattern: pattern.trim() })}><Trash2 size={16} />Delete</button>
          </form>
        </Panel>
        <Panel title="DMARC reports" subtitle="Domains with events not yet reported">
          <div className="metricList">{dmarc.data?.length ? dmarc.data.map((row) => <div className="metric" key={row.domain}><span>{row.domain}</span><strong>{row.events} events</strong></div>) : <Empty>No unreported DMARC events.</Empty>}</div>
        </Panel>
      </section>
    </>
  );
}
