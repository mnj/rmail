import { useEffect, useMemo, useRef, useState } from 'react';
import { RefreshCw, Search } from 'lucide-react';
import { apiText } from '../api';
import { Empty, ErrorBanner, Panel, useResource } from '../ui';

const components = ['smtpd', 'imapd', 'outbound', 'web', 'webmail'];

export function ObservabilityPage() {
  const [component, setComponent] = useState('smtpd');
  const [lines, setLines] = useState(300);
  const [logFilter, setLogFilter] = useState('');
  const [metricFilter, setMetricFilter] = useState('');
  const logs = useResource(() => apiText(`/logs?component=${component}&lines=${lines}`), [component, lines], 15000);
  const metrics = useResource(() => apiText('/metrics'), [], 30000);
  const logRef = useRef<HTMLPreElement>(null);

  const logText = useMemo(() => {
    const text = logs.data || '';
    if (!logFilter.trim()) return text;
    const needle = logFilter.toLowerCase();
    return text.split('\n').filter((line) => line.toLowerCase().includes(needle)).join('\n');
  }, [logs.data, logFilter]);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logText]);

  const samples = useMemo(() => {
    const needle = metricFilter.toLowerCase();
    return (metrics.data || '')
      .split('\n')
      .filter((line) => line && !line.startsWith('#'))
      .filter((line) => !needle || line.toLowerCase().includes(needle))
      .map((line) => {
        const index = line.lastIndexOf(' ');
        return { name: line.slice(0, index), value: line.slice(index + 1) };
      });
  }, [metrics.data, metricFilter]);

  return (
    <>
      <Panel
        title="Daemon logs"
        subtitle="Newest lines at the bottom; refreshes every 15 seconds"
        actions={<>
          <div className="tabs">{components.map((name) => <button key={name} className={name === component ? 'active' : ''} onClick={() => setComponent(name)}>{name}</button>)}</div>
          <select value={lines} onChange={(event) => setLines(Number(event.target.value))} aria-label="Lines">
            {[100, 300, 1000, 2000].map((count) => <option key={count} value={count}>{count} lines</option>)}
          </select>
          <button className="iconButton" title="Refresh" onClick={() => logs.reload()}><RefreshCw size={15} className={logs.loading ? 'spin' : ''} /></button>
        </>}
      >
        <div className="panelFilter"><div className="searchBox"><Search size={16} /><input value={logFilter} onChange={(event) => setLogFilter(event.target.value)} placeholder="Filter lines (e.g. a message ID or peer address)" /></div></div>
        <ErrorBanner error={logs.error} />
        <pre className="logView" ref={logRef}>{logText || 'No log lines available.'}</pre>
      </Panel>
      <Panel
        title="Prometheus metrics"
        subtitle={<>Scrape <code>/metrics</code> with Basic authentication</>}
        actions={<div className="searchBox"><Search size={16} /><input value={metricFilter} onChange={(event) => setMetricFilter(event.target.value)} placeholder="Filter metrics" /></div>}
      >
        <ErrorBanner error={metrics.error} />
        <div className="metricList scroll">{samples.length ? samples.map((sample, index) => <div className="metric" key={`${sample.name}-${index}`}><span>{sample.name}</span><strong>{sample.value}</strong></div>) : <Empty>No metrics match.</Empty>}</div>
      </Panel>
    </>
  );
}
