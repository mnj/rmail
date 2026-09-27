import { useEffect, useMemo, useRef, useState } from 'react';
import { RefreshCw, Search } from 'lucide-react';
import { apiText } from '../api';
import { Empty, ErrorBanner, Panel, useResource } from '../ui';

const components = ['smtpd', 'imapd', 'outbound', 'web', 'webmail', 'classifier'];

type LogEntry = { raw: string; time?: number; level?: string; event?: string; fields?: Record<string, unknown> };

const levels = ['error', 'warn', 'info', 'debug'];

function parseLine(raw: string): LogEntry {
  try {
    const value = JSON.parse(raw);
    if (value && typeof value === 'object' && 'event' in value) {
      return { raw, time: value.timestamp_unix_ms, level: value.level, event: value.event, fields: value.fields || {} };
    }
  } catch {
    // not structured
  }
  return { raw };
}

function formatField(value: unknown): string {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'string') return value;
  return JSON.stringify(value);
}

export function ObservabilityPage() {
  const [component, setComponent] = useState('smtpd');
  const [lines, setLines] = useState(300);
  const [logFilter, setLogFilter] = useState('');
  const [minLevel, setMinLevel] = useState('debug');
  const [raw, setRaw] = useState(false);
  const [metricFilter, setMetricFilter] = useState('');
  const logs = useResource(() => apiText(`/logs?component=${component}&lines=${lines}`), [component, lines], 15000);
  const metrics = useResource(() => apiText('/metrics'), [], 30000);
  const logRef = useRef<HTMLDivElement>(null);

  const entries = useMemo(() => {
    const needle = logFilter.trim().toLowerCase();
    const maxRank = levels.indexOf(minLevel);
    return (logs.data || '')
      .split('\n')
      .filter(Boolean)
      .map(parseLine)
      .filter((entry) => !entry.level || levels.indexOf(entry.level) <= maxRank)
      .filter((entry) => !needle || entry.raw.toLowerCase().includes(needle));
  }, [logs.data, logFilter, minLevel]);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [entries, raw]);

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
        <div className="panelFilter logTools">
          <div className="searchBox"><Search size={16} /><input value={logFilter} onChange={(event) => setLogFilter(event.target.value)} placeholder="Filter (message ID, connection ID, address, event…)" /></div>
          <select value={minLevel} onChange={(event) => setMinLevel(event.target.value)} aria-label="Minimum level">
            {levels.map((level) => <option key={level} value={level}>{level === 'debug' ? 'All levels' : `${level} and above`}</option>)}
          </select>
          <label className="checkLabel"><input type="checkbox" checked={raw} onChange={(event) => setRaw(event.target.checked)} /> Raw</label>
        </div>
        <ErrorBanner error={logs.error} />
        <div className="logView" ref={logRef}>
          {entries.length === 0 && <div className="logEmpty">No log lines match.</div>}
          {raw
            ? <pre>{entries.map((entry) => entry.raw).join('\n')}</pre>
            : entries.map((entry, index) => entry.event ? (
              <div className={`logLine ${entry.level}`} key={index}>
                <time>{entry.time ? new Date(entry.time).toLocaleTimeString() : ''}</time>
                <span className="logLevel">{entry.level}</span>
                <strong>{entry.event}</strong>
                <span className="logFields">
                  {Object.entries(entry.fields || {}).filter(([, value]) => value !== null && value !== undefined).map(([key, value]) => (
                    <button key={key} className="logField" title="Filter by this value" onClick={() => setLogFilter(formatField(value))}><em>{key}</em>={formatField(value)}</button>
                  ))}
                </span>
              </div>
            ) : <div className="logLine plain" key={index}>{entry.raw}</div>)}
        </div>
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
