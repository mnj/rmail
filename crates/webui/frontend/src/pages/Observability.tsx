import { useLayoutEffect, useMemo, useRef, useState } from 'react';
import { ArrowDown, Pause, Play, RefreshCw, Search } from 'lucide-react';
import { apiText } from '../api';
import { Empty, ErrorBanner, IconButton, Panel, useResource } from '../ui';

const components = ['smtpd', 'imapd', 'outbound', 'web', 'webmail', 'classifier'];

type LogEntry = { raw: string; time?: number; level?: string; event?: string; fields?: Record<string, unknown> };
type MetricGroup = { name: string; help: string; type: string; samples: { series: string; value: string }[] };

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

/** Group Prometheus text exposition by metric family, keeping HELP and TYPE. */
function parseMetrics(text: string): MetricGroup[] {
  const groups = new Map<string, MetricGroup>();
  const group = (name: string) => {
    let entry = groups.get(name);
    if (!entry) groups.set(name, (entry = { name, help: '', type: '', samples: [] }));
    return entry;
  };
  for (const line of text.split('\n')) {
    const meta = /^# (HELP|TYPE) (\S+) ?(.*)$/.exec(line);
    if (meta) {
      if (meta[1] === 'HELP') group(meta[2]).help = meta[3];
      else group(meta[2]).type = meta[3];
      continue;
    }
    if (!line || line.startsWith('#')) continue;
    const index = line.lastIndexOf(' ');
    const series = line.slice(0, index);
    const name = series.replace(/\{.*$/, '');
    // Histogram and summary series belong to their family.
    const family = groups.has(name) ? name : name.replace(/_(bucket|sum|count|total)$/, '');
    group(groups.has(family) ? family : name).samples.push({ series, value: line.slice(index + 1) });
  }
  return Array.from(groups.values()).filter((entry) => entry.samples.length).sort((a, b) => a.name.localeCompare(b.name));
}

export function ObservabilityPage() {
  const [component, setComponent] = useState('smtpd');
  const [lines, setLines] = useState(300);
  const [logFilter, setLogFilter] = useState('');
  const [minLevel, setMinLevel] = useState('debug');
  const [raw, setRaw] = useState(false);
  const [paused, setPaused] = useState(false);
  const [metricFilter, setMetricFilter] = useState('');
  const logs = useResource(() => apiText(`/logs?component=${component}&lines=${lines}`), [component, lines], paused ? undefined : 15000);
  const metrics = useResource(() => apiText('/metrics'), [], 30000);
  const logRef = useRef<HTMLDivElement>(null);
  // Follow new lines only while the view is scrolled to the bottom.
  const following = useRef(true);
  const [atBottom, setAtBottom] = useState(true);

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

  useLayoutEffect(() => {
    if (following.current && logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [entries, raw]);

  // A new component starts at its newest lines.
  useLayoutEffect(() => {
    following.current = true;
    setAtBottom(true);
  }, [component]);

  const onScroll = () => {
    const view = logRef.current;
    if (!view) return;
    const bottom = view.scrollHeight - view.scrollTop - view.clientHeight < 24;
    following.current = bottom;
    setAtBottom(bottom);
  };

  const jumpToNewest = () => {
    following.current = true;
    setAtBottom(true);
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight });
  };

  const groups = useMemo(() => {
    const needle = metricFilter.trim().toLowerCase();
    return parseMetrics(metrics.data || '')
      .map((group) => needle && !group.name.toLowerCase().includes(needle) && !group.help.toLowerCase().includes(needle)
        ? { ...group, samples: group.samples.filter((sample) => sample.series.toLowerCase().includes(needle)) }
        : group)
      .filter((group) => group.samples.length);
  }, [metrics.data, metricFilter]);

  return (
    <>
      <Panel
        title="Daemon logs"
        subtitle={paused ? 'Paused; newest lines at the bottom' : 'Newest lines at the bottom; refreshes every 15 seconds'}
        actions={<>
          <div className="tabs" role="tablist" aria-label="Component">{components.map((name) => <button key={name} role="tab" aria-selected={name === component} className={name === component ? 'active' : ''} onClick={() => setComponent(name)}>{name}</button>)}</div>
          <select value={lines} onChange={(event) => setLines(Number(event.target.value))} aria-label="Lines">
            {[100, 300, 1000, 2000].map((count) => <option key={count} value={count}>{count} lines</option>)}
          </select>
          <IconButton label={paused ? 'Resume auto-refresh' : 'Pause auto-refresh'} onClick={() => setPaused(!paused)}>{paused ? <Play size={15} /> : <Pause size={15} />}</IconButton>
          <IconButton label="Refresh now" onClick={() => logs.reload()}><RefreshCw size={15} className={logs.loading ? 'spin' : ''} /></IconButton>
        </>}
      >
        <div className="panelFilter logTools">
          <div className="searchBox"><Search size={16} /><input value={logFilter} onChange={(event) => setLogFilter(event.target.value)} placeholder="Filter (message ID, connection ID, address, event…)" aria-label="Filter log lines" /></div>
          <select value={minLevel} onChange={(event) => setMinLevel(event.target.value)} aria-label="Minimum level">
            {levels.map((level) => <option key={level} value={level}>{level === 'debug' ? 'All levels' : `${level} and above`}</option>)}
          </select>
          <label className="checkLabel"><input type="checkbox" checked={raw} onChange={(event) => setRaw(event.target.checked)} /> Raw</label>
        </div>
        <ErrorBanner error={logs.error} />
        <div className="logView" ref={logRef} onScroll={onScroll} tabIndex={0} aria-label={`${component} log`}>
          {logs.data === null && !logs.error && <div className="logEmpty">Loading…</div>}
          {logs.data !== null && entries.length === 0 && <div className="logEmpty">{logs.data ? 'No log lines match.' : 'This log is empty.'}</div>}
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
          {!atBottom && <button className="button logJump" onClick={jumpToNewest}><ArrowDown size={14} />Jump to newest</button>}
        </div>
      </Panel>
      <Panel
        title="Prometheus metrics"
        subtitle={<>{groups.length ? `${groups.length} metric families · ` : ''}Scrape <code>/metrics</code> with Basic authentication</>}
        actions={<div className="searchBox"><Search size={16} /><input value={metricFilter} onChange={(event) => setMetricFilter(event.target.value)} placeholder="Filter metrics" aria-label="Filter metrics" /></div>}
      >
        <ErrorBanner error={metrics.error} />
        <div className="metricGroups">
          {groups.map((group) => (
            <section className="metricGroup" key={group.name}>
              <header><code>{group.name}</code>{group.type && <span className="badge">{group.type}</span>}{group.help && <p>{group.help}</p>}</header>
              {group.samples.map((sample, index) => (
                <div className="metric" key={`${sample.series}-${index}`}><span title={sample.series}>{sample.series === group.name ? 'value' : sample.series.slice(sample.series.startsWith(group.name) ? group.name.length : 0) || sample.series}</span><strong>{sample.value}</strong></div>
              ))}
            </section>
          ))}
          {metrics.data !== null && !groups.length && <Empty>No metrics match.</Empty>}
        </div>
      </Panel>
    </>
  );
}
