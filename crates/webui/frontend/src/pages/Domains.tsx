import React, { useState } from 'react';
import { AlertTriangle, Check, CheckCircle2, CircleDashed, Copy, HelpCircle, KeyRound, RefreshCw, ShieldCheck, Trash2, XCircle } from 'lucide-react';
import { api, DkimKey, Discovery, DnsCheck, DnsChecks, DnsRecord, DnsStatus, failingRequired } from '../api';
import { Empty, ErrorBanner, Field, formatRelative, IconButton, Modal, Panel, plural, SkeletonRows, useFeedback, useResource } from '../ui';

function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard access can be refused (e.g. plain HTTP); the value stays selectable.
    }
  }
  return <IconButton label={copied ? 'Copied' : label} onClick={copy}>{copied ? <Check size={15} /> : <Copy size={15} />}</IconButton>;
}

function AddKeyModal({ domain, onClose, onSaved }: { domain: string; onClose: () => void; onSaved: () => void }) {
  const { run } = useFeedback();
  const year = new Date().getFullYear();
  const [algorithm, setAlgorithm] = useState<'rsa' | 'ed25519'>('rsa');
  const [selector, setSelector] = useState(`mail${year}`);
  const [pem, setPem] = useState('');
  const [saving, setSaving] = useState(false);
  const validSelector = /^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$/.test(selector.trim());

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setSaving(true);
    const ok = await run(
      () => api('/api/dkim', 'POST', { domain, selector: selector.trim(), algorithm, private_key: pem.trim() || null }),
      `Added ${selector.trim()}._domainkey.${domain}; publish its TXT record`,
    );
    setSaving(false);
    if (ok) { onSaved(); onClose(); }
  }

  return (
    <Modal title={`New DKIM key for ${domain}`} onClose={onClose} footer={<>
      <button className="button" type="button" onClick={onClose}>Cancel</button>
      <button className="button primary" type="submit" form="dkimForm" disabled={saving || !validSelector}>{saving ? 'Saving…' : pem.trim() ? 'Import key' : 'Generate key'}</button>
    </>}>
      <form id="dkimForm" className="formStack" onSubmit={submit}>
        <Field label="Selector" hint={`The record goes at ${selector.trim() || 'selector'}._domainkey.${domain}. A new selector per key makes rotation safe.`}>
          <input value={selector} onChange={(event) => setSelector(event.target.value)} autoFocus required />
        </Field>
        <Field label="Algorithm" hint={algorithm === 'ed25519' ? 'Ed25519 (RFC 8463) signs alongside an RSA key; many verifiers still only check RSA.' : '2048-bit RSA, understood by every verifier.'}>
          <select value={algorithm} onChange={(event) => setAlgorithm(event.target.value as 'rsa' | 'ed25519')} disabled={!!pem.trim()}>
            <option value="rsa">RSA</option>
            <option value="ed25519">Ed25519</option>
          </select>
        </Field>
        <Field label="Existing private key (optional)" hint="Paste a PEM key to keep a selector already published in DNS. Leave empty to generate one.">
          <textarea rows={5} value={pem} onChange={(event) => setPem(event.target.value)} placeholder="-----BEGIN PRIVATE KEY-----" spellCheck={false} />
        </Field>
      </form>
    </Modal>
  );
}

function KeyRows({ keys, onChanged }: { keys: DkimKey[]; onChanged: () => void }) {
  const { run, confirm } = useFeedback();

  async function remove(key: DkimKey) {
    const name = `${key.selector}._domainkey.${key.domain}`;
    if (!await confirm({ title: `Delete ${name}?`, message: 'Mail stops being signed with this key at once. Leave the DNS record up for a few days so mail already sent still verifies.', confirmLabel: 'Delete', danger: true })) return;
    if (await run(() => api('/api/dkim', 'DELETE', { domain: key.domain, selector: key.selector }), `Deleted ${name}`)) onChanged();
  }

  async function toggleArc(key: DkimKey) {
    const body = key.arc ? null : { domain: key.domain, selector: key.selector };
    if (await run(() => api('/api/dkim/arc', 'PUT', body), key.arc ? 'ARC sealing turned off' : `Forwarded mail is now ARC-sealed with ${key.selector}`)) onChanged();
  }

  return (
    <div className="tableScroll">
      <table>
        <thead><tr><th>Selector</th><th>Algorithm</th><th>Created</th><th>ARC</th><th><span className="visuallyHidden">Actions</span></th></tr></thead>
        <tbody>
          {keys.map((key) => (
            <tr key={key.selector}>
              <td className="nowrap"><strong>{key.selector}</strong></td>
              <td><span className="pill">{key.algorithm === 'rsa' ? 'RSA' : 'Ed25519'}</span></td>
              <td className="nowrap">{formatRelative(key.created_at)}</td>
              <td>
                {key.arc
                  ? <span className="pill ok"><ShieldCheck size={13} /> Seals forwards</span>
                  : key.algorithm === 'rsa' ? <span className="muted">—</span> : <span className="muted">RSA only</span>}
              </td>
              <td className="rowActions">
                {key.algorithm === 'rsa' && (
                  <IconButton label={key.arc ? 'Stop ARC sealing' : 'Seal forwarded mail with this key (ARC)'} onClick={() => toggleArc(key)}><ShieldCheck size={15} /></IconButton>
                )}
                <IconButton danger label={`Delete ${key.selector}`} onClick={() => remove(key)}><Trash2 size={15} /></IconButton>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const statusLabel: Record<DnsStatus, string> = { ok: 'OK', improve: 'Can improve', missing: 'Missing', different: 'Different', problem: 'Problem', unknown: 'Not checked' };
const statusIcon: Record<DnsStatus, React.ElementType> = { ok: CheckCircle2, improve: CheckCircle2, missing: CircleDashed, different: AlertTriangle, problem: XCircle, unknown: HelpCircle };

function statusTone(check: DnsCheck): string {
  switch (check.status) {
    case 'ok': return 'ok';
    case 'improve': return 'warn';
    case 'problem': return 'error';
    case 'missing': return check.need === 'required' ? 'error' : '';
    case 'different': return check.need === 'required' ? 'error' : 'warn';
    default: return '';
  }
}

function StatusPill({ check, checking }: { check: DnsCheck | undefined; checking: boolean }) {
  if (!check) return <span className="pill">{checking ? 'Checking…' : 'Not checked'}</span>;
  const Icon = statusIcon[check.status];
  return <span className={`pill ${statusTone(check)}`}><Icon size={13} aria-hidden="true" /> {statusLabel[check.status]}</span>;
}

function recordKey(record: { name: string; type: string; value: string }): string {
  return `${record.name} ${record.type} ${record.value}`;
}

/** What DNS has instead, and why it matters, under the value we expect. */
function CheckDetail({ check }: { check: DnsCheck | undefined }) {
  if (!check || check.status === 'ok') return null;
  const showPublished = check.published.length > 0 && !check.published.includes(check.value);
  if (!check.detail && !showPublished) return null;
  return (
    <div className={`checkDetail ${statusTone(check)}`}>
      {check.detail && <p>{check.detail}</p>}
      {showPublished && <p>In DNS now: {check.published.map((value) => <code key={value}>{value}</code>)}</p>}
    </div>
  );
}

function domainSummary(records: DnsRecord[], checks: Map<string, DnsCheck>, loading: boolean): React.ReactNode {
  const found = records.map((record) => checks.get(recordKey(record))).filter((check): check is DnsCheck => !!check);
  if (!found.length) return loading ? 'Checking DNS…' : 'DNS not checked';
  const failing = failingRequired(found).length;
  if (failing) return `${plural(failing, 'required record')} missing or wrong`;
  if (found.some((check) => check.status === 'unknown')) return 'Some records could not be checked';
  const published = found.filter((check) => check.status === 'ok' || check.status === 'improve').length;
  return published === found.length ? 'All records are published' : `Required records are in place · ${published} of ${found.length} published`;
}

export function DomainsPage() {
  const { run } = useFeedback();
  const discovery = useResource(() => api<Discovery>('/api/discovery'), []);
  const dns = useResource(() => api<DnsChecks>('/api/dns-checks'), [], 300000, 'dns-checks');
  const [adding, setAdding] = useState<string | null>(null);
  const [rechecking, setRechecking] = useState(false);
  const data = discovery.data;
  const checks = new Map<string, DnsCheck>();
  for (const domain of dns.data?.domains || []) for (const check of domain.records) checks.set(recordKey(check), check);
  const checking = dns.loading || rechecking;

  // A new or deleted key changes the expected records, which the server
  // notices and looks up afresh.
  function keysChanged() {
    discovery.reload();
    dns.reload();
  }

  async function recheck() {
    setRechecking(true);
    await run(async () => dns.setData(await api<DnsChecks>('/api/dns-checks', 'POST')), 'DNS checked again');
    setRechecking(false);
  }

  return (
    <>
      <ErrorBanner error={discovery.error} />
      <section className="routingPage">
        {data && data.domains.length > 0 && (
          <div className="dnsBar">
            <span className="muted">
              {dns.error ? `DNS could not be checked: ${dns.error}`
                : !dns.data ? 'Looking the records up…'
                : <>Checked {formatRelative(dns.data.checked_at)} · <code>{dns.data.hostname}</code> {dns.data.addresses.length ? <>resolves to {dns.data.addresses.join(', ')}</> : 'does not resolve'}</>}
            </span>
            <button className="button" onClick={recheck} disabled={checking}><RefreshCw size={16} className={checking ? 'spin' : undefined} />Check again</button>
          </div>
        )}
        {!data && !discovery.error && <Panel title="Domains"><table><tbody><SkeletonRows rows={4} cols={3} /></tbody></table></Panel>}
        {data && !data.domains.length && <Panel title="Domains"><Empty>No hosted domains yet. Add a mailbox and its domain appears here.</Empty></Panel>}
        {data?.domains.map((entry) => (
          <Panel
            key={entry.domain}
            title={entry.domain}
            subtitle={<>{entry.dkim.length ? `Signed with ${entry.dkim.length} DKIM key${entry.dkim.length === 1 ? '' : 's'}` : 'Outbound mail is not DKIM-signed'} · {domainSummary(entry.records, checks, checking)}</>}
            actions={<button className="button" onClick={() => setAdding(entry.domain)}><KeyRound size={16} />{entry.dkim.length ? 'Add key' : 'Set up DKIM'}</button>}
          >
            {entry.dkim.length > 0 && <KeyRows keys={entry.dkim} onChanged={keysChanged} />}
            <h3 className="subheading">DNS records to publish</h3>
            <div className="tableScroll">
              <table className="dnsTable">
                <thead><tr><th>Status</th><th>Name</th><th>Type</th><th>Value</th><th><span className="visuallyHidden">Copy</span></th></tr></thead>
                <tbody>
                  {entry.records.map((record) => {
                    const check = checks.get(recordKey(record));
                    return (
                      <tr key={recordKey(record)}>
                        <td className="nowrap"><StatusPill check={check} checking={checking} /></td>
                        <td className="nowrap"><code>{record.name}</code>{check?.need === 'required' && <small>Required</small>}</td>
                        <td><span className="pill">{record.type}</span></td>
                        <td className="breakAll"><code>{record.value}</code><small className="fieldHint">{record.purpose}</small><CheckDetail check={check} /></td>
                        <td className="rowActions"><CopyButton value={record.value} label={`Copy ${record.type} value for ${record.name}`} /></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </Panel>
        ))}
        {data && (
          <p className="muted">
            Records point at <code>{data.hostname}</code>. Publish them at your DNS provider; MTA-STS and SRV rows appear once those listeners or policies are enabled.
            A change can take a while to show here, because resolvers remember the old answer for as long as the record's TTL says.
          </p>
        )}
      </section>
      {adding && <AddKeyModal domain={adding} onClose={() => setAdding(null)} onSaved={keysChanged} />}
    </>
  );
}
