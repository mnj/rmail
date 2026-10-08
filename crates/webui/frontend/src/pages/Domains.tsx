import React, { useState } from 'react';
import { Check, Copy, KeyRound, ShieldCheck, Trash2 } from 'lucide-react';
import { api, DkimKey, Discovery } from '../api';
import { Empty, ErrorBanner, Field, formatRelative, IconButton, Modal, Panel, SkeletonRows, useFeedback, useResource } from '../ui';

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

export function DomainsPage() {
  const discovery = useResource(() => api<Discovery>('/api/discovery'), []);
  const [adding, setAdding] = useState<string | null>(null);
  const data = discovery.data;

  return (
    <>
      <ErrorBanner error={discovery.error} />
      <section className="routingPage">
        {!data && !discovery.error && <Panel title="Domains"><table><tbody><SkeletonRows rows={4} cols={3} /></tbody></table></Panel>}
        {data && !data.domains.length && <Panel title="Domains"><Empty>No hosted domains yet. Add a mailbox and its domain appears here.</Empty></Panel>}
        {data?.domains.map((entry) => (
          <Panel
            key={entry.domain}
            title={entry.domain}
            subtitle={entry.dkim.length ? `Signed with ${entry.dkim.length} DKIM key${entry.dkim.length === 1 ? '' : 's'}` : 'Outbound mail is not DKIM-signed'}
            actions={<button className="button" onClick={() => setAdding(entry.domain)}><KeyRound size={16} />{entry.dkim.length ? 'Add key' : 'Set up DKIM'}</button>}
          >
            {entry.dkim.length > 0 && <KeyRows keys={entry.dkim} onChanged={discovery.reload} />}
            <h3 className="subheading">DNS records to publish</h3>
            <div className="tableScroll">
              <table>
                <thead><tr><th>Name</th><th>Type</th><th>Value</th><th><span className="visuallyHidden">Copy</span></th></tr></thead>
                <tbody>
                  {entry.records.map((record) => (
                    <tr key={`${record.name} ${record.type} ${record.value}`} title={record.purpose}>
                      <td className="nowrap"><code>{record.name}</code></td>
                      <td><span className="pill">{record.type}</span></td>
                      <td className="breakAll"><code>{record.value}</code><small className="fieldHint">{record.purpose}</small></td>
                      <td className="rowActions"><CopyButton value={record.value} label={`Copy ${record.type} value for ${record.name}`} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
        ))}
        {data && (
          <p className="muted">
            Records point at <code>{data.hostname}</code>. Publish them at your DNS provider; MTA-STS and SRV rows appear once those listeners or policies are enabled.
          </p>
        )}
      </section>
      {adding && <AddKeyModal domain={adding} onClose={() => setAdding(null)} onSaved={discovery.reload} />}
    </>
  );
}
