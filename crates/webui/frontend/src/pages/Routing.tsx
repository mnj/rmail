import React, { useState } from 'react';
import { Pencil, Plus, Trash2 } from 'lucide-react';
import { api, Routing } from '../api';
import { Empty, ErrorBanner, Field, Panel, useFeedback, useResource } from '../ui';

export function RoutingPage() {
  const { run, confirm } = useFeedback();
  const routing = useResource(() => api<Routing>('/api/routing'), []);
  const [alias, setAlias] = useState({ address: '', targets: '' });
  const [catchall, setCatchall] = useState({ domain: '', target: '' });

  async function saveAlias(event: React.FormEvent) {
    event.preventDefault();
    const targets = alias.targets.split(/[\s,]+/).map((item) => item.trim()).filter(Boolean);
    if (!alias.address.trim() || !targets.length) return;
    if (await run(() => api('/api/routing/alias', 'POST', { address: alias.address.trim(), targets }), `Saved alias ${alias.address.trim()}`)) {
      setAlias({ address: '', targets: '' });
      routing.reload();
    }
  }

  async function saveCatchall(event: React.FormEvent) {
    event.preventDefault();
    if (!catchall.domain.trim() || !catchall.target.trim()) return;
    if (await run(() => api('/api/routing/catchall', 'POST', { domain: catchall.domain.trim(), target: catchall.target.trim() }), `Saved catchall for ${catchall.domain.trim()}`)) {
      setCatchall({ domain: '', target: '' });
      routing.reload();
    }
  }

  async function removeAlias(address: string) {
    if (!await confirm({ title: `Delete alias ${address}?`, message: 'Mail to this address will no longer be forwarded.', confirmLabel: 'Delete', danger: true })) return;
    if (await run(() => api('/api/routing/alias', 'DELETE', { address }), `Deleted alias ${address}`)) routing.reload();
  }

  async function removeCatchall(domain: string) {
    if (!await confirm({ title: `Delete catchall for ${domain}?`, message: 'Mail to unknown recipients in this domain will be rejected.', confirmLabel: 'Delete', danger: true })) return;
    if (await run(() => api('/api/routing/catchall', 'DELETE', { domain }), `Deleted catchall for ${domain}`)) routing.reload();
  }

  const data = routing.data;
  return (
    <>
      <ErrorBanner error={routing.error} />
      <section className="grid even">
        <Panel title="Aliases" subtitle="Forward an address to one or more mailboxes">
          <form className="formStack padded" onSubmit={saveAlias}>
            <Field label="Alias address"><input value={alias.address} onChange={(event) => setAlias({ ...alias, address: event.target.value })} placeholder="team@example.com" /></Field>
            <Field label="Deliver to" hint="Separate addresses with commas or spaces. Saving an existing alias replaces its targets."><input value={alias.targets} onChange={(event) => setAlias({ ...alias, targets: event.target.value })} placeholder="alice@example.com, bob@example.com" /></Field>
            <button className="button primary"><Plus size={16} />Save alias</button>
          </form>
          <table>
            <thead><tr><th>Alias</th><th>Targets</th><th /></tr></thead>
            <tbody>
              {data?.aliases.map((row) => (
                <tr key={row.address}>
                  <td><strong>{row.address}</strong></td>
                  <td className="wrap">{row.targets.join(', ')}</td>
                  <td className="rowActions">
                    <button className="iconButton" title="Edit" onClick={() => setAlias({ address: row.address, targets: row.targets.join(', ') })}><Pencil size={15} /></button>
                    <button className="iconButton danger" title="Delete" onClick={() => removeAlias(row.address)}><Trash2 size={15} /></button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {data && !data.aliases.length && <Empty>No aliases configured.</Empty>}
        </Panel>
        <Panel title="Catchalls" subtitle="Deliver mail for unknown recipients in a domain">
          <form className="formStack padded" onSubmit={saveCatchall}>
            <Field label="Domain"><input value={catchall.domain} onChange={(event) => setCatchall({ ...catchall, domain: event.target.value })} placeholder="example.com" /></Field>
            <Field label="Deliver to"><input value={catchall.target} onChange={(event) => setCatchall({ ...catchall, target: event.target.value })} placeholder="postmaster@example.com" /></Field>
            <button className="button primary"><Plus size={16} />Save catchall</button>
          </form>
          <table>
            <thead><tr><th>Domain</th><th>Target</th><th /></tr></thead>
            <tbody>
              {data?.catchalls.map((row) => (
                <tr key={row.domain}>
                  <td><strong>@{row.domain}</strong></td>
                  <td>{row.target}</td>
                  <td className="rowActions">
                    <button className="iconButton" title="Edit" onClick={() => setCatchall({ domain: row.domain, target: row.target })}><Pencil size={15} /></button>
                    <button className="iconButton danger" title="Delete" onClick={() => removeCatchall(row.domain)}><Trash2 size={15} /></button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {data && !data.catchalls.length && <Empty>No catchalls configured.</Empty>}
        </Panel>
      </section>
    </>
  );
}
