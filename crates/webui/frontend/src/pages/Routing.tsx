import React, { useId, useMemo, useState } from 'react';
import { Pencil, Plus, Search, Trash2, X } from 'lucide-react';
import { Account, api, Routing } from '../api';
import { Empty, ErrorBanner, Field, IconButton, Modal, Panel, SkeletonRows, useFeedback, useResource } from '../ui';

type AliasEdit = { mode: 'create' } | { mode: 'edit'; address: string; targets: string[] };
type CatchallEdit = { mode: 'create' } | { mode: 'edit'; domain: string; target: string };

const looksLikeAddress = (value: string) => /^[^\s@]+@[^\s@]+$/.test(value);

/** A target is "external" when it is not a mailbox on this server; mail to it is forwarded out. */
function Target({ address, local }: { address: string; local: Set<string> }) {
  const external = local.size > 0 && !local.has(address.toLowerCase());
  return <span className={`tag ${external ? 'external' : ''}`} title={external ? `${address} is not a mailbox on this server; mail is forwarded out` : address}>{address}</span>;
}

/** Address list entered as tags. Enter, comma or space commits the typed address. */
function TargetInput({ value, onChange, mailboxes, id }: { value: string[]; onChange: (value: string[]) => void; mailboxes: string[]; id: string }) {
  const [draft, setDraft] = useState('');
  const listId = useId();
  const local = useMemo(() => new Set(mailboxes.map((item) => item.toLowerCase())), [mailboxes]);

  const commit = (text: string) => {
    const added = text.split(/[\s,]+/).map((item) => item.trim()).filter(Boolean);
    if (added.length) onChange([...value, ...added.filter((item) => !value.includes(item))]);
    setDraft('');
  };

  return (
    <div className="tagInput" onClick={(event) => (event.currentTarget.querySelector('input') as HTMLInputElement | null)?.focus()}>
      {value.map((item) => (
        <span className={`tag ${!looksLikeAddress(item) || (local.size > 0 && !local.has(item.toLowerCase())) ? 'external' : ''}`} key={item}>
          {item}
          <button type="button" aria-label={`Remove ${item}`} onClick={() => onChange(value.filter((other) => other !== item))}><X size={12} /></button>
        </span>
      ))}
      <input
        id={id}
        list={listId}
        value={draft}
        placeholder={value.length ? 'Add another…' : 'alice@example.com'}
        onChange={(event) => (/[\s,]/.test(event.target.value) ? commit(event.target.value) : setDraft(event.target.value))}
        onKeyDown={(event) => {
          if (event.key === 'Enter' && draft.trim()) { event.preventDefault(); commit(draft); }
          if (event.key === 'Backspace' && !draft && value.length) onChange(value.slice(0, -1));
        }}
        onBlur={() => draft.trim() && commit(draft)}
      />
      <datalist id={listId}>{mailboxes.filter((item) => !value.includes(item)).map((item) => <option key={item} value={item} />)}</datalist>
    </div>
  );
}

function AliasModal({ editing, mailboxes, onClose, onSaved }: { editing: AliasEdit; mailboxes: string[]; onClose: () => void; onSaved: () => void }) {
  const { run } = useFeedback();
  const existing = editing.mode === 'edit' ? editing : null;
  const [address, setAddress] = useState(existing?.address || '');
  const [targets, setTargets] = useState<string[]>(existing?.targets || []);
  const [saving, setSaving] = useState(false);
  const targetsId = useId();
  const invalid = targets.filter((item) => !looksLikeAddress(item));
  const local = new Set(mailboxes.map((item) => item.toLowerCase()));
  const external = targets.filter((item) => looksLikeAddress(item) && local.size > 0 && !local.has(item.toLowerCase()));

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setSaving(true);
    const ok = await run(() => api('/api/routing/alias', 'POST', { address: address.trim(), targets }), `Saved alias ${address.trim()}`);
    setSaving(false);
    if (ok) { onSaved(); onClose(); }
  }

  return (
    <Modal title={existing ? `Edit ${existing.address}` : 'New alias'} onClose={onClose} footer={<>
      <button className="button" type="button" onClick={onClose}>Cancel</button>
      <button className="button primary" type="submit" form="aliasForm" disabled={saving || !looksLikeAddress(address.trim()) || !targets.length || invalid.length > 0}>{saving ? 'Saving…' : existing ? 'Save changes' : 'Create alias'}</button>
    </>}>
      <form id="aliasForm" className="formStack" onSubmit={submit}>
        <Field label="Alias address">
          <input value={address} onChange={(event) => setAddress(event.target.value)} placeholder="team@example.com" disabled={!!existing} autoFocus={!existing} required />
        </Field>
        <div className="field">
          <label className="fieldLabel" htmlFor={targetsId}>Deliver to</label>
          <TargetInput id={targetsId} value={targets} onChange={setTargets} mailboxes={mailboxes} />
          <small className="fieldHint">
            {invalid.length > 0
              ? <span className="errorText">Not an address: {invalid.join(', ')}</span>
              : external.length > 0
                ? <>Not mailboxes on this server, so mail is forwarded out: {external.join(', ')}</>
                : 'Press Enter, comma or space after each address.'}
          </small>
        </div>
      </form>
    </Modal>
  );
}

function CatchallModal({ editing, mailboxes, onClose, onSaved }: { editing: CatchallEdit; mailboxes: string[]; onClose: () => void; onSaved: () => void }) {
  const { run } = useFeedback();
  const existing = editing.mode === 'edit' ? editing : null;
  const domains = useMemo(() => Array.from(new Set(mailboxes.map((item) => item.split('@')[1]).filter(Boolean))).sort(), [mailboxes]);
  const [domain, setDomain] = useState(existing?.domain || '');
  const [target, setTarget] = useState(existing?.target || '');
  const [saving, setSaving] = useState(false);
  const listId = useId();
  const domainListId = useId();
  const cleanDomain = domain.trim().replace(/^@/, '');
  const external = looksLikeAddress(target.trim()) && mailboxes.length > 0 && !mailboxes.some((item) => item.toLowerCase() === target.trim().toLowerCase());

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setSaving(true);
    const ok = await run(() => api('/api/routing/catchall', 'POST', { domain: cleanDomain, target: target.trim() }), `Saved catchall for ${cleanDomain}`);
    setSaving(false);
    if (ok) { onSaved(); onClose(); }
  }

  return (
    <Modal title={existing ? `Edit catchall for @${existing.domain}` : 'New catchall'} onClose={onClose} footer={<>
      <button className="button" type="button" onClick={onClose}>Cancel</button>
      <button className="button primary" type="submit" form="catchallForm" disabled={saving || !cleanDomain || !looksLikeAddress(target.trim())}>{saving ? 'Saving…' : existing ? 'Save changes' : 'Create catchall'}</button>
    </>}>
      <form id="catchallForm" className="formStack" onSubmit={submit}>
        <Field label="Domain" hint="Mail to any unknown address in this domain is delivered to the target.">
          <input value={domain} list={domainListId} onChange={(event) => setDomain(event.target.value)} placeholder="example.com" disabled={!!existing} autoFocus={!existing} required />
        </Field>
        <datalist id={domainListId}>{domains.map((item) => <option key={item} value={item} />)}</datalist>
        <Field label="Deliver to" hint={external ? 'Not a mailbox on this server, so mail is forwarded out.' : undefined}>
          <input value={target} list={listId} onChange={(event) => setTarget(event.target.value)} placeholder="postmaster@example.com" autoFocus={!!existing} required />
        </Field>
        <datalist id={listId}>{mailboxes.map((item) => <option key={item} value={item} />)}</datalist>
      </form>
    </Modal>
  );
}

export function RoutingPage() {
  const { run, confirm } = useFeedback();
  const routing = useResource(() => api<Routing>('/api/routing'), []);
  // Only used to suggest targets and flag external ones; routing works without it.
  const accounts = useResource(() => api<Account[]>('/api/accounts').catch(() => [] as Account[]), [], undefined, 'accounts');
  const [aliasEdit, setAliasEdit] = useState<AliasEdit | null>(null);
  const [catchallEdit, setCatchallEdit] = useState<CatchallEdit | null>(null);
  const [filter, setFilter] = useState('');

  const mailboxes = useMemo(() => (accounts.data || []).map((account) => account.address).sort(), [accounts.data]);
  const local = useMemo(() => new Set(mailboxes.map((item) => item.toLowerCase())), [mailboxes]);
  const data = routing.data;
  const needle = filter.trim().toLowerCase();
  const aliases = (data?.aliases || []).filter((row) => !needle || [row.address, ...row.targets].some((item) => item.toLowerCase().includes(needle)));

  async function removeAlias(address: string) {
    if (!await confirm({ title: `Delete alias ${address}?`, message: 'Mail to this address will no longer be forwarded.', confirmLabel: 'Delete', danger: true })) return;
    if (await run(() => api('/api/routing/alias', 'DELETE', { address }), `Deleted alias ${address}`)) routing.reload();
  }

  async function removeCatchall(domain: string) {
    if (!await confirm({ title: `Delete catchall for ${domain}?`, message: 'Mail to unknown recipients in this domain will be rejected.', confirmLabel: 'Delete', danger: true })) return;
    if (await run(() => api('/api/routing/catchall', 'DELETE', { domain }), `Deleted catchall for ${domain}`)) routing.reload();
  }

  return (
    <>
      <ErrorBanner error={routing.error} />
      <section className="routingPage">
        <Panel
          title="Aliases"
          subtitle={data ? `${data.aliases.length} alias${data.aliases.length === 1 ? '' : 'es'} · forward an address to one or more recipients` : 'Forward an address to one or more recipients'}
          actions={<>
            {(data?.aliases.length ?? 0) > 5 && <div className="searchBox"><Search size={16} /><input value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Filter aliases" aria-label="Filter aliases" /></div>}
            <button className="button primary" onClick={() => setAliasEdit({ mode: 'create' })}><Plus size={16} />New alias</button>
          </>}
        >
          <div className="tableScroll">
            <table>
              <thead><tr><th>Alias</th><th>Delivers to</th><th><span className="visuallyHidden">Actions</span></th></tr></thead>
              <tbody>
                {!data && !routing.error && <SkeletonRows rows={3} cols={3} />}
                {aliases.map((row) => (
                  <tr key={row.address}>
                    <td className="nowrap"><strong>{row.address}</strong></td>
                    <td><div className="tagList">{row.targets.map((target) => <Target key={target} address={target} local={local} />)}</div></td>
                    <td className="rowActions">
                      <IconButton label={`Edit ${row.address}`} onClick={() => setAliasEdit({ mode: 'edit', address: row.address, targets: row.targets })}><Pencil size={15} /></IconButton>
                      <IconButton danger label={`Delete ${row.address}`} onClick={() => removeAlias(row.address)}><Trash2 size={15} /></IconButton>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {data && !aliases.length && <Empty>{needle ? 'No aliases match the filter.' : 'No aliases yet. An alias forwards mail for an address, such as team@, to one or more recipients.'}</Empty>}
        </Panel>

        <Panel
          title="Catchalls"
          subtitle="Deliver mail for unknown recipients in a domain"
          actions={<button className="button" onClick={() => setCatchallEdit({ mode: 'create' })}><Plus size={16} />New catchall</button>}
        >
          <div className="tableScroll">
          <table>
            <thead><tr><th>Domain</th><th>Delivers to</th><th><span className="visuallyHidden">Actions</span></th></tr></thead>
            <tbody>
              {!data && !routing.error && <SkeletonRows rows={1} cols={3} />}
              {data?.catchalls.map((row) => (
                <tr key={row.domain}>
                  <td className="nowrap"><strong>@{row.domain}</strong></td>
                  <td><Target address={row.target} local={local} /></td>
                  <td className="rowActions">
                    <IconButton label={`Edit catchall for ${row.domain}`} onClick={() => setCatchallEdit({ mode: 'edit', domain: row.domain, target: row.target })}><Pencil size={15} /></IconButton>
                    <IconButton danger label={`Delete catchall for ${row.domain}`} onClick={() => removeCatchall(row.domain)}><Trash2 size={15} /></IconButton>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
          {data && !data.catchalls.length && <Empty>No catchalls. Mail to unknown addresses is rejected.</Empty>}
        </Panel>
      </section>
      {aliasEdit && <AliasModal editing={aliasEdit} mailboxes={mailboxes} onClose={() => setAliasEdit(null)} onSaved={routing.reload} />}
      {catchallEdit && <CatchallModal editing={catchallEdit} mailboxes={mailboxes} onClose={() => setCatchallEdit(null)} onSaved={routing.reload} />}
    </>
  );
}
