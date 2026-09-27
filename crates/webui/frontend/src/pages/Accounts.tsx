import React, { useMemo, useState } from 'react';
import { Dices, KeyRound, Pencil, Plus, Search, Trash2 } from 'lucide-react';
import { Account, api } from '../api';
import { Empty, ErrorBanner, Field, formatBytes, generatePassword, Modal, Panel, useFeedback, useResource } from '../ui';

type Editing = { mode: 'create' } | { mode: 'edit'; account: Account };

function AccountModal({ editing, onClose, onSaved }: { editing: Editing; onClose: () => void; onSaved: () => void }) {
  const { run } = useFeedback();
  const existing = editing.mode === 'edit' ? editing.account : null;
  const [address, setAddress] = useState(existing?.address || '');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [quota, setQuota] = useState(existing?.quota_bytes ? String(Math.round(existing.quota_bytes / 1024 / 1024)) : '');
  const [saving, setSaving] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setSaving(true);
    const body: Record<string, unknown> = { address: address.trim() };
    if (password) body.password = password;
    // Zero removes the quota; an untouched empty field on edit keeps it.
    if (quota !== '') body.quota_mib = Number(quota);
    else if (existing?.quota_bytes) body.quota_mib = 0;
    const ok = await run(() => api('/api/accounts', existing ? 'PATCH' : 'POST', body), existing ? `Updated ${address}` : `Created ${address}`);
    setSaving(false);
    if (ok) {
      onSaved();
      onClose();
    }
  }

  return (
    <Modal title={existing ? `Edit ${existing.address}` : 'New mailbox'} onClose={onClose} footer={<>
      <button className="button" type="button" onClick={onClose}>Cancel</button>
      <button className="button primary" type="submit" form="accountForm" disabled={saving || !address.includes('@') || (!existing && !password)}>{saving ? 'Saving…' : existing ? 'Save changes' : 'Create mailbox'}</button>
    </>}>
      <form id="accountForm" className="formStack" onSubmit={submit}>
        <Field label="Address">
          <input value={address} onChange={(event) => setAddress(event.target.value)} placeholder="user@example.com" disabled={!!existing} autoFocus={!existing} required />
        </Field>
        <Field label={existing ? 'New password' : 'Password'} hint={existing ? 'Leave empty to keep the current password. Changing it signs the user out of webmail.' : 'Stored as Argon2id plus a SCRAM-SHA-256 verifier.'}>
          <div className="inputRow">
            <input aria-label={existing ? 'New password' : 'Password'} type={showPassword ? 'text' : 'password'} value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password" autoFocus={!!existing} />
            <button type="button" className="iconButton" title="Generate a password" onClick={() => { setPassword(generatePassword()); setShowPassword(true); }}><Dices size={15} /></button>
          </div>
        </Field>
        <Field label="Storage quota (MiB)" hint="Empty or 0 means unlimited.">
          <input type="number" min={0} value={quota} onChange={(event) => setQuota(event.target.value)} placeholder="Unlimited" />
        </Field>
      </form>
    </Modal>
  );
}

export function AccountsPage() {
  const { run, confirm } = useFeedback();
  const accounts = useResource(() => api<Account[]>('/api/accounts'), []);
  const [editing, setEditing] = useState<Editing | null>(null);
  const [filter, setFilter] = useState('');

  const rows = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    return (accounts.data || []).filter((account) => !needle || account.address.includes(needle));
  }, [accounts.data, filter]);

  async function remove(account: Account) {
    const ok = await confirm({
      title: `Delete ${account.address}?`,
      message: <>The mailbox can no longer sign in or receive mail. Stored messages ({account.messages}) stay on disk under the mail root until you remove them.</>,
      confirmLabel: 'Delete mailbox',
      danger: true,
    });
    if (ok && await run(() => api('/api/accounts', 'DELETE', { address: account.address }), `Deleted ${account.address}`)) accounts.reload();
  }

  const totalUsed = rows.reduce((sum, account) => sum + account.used_bytes, 0);

  return (
    <>
      <ErrorBanner error={accounts.error} />
      <Panel
        title="Mailboxes"
        subtitle={`${rows.length} of ${accounts.data?.length ?? 0} · ${formatBytes(totalUsed)} stored`}
        actions={<>
          <div className="searchBox"><Search size={16} /><input value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Filter mailboxes" /></div>
          <button className="button primary" onClick={() => setEditing({ mode: 'create' })}><Plus size={16} />New mailbox</button>
        </>}
      >
        <table>
          <thead><tr><th>Mailbox</th><th>Sign-in</th><th>Storage</th><th>Folders</th><th>Messages</th><th /></tr></thead>
          <tbody>
            {rows.map((account) => {
              const percent = account.quota_bytes ? Math.min(100, Math.round((account.used_bytes / account.quota_bytes) * 100)) : null;
              return (
                <tr key={account.address}>
                  <td><strong>{account.address}</strong><small>{account.unseen ? `${account.unseen} unread` : 'No unread mail'}</small></td>
                  <td><span className={`pill ${account.auth === 'Unset' ? 'warn' : ''}`}>{account.auth === 'Unset' ? 'No password' : account.auth}</span></td>
                  <td className="usage">
                    <span>{formatBytes(account.used_bytes)} / {account.quota_bytes == null ? 'unlimited' : formatBytes(account.quota_bytes)}</span>
                    {percent !== null && <div className={`usageBar ${percent > 90 ? 'high' : ''}`}><i style={{ width: `${percent}%` }} /></div>}
                  </td>
                  <td>{account.folders}</td>
                  <td>{account.messages}</td>
                  <td className="rowActions">
                    <button className="iconButton" title="Edit mailbox" onClick={() => setEditing({ mode: 'edit', account })}>{account.auth === 'Unset' ? <KeyRound size={15} /> : <Pencil size={15} />}</button>
                    <button className="iconButton danger" title="Delete mailbox" onClick={() => remove(account)}><Trash2 size={15} /></button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {!accounts.loading && rows.length === 0 && <Empty>{filter ? 'No mailboxes match the filter.' : 'No mailboxes yet. Create the first one to start receiving mail.'}</Empty>}
      </Panel>
      {editing && <AccountModal editing={editing} onClose={() => setEditing(null)} onSaved={accounts.reload} />}
    </>
  );
}
