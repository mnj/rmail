import React, { useMemo, useState } from 'react';
import { Dices, KeyRound, Pencil, Plus, Search, ShieldOff, Trash2 } from 'lucide-react';
import { Account, DavShare, DirectoryPolicy, FolderShare, JournalPolicy, TwoFactorPolicy, api } from '../api';
import { Empty, ErrorBanner, Field, formatBytes, generatePassword, IconButton, invalidate, Modal, Panel, SkeletonRows, SortHeader, useFeedback, useResource, useSort } from '../ui';

type Column = 'address' | 'storage' | 'folders' | 'messages';

/** Share of the quota in use, or null without a quota. */
function quotaPercent(account: Account): number | null {
  return account.quota_bytes ? Math.round((account.used_bytes / account.quota_bytes) * 100) : null;
}

type Editing = { mode: 'create' } | { mode: 'edit'; account: Account };

function AccountModal({ editing, onClose, onSaved }: { editing: Editing; onClose: () => void; onSaved: () => void }) {
  const { run } = useFeedback();
  const existing = editing.mode === 'edit' ? editing.account : null;
  const [address, setAddress] = useState(existing?.address || '');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [quota, setQuota] = useState(existing?.quota_bytes ? String(Math.round(existing.quota_bytes / 1024 / 1024)) : '');
  const [kind, setKind] = useState<string>(existing?.resource || 'person');
  const [approver, setApprover] = useState(existing?.approver || '');
  const [saving, setSaving] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setSaving(true);
    const body: Record<string, unknown> = { address: address.trim() };
    if (password) body.password = password;
    // Zero removes the quota; an untouched empty field on edit keeps it.
    if (quota !== '') body.quota_mib = Number(quota);
    else if (existing?.quota_bytes) body.quota_mib = 0;
    const ok = await run(async () => {
      await api('/api/accounts', existing ? 'PATCH' : 'POST', body);
      if (kind !== (existing?.resource || 'person') || (kind !== 'person' && approver.trim() !== (existing?.approver || ''))) {
        await api('/api/accounts/resource', 'POST', { address: address.trim(), kind: kind === 'person' ? null : kind, approver: approver.trim() || null });
      }
    }, existing ? `Updated ${address}` : `Created ${address}`);
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
            <IconButton label="Generate a password" onClick={() => { setPassword(generatePassword()); setShowPassword(true); }}><Dices size={15} /></IconButton>
          </div>
        </Field>
        <Field label="Storage quota (MiB)" hint="Empty or 0 means unlimited.">
          <input type="number" min={0} value={quota} onChange={(event) => setQuota(event.target.value)} placeholder="Unlimited" />
        </Field>
        <Field label="Type" hint={kind === 'person' ? 'A person\'s mailbox.' : 'People in its domain book it by inviting it to a meeting: it accepts when its calendar is free and declines a clash. Invitations from elsewhere wait in its inbox.'}>
          <select value={kind} onChange={(event) => setKind(event.target.value)}>
            <option value="person">Person</option>
            <option value="room">Room</option>
            <option value="equipment">Equipment</option>
          </select>
        </Field>
        {kind !== 'person' && (
          <Field label="Approver (optional)" hint="A mailbox that approves bookings: those that fit are held as tentative until they approve or decline them in webmail. Clashes are still declined at once.">
            <input type="email" value={approver} onChange={(event) => setApprover(event.target.value)} placeholder="facilities@example.com" />
          </Field>
        )}
      </form>
    </Modal>
  );
}

/** What RFC 4314 rights amount to, in words. */
function describeRights(rights: string) {
  const changes = ['w', 'i', 't', 'e'].some((right) => rights.includes(right));
  const access = changes ? 'Read and change' : rights.includes('s') ? 'Read, marks as read' : 'Read only';
  return `${access}${rights.includes('a') ? ', can reshare' : ''}`;
}

function SharingPanel() {
  const { run, confirm } = useFeedback();
  const shares = useResource(() => api<FolderShare[]>('/api/sharing'), [], undefined, 'sharing');
  async function revoke(share: FolderShare) {
    const ok = await confirm({
      title: `Stop sharing ${share.folder}?`,
      message: <>{share.grantee} loses access to {share.owner}'s folder {share.folder}. Its messages are not changed.</>,
      confirmLabel: 'Stop sharing',
      danger: true,
    });
    if (ok && await run(() => api('/api/sharing', 'DELETE', { owner: share.owner, mailbox_id: share.mailbox_id, grantee: share.grantee }), `${share.folder} is no longer shared with ${share.grantee}`)) shares.reload();
  }
  return (
    <Panel title="Shared folders" subtitle="Folders users share from webmail or their mail app (IMAP ACL)">
      <ErrorBanner error={shares.error} />
      {shares.data && shares.data.length > 0 && (
        <div className="tableScroll">
          <table>
            <thead><tr><th>Folder</th><th>Shared with</th><th>Access</th><th><span className="visuallyHidden">Actions</span></th></tr></thead>
            <tbody>
              {shares.data.map((share) => (
                <tr key={`${share.owner} ${share.mailbox_id} ${share.grantee}`}>
                  <td><strong>{share.folder === 'INBOX' ? 'Inbox' : share.folder}</strong><small>{share.owner}</small></td>
                  <td>{share.grantee}</td>
                  <td><span className="pill" title={`RFC 4314 rights: ${share.rights}`}>{describeRights(share.rights)}</span></td>
                  <td className="rowActions"><IconButton danger label={`Stop sharing ${share.folder} with ${share.grantee}`} onClick={() => revoke(share)}><Trash2 size={15} /></IconButton></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {shares.data !== null && shares.data.length === 0 && <Empty>No folders are shared. Users share folders from webmail or with any IMAP client that supports ACL.</Empty>}
    </Panel>
  );
}

const davKind: Record<DavShare['kind'], string> = { calendar: 'Calendar', addressbook: 'Address book' };

function TwoFactorPanel() {
  const { run } = useFeedback();
  const policy = useResource(() => api<TwoFactorPolicy>('/api/two-factor-policy'), [], undefined, 'two-factor-policy');
  // Domains with a change on its way; their switch waits for it.
  const [pending, setPending] = useState<string[]>([]);
  async function toggle(domain: string, required: boolean) {
    setPending((list) => [...list, domain]);
    try {
      if (await run(() => api('/api/two-factor-policy', 'PUT', { domain, required }), required ? `${domain} now requires two-factor sign-in` : `${domain} no longer requires two-factor sign-in`)) await policy.reload();
    } finally {
      setPending((list) => list.filter((d) => d !== domain));
    }
  }
  return (
    <Panel title="Two-factor sign-in" subtitle="Users set it up under Security in webmail. Where a domain requires it, users without it must set it up at their next webmail sign-in; their mail apps keep working until they do, then need app passwords.">
      <ErrorBanner error={policy.error} />
      {policy.data && policy.data.domains.length > 0 && (
        <div className="tableScroll">
          <table>
            <thead><tr><th>Domain</th><th>Two-factor sign-in</th></tr></thead>
            <tbody>
              {policy.data.domains.map(({ domain, required }) => (
                <tr key={domain}>
                  <td><strong>{domain}</strong></td>
                  <td><label className="checkLabel"><input type="checkbox" checked={required} disabled={pending.includes(domain)} onChange={(event) => toggle(domain, event.target.checked)} /> Required</label></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {policy.data && policy.data.domains.length === 0 && <Empty>No domains yet.</Empty>}
    </Panel>
  );
}

function DirectoryPanel() {
  const { run } = useFeedback();
  const policy = useResource(() => api<DirectoryPolicy>('/api/directory-policy'), [], undefined, 'directory-policy');
  const [pending, setPending] = useState<string[]>([]);
  async function change(domain: string, setting: { enabled: boolean } | { freebusy_shared: boolean }, done: string) {
    setPending((list) => [...list, domain]);
    try {
      if (await run(() => api('/api/directory-policy', 'PUT', { domain, ...setting }), done)) await policy.reload();
    } finally {
      setPending((list) => list.filter((d) => d !== domain));
    }
  }
  return (
    <Panel title="Directory and free-busy" subtitle="The directory is a read-only address book of everyone (and every group address) in the domain, for the people in it: in webmail contacts, compose suggestions and their CardDAV apps. Free-busy times (when someone is busy, never what they do) are seen by calendar apps in the same domain; sharing them lets every domain on this server see them too. Both are off unless turned on, since not every domain's users know each other.">
      <ErrorBanner error={policy.error} />
      {policy.data && policy.data.domains.length > 0 && (
        <div className="tableScroll">
          <table>
            <thead><tr><th>Domain</th><th>Directory</th><th>Free-busy</th></tr></thead>
            <tbody>
              {policy.data.domains.map(({ domain, enabled, freebusy_shared }) => (
                <tr key={domain}>
                  <td><strong>{domain}</strong></td>
                  <td><label className="checkLabel"><input type="checkbox" checked={enabled} disabled={pending.includes(domain)}
                    onChange={(event) => { const on = event.target.checked; change(domain, { enabled: on }, on ? `${domain} now has a directory` : `${domain} no longer has a directory`); }} /> Shared with its people</label></td>
                  <td><label className="checkLabel"><input type="checkbox" checked={freebusy_shared} disabled={pending.includes(domain)}
                    onChange={(event) => { const on = event.target.checked; change(domain, { freebusy_shared: on }, on ? `${domain}'s free-busy times are visible server-wide` : `${domain}'s free-busy times stay within it`); }} /> Visible to every domain here</label></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {policy.data && policy.data.domains.length === 0 && <Empty>No domains yet.</Empty>}
    </Panel>
  );
}

function JournalPanel() {
  const { run } = useFeedback();
  const policy = useResource(() => api<JournalPolicy>('/api/journal'), [], undefined, 'journal');
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  async function save(domain: string) {
    const archive = (drafts[domain] ?? '').trim();
    if (await run(() => api('/api/journal', 'PUT', { domain, archive: archive || null }), archive ? `${domain}'s mail is now journaled to ${archive}` : `${domain}'s mail is no longer journaled`)) {
      setDrafts((all) => { const next = { ...all }; delete next[domain]; return next; });
      await policy.reload();
    }
  }
  return (
    <Panel title="Journaling" subtitle="A copy of every message a domain sends or receives, kept in an archive mailbox with headers naming the sender and every recipient, Bcc included. Use a mailbox of its own and put it on legal hold so nothing in it can be deleted.">
      <ErrorBanner error={policy.error} />
      {policy.data && policy.data.domains.length > 0 && (
        <div className="tableScroll">
          <table>
            <thead><tr><th>Domain</th><th>Archive mailbox</th><th /></tr></thead>
            <tbody>
              {policy.data.domains.map(({ domain, archive }) => (
                <tr key={domain}>
                  <td><strong>{domain}</strong></td>
                  <td><input aria-label={`Archive mailbox for ${domain}`} type="email" placeholder="Not journaled" value={drafts[domain] ?? archive ?? ''}
                    onChange={(event) => setDrafts((all) => ({ ...all, [domain]: event.target.value }))} /></td>
                  <td><button className="button" disabled={drafts[domain] === undefined} onClick={() => save(domain)}>Save</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {policy.data && policy.data.domains.length === 0 && <Empty>No domains yet.</Empty>}
    </Panel>
  );
}

function DavSharingPanel() {
  const { run, confirm } = useFeedback();
  const shares = useResource(() => api<DavShare[]>('/api/dav-sharing'), [], undefined, 'dav-sharing');
  async function revoke(share: DavShare) {
    const ok = await confirm({
      title: `Stop sharing ${share.name}?`,
      message: <>{share.grantee} loses access to {share.owner}'s {davKind[share.kind].toLowerCase()} {share.name}. Its contents are not changed.</>,
      confirmLabel: 'Stop sharing',
      danger: true,
    });
    if (ok && await run(() => api('/api/dav-sharing', 'DELETE', { owner: share.owner, collection_id: share.collection_id, grantee: share.grantee }), `${share.name} is no longer shared with ${share.grantee}`)) shares.reload();
  }
  return (
    <Panel title="Shared calendars and address books" subtitle="Calendars and address books users share from webmail or their calendar app (CalDAV/CardDAV)">
      <ErrorBanner error={shares.error} />
      {shares.data && shares.data.length > 0 && (
        <div className="tableScroll">
          <table>
            <thead><tr><th>Collection</th><th>Shared with</th><th>Access</th><th><span className="visuallyHidden">Actions</span></th></tr></thead>
            <tbody>
              {shares.data.map((share) => (
                <tr key={`${share.owner} ${share.collection_id} ${share.grantee}`}>
                  <td><strong>{share.name}</strong><small>{davKind[share.kind]} of {share.owner}</small></td>
                  <td>{share.grantee}</td>
                  <td><span className="pill">{share.access === 'read' ? 'Read only' : 'Read and change'}</span></td>
                  <td className="rowActions"><IconButton danger label={`Stop sharing ${share.name} with ${share.grantee}`} onClick={() => revoke(share)}><Trash2 size={15} /></IconButton></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {shares.data !== null && shares.data.length === 0 && <Empty>No calendars or address books are shared. Users share them from webmail, Apple Calendar or with rmail_ctl share calendar.</Empty>}
    </Panel>
  );
}

export function AccountsPage() {
  const { run, confirm } = useFeedback();
  const accounts = useResource(() => api<Account[]>('/api/accounts'), [], undefined, 'accounts');
  const [editing, setEditing] = useState<Editing | null>(null);
  const [filter, setFilter] = useState('');

  const rows = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    return (accounts.data || []).filter((account) => !needle || account.address.toLowerCase().includes(needle));
  }, [accounts.data, filter]);
  const { sorted, sort, toggle } = useSort<Account, Column>(rows, { key: 'address', dir: 'asc' }, (account, key) => {
    if (key === 'address') return account.address;
    if (key === 'storage') return account.used_bytes;
    return account[key];
  });

  async function resetTwoFactor(account: Account) {
    const ok = await confirm({
      title: `Turn off two-factor sign-in for ${account.address}?`,
      message: <>For a user who lost their phone and recovery codes. They sign in to webmail with their password alone and can set it up again; their app passwords stay. If their domain requires it, they are asked to set it up at the next sign-in.</>,
      confirmLabel: 'Turn off',
      danger: true,
    });
    if (ok && await run(() => api('/api/accounts/two-factor-reset', 'POST', { address: account.address }), `Two-factor sign-in turned off for ${account.address}`)) accounts.reload();
  }

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
          <div className="searchBox"><Search size={16} /><input value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Filter mailboxes" aria-label="Filter mailboxes" /></div>
          <button className="button primary" onClick={() => setEditing({ mode: 'create' })}><Plus size={16} />New mailbox</button>
        </>}
      >
        <div className="tableScroll">
        <table>
          <thead><tr>
            <SortHeader label="Mailbox" column="address" sort={sort} onSort={toggle} />
            <th>Sign-in</th>
            <SortHeader label="Storage" column="storage" sort={sort} onSort={toggle} numeric />
            <SortHeader label="Folders" column="folders" sort={sort} onSort={toggle} numeric />
            <SortHeader label="Messages" column="messages" sort={sort} onSort={toggle} numeric />
            <th><span className="visuallyHidden">Actions</span></th>
          </tr></thead>
          <tbody>
            {accounts.data === null && !accounts.error && <SkeletonRows cols={6} />}
            {sorted.map((account) => {
              const percent = quotaPercent(account);
              const level = percent === null ? '' : percent >= 90 ? 'high' : percent >= 75 ? 'warn' : '';
              return (
                <tr key={account.address}>
                  <td><strong>{account.address}</strong><small>{account.unseen ? `${account.unseen} unread` : 'No unread mail'}</small></td>
                  <td>
                    <span className={`pill ${account.auth === 'Unset' ? 'warn' : ''}`}>{account.auth === 'Unset' ? 'No password' : account.auth}</span>
                    {account.resource && <span className="pill" title={account.approver ? `Bookings approved by ${account.approver}` : undefined}>{account.resource === 'room' ? 'Room' : 'Equipment'}{account.approver ? ' · needs approval' : ''}</span>}
                    {account.two_factor && <span className="pill ok" title="Two-factor sign-in is on; mail apps use app passwords">2FA</span>}
                    {account.app_passwords > 0 && <small>{account.app_passwords} app password{account.app_passwords === 1 ? '' : 's'}</small>}
                  </td>
                  <td className="usage num">
                    <span>{formatBytes(account.used_bytes)} / {account.quota_bytes == null ? 'unlimited' : formatBytes(account.quota_bytes)}</span>
                    {percent !== null && <div className={`usageBar ${level}`} style={{ marginLeft: 'auto' }} title={`${percent}% of quota`}><i style={{ width: `${Math.min(100, percent)}%` }} /></div>}
                    {level === 'high' && <small className="errorText">{percent}% of quota</small>}
                  </td>
                  <td className="num">{account.folders}</td>
                  <td className="num">{account.messages}</td>
                  <td className="rowActions">
                    <IconButton label={account.auth === 'Unset' ? `Set a password for ${account.address}` : `Edit ${account.address}`} onClick={() => setEditing({ mode: 'edit', account })}>{account.auth === 'Unset' ? <KeyRound size={15} /> : <Pencil size={15} />}</IconButton>
                    {account.two_factor && <IconButton label={`Turn off two-factor sign-in for ${account.address}`} onClick={() => resetTwoFactor(account)}><ShieldOff size={15} /></IconButton>}
                    <IconButton danger label={`Delete ${account.address}`} onClick={() => remove(account)}><Trash2 size={15} /></IconButton>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        </div>
        {accounts.data !== null && rows.length === 0 && <Empty>{filter ? 'No mailboxes match the filter.' : 'No mailboxes yet. Create the first one to start receiving mail.'}</Empty>}
      </Panel>
      <TwoFactorPanel />
      <DirectoryPanel />
      <JournalPanel />
      <SharingPanel />
      <DavSharingPanel />
      {editing && <AccountModal editing={editing} onClose={() => setEditing(null)} onSaved={() => { accounts.reload(); invalidate('directory-policy'); }} />}
    </>
  );
}
