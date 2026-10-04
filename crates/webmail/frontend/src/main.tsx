import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Archive, FolderInput, FolderTree, Image, LogOut, Mail, MailOpen, Menu, RefreshCw, Search, Trash2, X } from 'lucide-react';
import './style.css';

type Folder = { name: string; special_use: string | null; messages: number; unread: number };
type Suggestion = { folder: string; score: number; method: 'sender' | 'knn' | 'llm' };
type Message = { uid: number; flags: string[]; size: number; internal_date: number; from: string; to: string; subject: string; snippet: string; suggestion?: Suggestion };
type MessageDetail = Message & { date: string; text_body: string; html_body: string | null; has_remote_content: boolean };
type OrganizeFolder = { name: string; learned: number; accepted: number; dismissed: number; excluded: boolean; autofile: boolean };
type Organize = { server_enabled: boolean; enabled: boolean; pending: number; folders: OrganizeFolder[]; cloud_providers: string[]; cloud_consent: boolean; cloud_required: boolean };

type Api = <T>(url: string, options?: RequestInit) => Promise<T>;

const methodLabel: Record<Suggestion['method'], string> = {
  sender: 'where you file mail from this sender',
  knn: 'similar messages you filed',
  llm: 'an AI model',
};

const providerNames: Record<string, string> = {
  openrouter: 'OpenRouter (openrouter.ai)',
  typesafe: 'TypeSafe (typesafe.ai)',
};

function listNames(ids: string[]): string {
  const names = ids.map((id) => providerNames[id] || id);
  return names.length > 1 ? `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}` : names[0] || '';
}

function OrganizeDialog({ api, onClose, onSaved }: { api: Api; onClose: () => void; onSaved: () => void }) {
  const [data, setData] = useState<Organize | null>(null);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    api<Organize>('/api/organize').then(setData).catch((err) => setError((err as Error).message));
  }, []);

  function update(name: string, change: Partial<OrganizeFolder>) {
    if (!data) return;
    setData({ ...data, folders: data.folders.map((f) => (f.name === name ? { ...f, ...change } : f)) });
  }

  async function save() {
    if (!data) return;
    setSaving(true);
    try {
      await api('/api/organize', {
        method: 'PUT',
        body: JSON.stringify({
          enabled: data.enabled,
          ...(data.cloud_providers.length ? { cloud_consent: data.cloud_consent } : {}),
          excluded_folders: data.folders.filter((f) => f.excluded).map((f) => f.name),
          autofile_folders: data.folders.filter((f) => f.autofile && !f.excluded).map((f) => f.name),
        }),
      });
      onSaved();
      onClose();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="dialog-scrim" onClick={onClose}>
      <section className="dialog" role="dialog" aria-label="Organize my mail" onClick={(e) => e.stopPropagation()}>
        <header><h2>Organize my mail</h2><button className="icon" onClick={onClose} title="Close"><X size={18} /></button></header>
        {error && <p className="error">{error}</p>}
        {!data ? <p>Loading…</p> : <>
          <p className="dialog-intro">rMail learns from how you file mail into your folders and suggests a folder for new mail in your inbox.{' '}
            {data.cloud_providers.length === 0
              ? 'It runs entirely on this server; your mail is not sent anywhere.'
              : <>Your administrator uses {listNames(data.cloud_providers)} for this. They only receive your mail if you agree below.</>}
          </p>
          {!data.server_enabled && <p className="notice">Your administrator has not turned this on yet. Your choices are saved and take effect once they do.</p>}
          <label className="switch-row"><input type="checkbox" checked={data.enabled} onChange={(e) => setData({ ...data, enabled: e.target.checked })} /><span>Suggest folders for new mail</span></label>
          {data.enabled && data.cloud_providers.length > 0 && <>
            <label className="switch-row"><input type="checkbox" checked={data.cloud_consent} onChange={(e) => setData({ ...data, cloud_consent: e.target.checked })} /><span>Send my mail to {listNames(data.cloud_providers)} for suggestions</span></label>
            <p className="dialog-hint">
              {data.cloud_required
                ? 'The sender, subject and start of each message you file or receive are sent to them, including recent mail already in your folders. Without this, rMail cannot make suggestions for you.'
                : 'Only messages rMail is unsure about are sent: their sender, subject and the start of the body. Without this, suggestions still come from mail you filed, on this server.'}
              {' '}You can withdraw this at any time.
            </p>
          </>}
          {data.enabled && (data.folders.length === 0
            ? <p className="notice">Create a few folders and file some mail into them first; suggestions are based on your own filing.</p>
            : <table className="organize-table">
              <thead><tr><th>Folder</th><th>Learn &amp; suggest</th><th>Move automatically</th><th>Last 30 days</th></tr></thead>
              <tbody>{data.folders.map((f) => (
                <tr key={f.name}>
                  <td><strong>{f.name}</strong><small>{f.learned} messages learned</small></td>
                  <td><input type="checkbox" aria-label={`Suggest ${f.name}`} checked={!f.excluded} onChange={(e) => update(f.name, { excluded: !e.target.checked })} /></td>
                  <td><input type="checkbox" aria-label={`Move to ${f.name} automatically`} disabled={f.excluded} checked={f.autofile && !f.excluded} onChange={(e) => update(f.name, { autofile: e.target.checked })} /></td>
                  <td><small>{f.accepted} accepted · {f.dismissed} dismissed</small></td>
                </tr>
              ))}</tbody>
            </table>)}
          {data.enabled && <p className="dialog-hint">Automatic moves only happen when rMail is very confident and the suggestion is based on mail you filed yourself. Everything else stays in your inbox as a suggestion.</p>}
          <footer><button className="secondary" onClick={onClose}>Cancel</button><button className="primary" disabled={saving} onClick={save}>{saving ? 'Saving…' : 'Save'}</button></footer>
        </>}
      </section>
    </div>
  );
}

function App() {
  const [address, setAddress] = useState<string | null>(null);
  const [loginAddress, setLoginAddress] = useState('');
  const [password, setPassword] = useState('');
  const [folders, setFolders] = useState<Folder[]>([]);
  const [folder, setFolder] = useState('INBOX');
  const [messages, setMessages] = useState<Message[]>([]);
  const [selected, setSelected] = useState<MessageDetail | null>(null);
  const [checked, setChecked] = useState<number[]>([]);
  const [query, setQuery] = useState('');
  const [mobileView, setMobileView] = useState<'folders' | 'list' | 'message'>('list');
  const [error, setError] = useState('');
  const [organizing, setOrganizing] = useState(false);

  async function api<T>(url: string, options?: RequestInit): Promise<T> {
    // X-Rmail-Webmail marks the request as same-origin (CSRF protection).
    const res = await fetch(url, { ...options, credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-Rmail-Webmail': '1', ...(options?.headers || {}) } });
    if (!res.ok) throw Object.assign(new Error(await res.text() || res.statusText), { status: res.status });
    if (res.status === 204) return undefined as T;
    return res.json() as Promise<T>;
  }

  async function refresh(nextFolder = folder) {
    const q = query ? `&q=${encodeURIComponent(query)}` : '';
    const [folderData, messageData] = await Promise.all([
      api<Folder[]>('/api/folders'),
      api<Message[]>(`/api/folders/${encodeURIComponent(nextFolder)}/messages?limit=100${q}`),
    ]);
    setFolders(folderData);
    setMessages(messageData);
    setChecked([]);
  }

  useEffect(() => {
    api<{ address: string }>('/api/session').then((s) => {
      setAddress(s.address);
      return refresh();
    }).catch(() => setAddress(null));
  }, []);

  async function login(event: React.FormEvent) {
    event.preventDefault();
    setError('');
    try {
      const session = await api<{ address: string }>('/api/login', { method: 'POST', body: JSON.stringify({ address: loginAddress, password }) });
      setAddress(session.address);
      setPassword('');
      await refresh();
    } catch (err) {
      setError((err as { status?: number }).status === 429 ? (err as Error).message : 'Invalid mailbox or password');
    }
  }

  async function logout() {
    await api('/api/logout', { method: 'POST' }).catch(() => undefined);
    setAddress(null);
    setSelected(null);
    setMessages([]);
    setFolders([]);
  }

  async function loadRemoteContent() {
    if (!selected) return;
    const detail = await api<MessageDetail>(`/api/folders/${encodeURIComponent(folder)}/messages/${selected.uid}?remote_content=1`);
    setSelected({ ...detail, has_remote_content: false });
  }

  async function openMessage(message: Message) {
    const detail = await api<MessageDetail>(`/api/folders/${encodeURIComponent(folder)}/messages/${message.uid}`);
    setSelected(detail);
    setMobileView('message');
    if (!message.flags.some((f) => f.toLowerCase() === '\\seen')) {
      await api(`/api/folders/${encodeURIComponent(folder)}/messages/${message.uid}`, { method: 'PATCH', body: JSON.stringify({ seen: true }) });
      await refresh();
    }
  }

  async function actOnSelected(action: string) {
    if (!selected) return;
    await api(`/api/folders/${encodeURIComponent(folder)}/messages/bulk`, { method: 'POST', body: JSON.stringify({ action, uids: [selected.uid] }) });
    setSelected(null);
    setChecked([]);
    setMobileView('list');
    await refresh();
  }

  async function resolveSuggestion(uid: number, action: 'accept' | 'dismiss') {
    try {
      await api(`/api/suggestions/${uid}/${action}`, { method: 'POST' });
    } catch (err) {
      window.alert((err as Error).message);
    }
    if (selected?.uid === uid) {
      if (action === 'accept') {
        setSelected(null);
        setMobileView('list');
      } else {
        setSelected({ ...selected, suggestion: undefined });
      }
    }
    await refresh();
  }

  async function acceptAll() {
    await api('/api/suggestions/accept-all', { method: 'POST' }).catch((err) => window.alert((err as Error).message));
    setSelected(null);
    await refresh();
  }

  async function chooseFolder(name: string) {
    setFolder(name);
    setSelected(null);
    setMobileView('list');
    await refresh(name);
  }

  const title = useMemo(() => folders.find((f) => f.name === folder)?.name || folder, [folders, folder]);
  const suggested = messages.filter((m) => m.suggestion).length;
  const selectedSuggestion = selected ? messages.find((m) => m.uid === selected.uid)?.suggestion : undefined;

  if (!address) {
    return <main className="login-shell"><form className="login-panel" onSubmit={login}><h1>rMail</h1><input value={loginAddress} onChange={(e) => setLoginAddress(e.target.value)} placeholder="Mailbox" autoComplete="username" /><input value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" type="password" autoComplete="current-password" />{error && <p className="error">{error}</p>}<button type="submit">Sign in</button></form></main>;
  }

  return (
    <main className={`app mobile-${mobileView}`}>
      <aside className="folders"><div className="account">{address}</div>{folders.map((f) => <button key={f.name} className={f.name === folder ? 'active' : ''} onClick={() => chooseFolder(f.name)}><span>{f.name}</span><small>{f.unread ? f.unread : f.messages}</small></button>)}</aside>
      <section className="mailbox">
        <header className="topbar"><button className="icon mobile-only" onClick={() => setMobileView('folders')} title="Folders"><Menu size={18} /></button><div className="search"><Search size={18} /><input value={query} onChange={(e) => setQuery(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && refresh()} placeholder="Search mail" /></div><button className="icon" onClick={() => refresh()} title="Refresh"><RefreshCw size={18} /></button><button className="icon" onClick={() => setOrganizing(true)} title="Organize my mail"><FolderTree size={18} /></button><button className="icon" onClick={logout} title="Sign out"><LogOut size={18} /></button></header>
        <div className="toolbar"><strong>{title}</strong>{folder === 'INBOX' && suggested > 0 && <button className="accept-all" onClick={acceptAll} title="Move every suggested message to its suggested folder"><FolderInput size={15} />Move {suggested} suggested</button>}<span>{messages.length}</span></div>
        <div className="message-list">{messages.map((m) => <div key={m.uid} className={`row ${m.flags.some((f) => f.toLowerCase() === '\\seen') ? '' : 'unread'}`}><input type="checkbox" checked={checked.includes(m.uid)} onChange={(e) => setChecked(e.target.checked ? [...checked, m.uid] : checked.filter((id) => id !== m.uid))} /><button onClick={() => openMessage(m)}><span className="from">{m.from || '(unknown)'}</span><span className="subject">{m.subject || '(no subject)'}</span><span className="snippet">{m.snippet}</span></button>{m.suggestion && <div className="suggestion-chip"><button className="chip-move" onClick={() => resolveSuggestion(m.uid, 'accept')} title={`Suggested from ${methodLabel[m.suggestion.method]}`}><FolderInput size={13} />{m.suggestion.folder}</button><button className="chip-dismiss" onClick={() => resolveSuggestion(m.uid, 'dismiss')} title="Not this folder"><X size={13} /></button></div>}</div>)}</div>
      </section>
      <article className="reader">{selected ? <><div className="reader-actions"><button className="back mobile-only" onClick={() => setMobileView('list')}>Back</button><button className="icon" onClick={() => actOnSelected('archive')} title="Archive"><Archive size={18} /></button><button className="icon" onClick={() => actOnSelected('delete')} title="Delete"><Trash2 size={18} /></button><button className="icon" onClick={() => actOnSelected('mark_read')} title="Mark read"><MailOpen size={18} /></button><button className="icon" onClick={() => actOnSelected('mark_unread')} title="Mark unread"><Mail size={18} /></button></div>{selectedSuggestion && <div className="suggestion-banner"><FolderInput size={16} /><span>Suggested folder: <strong>{selectedSuggestion.folder}</strong>, based on {methodLabel[selectedSuggestion.method]}.</span><button onClick={() => resolveSuggestion(selected.uid, 'accept')}>Move</button><button onClick={() => resolveSuggestion(selected.uid, 'dismiss')}>Not this</button></div>}<h2>{selected.subject || '(no subject)'}</h2><div className="meta">From {selected.from || '(unknown)'} to {selected.to || address}</div>{selected.html_body && selected.has_remote_content && <div className="remote-banner"><Image size={16} /><span>Remote images are blocked to protect your privacy.</span><button onClick={loadRemoteContent}>Load images</button></div>}{selected.html_body ? <iframe className="html-message" sandbox="allow-popups allow-popups-to-escape-sandbox" srcDoc={selected.html_body} /> : <pre>{selected.text_body}</pre>}</> : <div className="empty">Select a message</div>}</article>
      {organizing && <OrganizeDialog api={api} onClose={() => setOrganizing(false)} onSaved={() => refresh()} />}
    </main>
  );
}

createRoot(document.getElementById('root')!).render(<App />);
