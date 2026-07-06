import React, { useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Archive, Mail, MailOpen, Menu, RefreshCw, Search, Trash2 } from 'lucide-react';
import './style.css';

type Folder = { name: string; special_use: string | null; messages: number; unread: number };
type Message = { uid: number; flags: string[]; size: number; internal_date: number; from: string; to: string; subject: string; snippet: string };
type MessageDetail = Message & { date: string; text_body: string; html_body: string | null };

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
  const iframeRef = useRef<HTMLIFrameElement | null>(null);

  async function api<T>(url: string, options?: RequestInit): Promise<T> {
    const res = await fetch(url, { credentials: 'same-origin', headers: { 'Content-Type': 'application/json', ...(options?.headers || {}) }, ...options });
    if (!res.ok) throw new Error(await res.text() || res.statusText);
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
    } catch {
      setError('Invalid mailbox or password');
    }
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

  async function chooseFolder(name: string) {
    setFolder(name);
    setSelected(null);
    setMobileView('list');
    await refresh(name);
  }

  const title = useMemo(() => folders.find((f) => f.name === folder)?.name || folder, [folders, folder]);

  useEffect(() => {
    const iframe = iframeRef.current;
    if (!iframe || !selected?.html_body) return;
    const resize = () => {
      const doc = iframe.contentDocument;
      if (!doc) return;
      iframe.style.height = `${Math.max(320, doc.documentElement.scrollHeight, doc.body.scrollHeight)}px`;
    };
    iframe.addEventListener('load', resize);
    const id = window.setTimeout(resize, 100);
    return () => {
      iframe.removeEventListener('load', resize);
      window.clearTimeout(id);
    };
  }, [selected]);

  if (!address) {
    return <main className="login-shell"><form className="login-panel" onSubmit={login}><h1>rMail</h1><input value={loginAddress} onChange={(e) => setLoginAddress(e.target.value)} placeholder="Mailbox" autoComplete="username" /><input value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" type="password" autoComplete="current-password" />{error && <p className="error">{error}</p>}<button type="submit">Sign in</button></form></main>;
  }

  return (
    <main className={`app mobile-${mobileView}`}>
      <aside className="folders"><div className="account">{address}</div>{folders.map((f) => <button key={f.name} className={f.name === folder ? 'active' : ''} onClick={() => chooseFolder(f.name)}><span>{f.name}</span><small>{f.unread ? f.unread : f.messages}</small></button>)}</aside>
      <section className="mailbox">
        <header className="topbar"><button className="icon mobile-only" onClick={() => setMobileView('folders')} title="Folders"><Menu size={18} /></button><div className="search"><Search size={18} /><input value={query} onChange={(e) => setQuery(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && refresh()} placeholder="Search mail" /></div><button className="icon" onClick={() => refresh()} title="Refresh"><RefreshCw size={18} /></button></header>
        <div className="toolbar"><strong>{title}</strong><span>{messages.length}</span></div>
        <div className="message-list">{messages.map((m) => <div key={m.uid} className={`row ${m.flags.some((f) => f.toLowerCase() === '\\seen') ? '' : 'unread'}`}><input type="checkbox" checked={checked.includes(m.uid)} onChange={(e) => setChecked(e.target.checked ? [...checked, m.uid] : checked.filter((id) => id !== m.uid))} /><button onClick={() => openMessage(m)}><span className="from">{m.from || '(unknown)'}</span><span className="subject">{m.subject || '(no subject)'}</span><span className="snippet">{m.snippet}</span></button></div>)}</div>
      </section>
      <article className="reader">{selected ? <><div className="reader-actions"><button className="back mobile-only" onClick={() => setMobileView('list')}>Back</button><button className="icon" onClick={() => actOnSelected('archive')} title="Archive"><Archive size={18} /></button><button className="icon" onClick={() => actOnSelected('delete')} title="Delete"><Trash2 size={18} /></button><button className="icon" onClick={() => actOnSelected('mark_read')} title="Mark read"><MailOpen size={18} /></button><button className="icon" onClick={() => actOnSelected('mark_unread')} title="Mark unread"><Mail size={18} /></button></div><h2>{selected.subject || '(no subject)'}</h2><div className="meta">From {selected.from || '(unknown)'} to {selected.to || address}</div>{selected.html_body ? <iframe ref={iframeRef} className="html-message" sandbox="allow-popups allow-popups-to-escape-sandbox" srcDoc={selected.html_body} /> : <pre>{selected.text_body}</pre>}</> : <div className="empty">Select a message</div>}</article>
    </main>
  );
}

createRoot(document.getElementById('root')!).render(<App />);
