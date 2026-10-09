import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  AlertOctagon, Archive, ChevronLeft, Code2, Download, File, FileText, FolderInput, FolderPlus, FolderTree, Image as ImageIcon,
  Forward, Inbox, LogOut, Mail, MailOpen, Menu, Monitor, Moon, MoreHorizontal, Paperclip, Pencil, PenSquare, RefreshCw, Reply,
  ReplyAll, Search, Send, Share2, Sparkles, Star, Sun, Tag, Trash2, Users, X,
} from 'lucide-react';
import { OrganizeDialog } from './organize';
import { ComposeSeed, ComposeWindow, draftSeed, forwardSeed, replySeed } from './compose';
import {
  Api, ApiError, Attachment, Folder, Grant, Label, LabelPreview, Message, MessageDetail, MessagePage, Organize,
  can, formatFullDate, formatListDate, formatSize, hasFlag, isUserFolder, methodLabel, providerName, sharedFolderName, sortFolders, splitAddress,
} from './types';
import './style.css';

const PAGE = 50;

// ---------------------------------------------------------------------------
// Theme: follows the OS unless the user picks one (per browser).

type Theme = 'system' | 'light' | 'dark';
const themeKey = 'rmail-webmail-theme';

function storedTheme(): Theme {
  try {
    const value = localStorage.getItem(themeKey);
    return value === 'light' || value === 'dark' ? value : 'system';
  } catch {
    return 'system';
  }
}

function applyTheme(theme: Theme) {
  if (theme === 'system') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', theme);
}

applyTheme(storedTheme());

function ThemeSwitch() {
  const [theme, setTheme] = useState<Theme>(storedTheme);
  const choose = (next: Theme) => {
    setTheme(next);
    applyTheme(next);
    try {
      if (next === 'system') localStorage.removeItem(themeKey);
      else localStorage.setItem(themeKey, next);
    } catch {
      // storage unavailable: lasts for this page load
    }
  };
  const options: [Theme, string, React.ElementType][] = [['light', 'Light theme', Sun], ['system', 'Match system theme', Monitor], ['dark', 'Dark theme', Moon]];
  return (
    <div className="theme-switch" role="group" aria-label="Theme">
      {options.map(([id, label, Icon]) => (
        <button key={id} type="button" aria-pressed={theme === id} aria-label={label} title={label} onClick={() => choose(id)}><Icon size={14} /></button>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Small pieces

function useApi(onUnauthorized: () => void): Api {
  return useCallback(async <T,>(url: string, options?: RequestInit): Promise<T> => {
    // X-Rmail-Webmail marks the request as same-origin (CSRF protection).
    const res = await fetch(url, { ...options, credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-Rmail-Webmail': '1', ...(options?.headers || {}) } });
    if (res.status === 401 && !url.startsWith('/api/login') && !url.startsWith('/api/session')) onUnauthorized();
    if (!res.ok) throw new ApiError((await res.text()) || res.statusText, res.status);
    if (res.status === 204 || res.status === 201) return undefined as T;
    const type = res.headers.get('content-type') || '';
    return (type.includes('json') ? res.json() : res.text()) as Promise<T>;
  }, [onUnauthorized]) as Api;
}

function IconButton({ label, onClick, children, disabled, active, className }: { label: string; onClick: () => void; children: React.ReactNode; disabled?: boolean; active?: boolean; className?: string }) {
  return <button type="button" className={`icon ${active ? 'active' : ''} ${className || ''}`} aria-label={label} title={label} disabled={disabled} onClick={onClick}>{children}</button>;
}

function folderIcon(folder: Folder) {
  if (folder.owner) return Users;
  if (folder.name === 'INBOX') return Inbox;
  switch (folder.special_use) {
    case '\\Sent': return Send;
    case '\\Drafts': return Pencil;
    case '\\Archive': return Archive;
    case '\\Junk': return AlertOctagon;
    case '\\Trash': return Trash2;
    default: return FolderTree;
  }
}

const folderLabel = (folder: Folder) => (folder.owner ? sharedFolderName(folder) : folder.name === 'INBOX' ? 'Inbox' : folder.name);

/** Whether a bulk action is possible in `folder`: always in the user's own folders, by the rights in a shared one. */
function allowed(folder: Folder | undefined, action: string) {
  if (!folder?.owner) return true;
  switch (action) {
    case 'mark_read': case 'mark_unread': return can(folder, 's');
    case 'flag': case 'unflag': return can(folder, 'w');
    case 'delete': return can(folder, 't') && can(folder, 'e');
    default: return false;
  }
}

const accessLabel: Record<string, string> = { read: 'Can read', edit: 'Can read and change' };

/** Who one of the user's own folders is shared with, and changes to that. */
function ShareDialog({ api, folder, onClose }: { api: Api; folder: string; onClose: () => void }) {
  const [grants, setGrants] = useState<Grant[] | null>(null);
  const [address, setAddress] = useState('');
  const [access, setAccess] = useState<'read' | 'edit'>('read');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const base = `/api/folders/${encodeURIComponent(folder)}/sharing`;
  const load = useCallback(() => api<Grant[]>(base).then(setGrants).catch((err) => setError((err as Error).message)), [api, base]);
  useEffect(() => { load(); }, [load]);
  async function change(who: string, next: string) {
    setBusy(true);
    setError('');
    try {
      await api(base, { method: 'PUT', body: JSON.stringify({ address: who, access: next }) });
      await load();
      return true;
    } catch (err) {
      setError((err as Error).message);
      return false;
    } finally {
      setBusy(false);
    }
  }
  async function add(event: React.FormEvent) {
    event.preventDefault();
    if (await change(address.trim(), access)) setAddress('');
  }
  return (
    <div className="dialog-scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()} onKeyDown={(e) => e.key === 'Escape' && onClose()}>
      <section className="dialog" role="dialog" aria-label={`Share ${folder}`}>
        <header><h2>Share {folder === 'INBOX' ? 'Inbox' : folder}</h2><IconButton label="Close" onClick={onClose}><X size={16} /></IconButton></header>
        <p className="dialog-intro">People on this server you share with see the folder under “Shared with me” in webmail and under Other Users in mail apps. Read and starred marks are shared with them.</p>
        <form className="share-add" onSubmit={add}>
          <input aria-label="Address to share with" placeholder="colleague@example.com" value={address} onChange={(e) => setAddress(e.target.value)} />
          <select aria-label="Access" value={access} onChange={(e) => setAccess(e.target.value as 'read' | 'edit')}>
            <option value="read">{accessLabel.read}</option>
            <option value="edit">{accessLabel.edit}</option>
          </select>
          <button className="primary" disabled={busy || !address.trim()}>Share</button>
        </form>
        {error && <p className="error">{error}</p>}
        {grants === null ? <p className="muted">Loading…</p> : grants.length === 0 ? <p className="muted">Not shared with anyone.</p> : (
          <ul className="share-list">
            {grants.map((grant) => (
              <li key={grant.address}>
                <span className="share-who" title={grant.address}>{grant.address}</span>
                <select aria-label={`Access for ${grant.address}`} value={grant.access ?? ''} disabled={busy} onChange={(e) => change(grant.address, e.target.value)}>
                  {!grant.access && <option value="">Custom ({grant.rights})</option>}
                  <option value="read">{accessLabel.read}</option>
                  <option value="edit">{accessLabel.edit}</option>
                </select>
                <IconButton label={`Stop sharing with ${grant.address}`} disabled={busy} onClick={() => change(grant.address, 'none')}><X size={14} /></IconButton>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

function LabelChips({ labels, onRemove }: { labels: Label[]; onRemove?: (label: Label) => void }) {
  if (!labels.length) return null;
  return (
    <div className="label-chips">
      {labels.map((label) => (
        <span className="label-chip" key={label.keyword} title={label.description || label.name}>
          <Tag size={11} />{label.name}
          {onRemove && <button aria-label={`Remove label ${label.name}`} title="Remove label" onClick={(e) => { e.stopPropagation(); onRemove(label); }}><X size={11} /></button>}
        </span>
      ))}
    </div>
  );
}

/** A small modal: a text prompt (folder names) or a confirmation. */
function PromptDialog({ title, label, initial, confirm, danger, onSubmit, onClose }: { title: string; label?: string; initial?: string; confirm: string; danger?: boolean; onSubmit: (value: string) => Promise<void> | void; onClose: () => void }) {
  const [value, setValue] = useState(initial || '');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      await onSubmit(value.trim());
      onClose();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="dialog-scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <form className="dialog small" role="dialog" aria-label={title} onSubmit={submit} onKeyDown={(e) => e.key === 'Escape' && onClose()}>
        <header><h2>{title}</h2><IconButton label="Close" onClick={onClose}><X size={16} /></IconButton></header>
        {label && <label className="field"><span>{label}</span><input autoFocus value={value} onChange={(e) => setValue(e.target.value)} placeholder="Folder name, e.g. Projects or Projects/2026" /></label>}
        {error && <p className="error">{error}</p>}
        <footer><button type="button" className="secondary" onClick={onClose}>Cancel</button><button className={danger ? 'danger' : 'primary'} disabled={busy || (!!label && !value.trim())} autoFocus={!label}>{confirm}</button></footer>
      </form>
    </div>
  );
}

function RawDialog({ api, folder, uid, onClose }: { api: Api; folder: string; uid: number; onClose: () => void }) {
  const [raw, setRaw] = useState<string | null>(null);
  const [error, setError] = useState('');
  const base = `/api/folders/${encodeURIComponent(folder)}/messages/${uid}/raw`;
  useEffect(() => {
    api<string>(base).then(setRaw).catch((err) => setError((err as Error).message));
  }, [api, base]);
  return (
    <div className="dialog-scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()} onKeyDown={(e) => e.key === 'Escape' && onClose()}>
      <section className="dialog wide" role="dialog" aria-label="Message source">
        <header>
          <h2>Message source</h2>
          <div className="header-actions">
            <button className="secondary" disabled={!raw} onClick={() => raw && navigator.clipboard?.writeText(raw)}>Copy</button>
            <a className="button secondary" href={`${base}?download=1`} download><Download size={14} />Download .eml</a>
            <IconButton label="Close" onClick={onClose}><X size={16} /></IconButton>
          </div>
        </header>
        {error && <p className="error">{error}</p>}
        <pre className="raw-source" tabIndex={0}>{raw ?? 'Loading…'}</pre>
      </section>
    </div>
  );
}

function attachmentIcon(attachment: Attachment) {
  if (attachment.content_type.startsWith('image/')) return ImageIcon;
  if (attachment.content_type.startsWith('text/') || attachment.content_type === 'application/pdf') return FileText;
  return File;
}

function Attachments({ folder, uid, attachments }: { folder: string; uid: number; attachments: Attachment[] }) {
  if (!attachments.length) return null;
  const url = (a: Attachment, inline = false) => `/api/folders/${encodeURIComponent(folder)}/messages/${uid}/attachments/${a.index}${inline ? '?inline=1' : ''}`;
  const previewable = (a: Attachment) => ['image/png', 'image/jpeg', 'image/gif', 'image/webp'].includes(a.content_type);
  const total = attachments.reduce((sum, a) => sum + a.size, 0);
  return (
    <section className="attachments" aria-label="Attachments">
      <h3><Paperclip size={14} />{attachments.length} attachment{attachments.length === 1 ? '' : 's'} <small>{formatSize(total)}</small></h3>
      <div className="attachment-grid">
        {attachments.map((a) => {
          const Icon = attachmentIcon(a);
          return (
            <a key={a.index} className="attachment" href={url(a)} download={a.filename} title={`Download ${a.filename}`}>
              {previewable(a) ? <img src={url(a, true)} alt="" loading="lazy" /> : <span className="attachment-icon"><Icon size={20} /></span>}
              <span className="attachment-meta"><strong>{a.filename}</strong><small>{formatSize(a.size)}</small></span>
              <Download size={14} className="attachment-download" />
            </a>
          );
        })}
      </div>
    </section>
  );
}

/** On-demand AI actions for one message, when the server offers them. */
function AiPanel({ api, folder, message, organize, onLabelsChanged, onOpenSettings }: { api: Api; folder: string; message: MessageDetail; organize: Organize | null; onLabelsChanged: () => void; onOpenSettings: () => void }) {
  const [busy, setBusy] = useState<'summary' | 'labels' | null>(null);
  const [summary, setSummary] = useState<string | null>(null);
  const [preview, setPreview] = useState<LabelPreview | null>(null);
  const [error, setError] = useState('');
  const [consentNeeded, setConsentNeeded] = useState<string | null>(null);
  useEffect(() => { setSummary(null); setPreview(null); setError(''); setConsentNeeded(null); }, [message.uid]);
  if (!organize || (!organize.ai_labels && !organize.ai_summary)) return null;
  const base = `/api/folders/${encodeURIComponent(folder)}/messages/${message.uid}`;
  // The fallback model's provider, when it is a cloud one.
  const cloud = organize.labels_cloud ? organize.cloud_providers[organize.cloud_providers.length - 1] : null;

  async function run(action: 'summary' | 'labels') {
    setBusy(action);
    setError('');
    setConsentNeeded(null);
    try {
      const result = await api<{ summary?: string } & LabelPreview>(`${base}/ai`, { method: 'POST', body: JSON.stringify({ action }) });
      if (action === 'summary') setSummary(result.summary || '');
      else setPreview(result);
    } catch (err) {
      const text = (err as Error).message;
      if (err instanceof ApiError && err.status === 403 && text.startsWith('consent:')) setConsentNeeded(text.slice('consent:'.length));
      else setError(text);
    } finally {
      setBusy(null);
    }
  }

  async function apply(keyword: string, present: boolean) {
    await api(base, { method: 'PATCH', body: JSON.stringify({ keywords: { [keyword]: present } }) }).catch((err) => setError((err as Error).message));
    setPreview((p) => p && { ...p, labels: p.labels.map((l) => (l.keyword === keyword ? { ...l, applied: present } : l)) });
    onLabelsChanged();
  }

  async function addProposed() {
    if (!preview?.proposed) return;
    try {
      const label = await api<Label>('/api/organize/labels', { method: 'POST', body: JSON.stringify(preview.proposed) });
      await api(base, { method: 'PATCH', body: JSON.stringify({ keywords: { [label.keyword]: true } }) });
      setPreview({ ...preview, proposed: null, labels: [{ name: label.name, keyword: label.keyword, probability: 1, applied: true }, ...preview.labels] });
      onLabelsChanged();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  const sends = cloud ? `Sends this message's sender, subject and start of the body to ${providerName(cloud)}.` : 'Runs on this server.';
  const shown = preview ? preview.labels.filter((l) => l.probability >= 0.15).slice(0, 6) : [];
  return (
    <section className="ai-panel" aria-label="AI">
      <div className="ai-actions">
        <Sparkles size={15} className="ai-mark" />
        {organize.ai_summary && <button className="chip-button" disabled={busy !== null} onClick={() => run('summary')} title={sends}>{busy === 'summary' ? 'Summarizing…' : 'Summarize'}</button>}
        {organize.ai_labels && <button className="chip-button" disabled={busy !== null} onClick={() => run('labels')} title={sends}>{busy === 'labels' ? 'Thinking…' : 'Suggest labels'}</button>}
      </div>
      {consentNeeded && (
        <p className="ai-note">This uses {providerName(consentNeeded)}, which only receives your mail if you agree. <button className="link" onClick={onOpenSettings}>Review in Organize my mail</button></p>
      )}
      {error && <p className="error">{error}</p>}
      {summary !== null && <p className="ai-summary">{summary || 'The model returned no summary.'}</p>}
      {preview && (
        <div className="ai-labels">
          {shown.length === 0 && !preview.proposed && <span className="muted">No label fits this message.</span>}
          {shown.map((guess) => (
            <button key={guess.name} className={`guess ${guess.applied ? 'applied' : ''} ${guess.probability >= preview.threshold ? 'likely' : ''}`} disabled={!guess.keyword} onClick={() => guess.keyword && apply(guess.keyword, !guess.applied)} title={guess.applied ? 'Remove this label' : 'Add this label'}>
              <Tag size={11} />{guess.name}<small>{Math.round(guess.probability * 100)}%</small>
            </button>
          ))}
          {preview.proposed && (
            <button className="guess proposed" onClick={addProposed} title={preview.proposed.description}>
              <Sparkles size={11} />New label: {preview.proposed.name}
            </button>
          )}
        </div>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Mailbox

function Mailbox({ api, address, canSend, onLogout }: { api: Api; address: string; canSend: boolean; onLogout: () => void }) {
  const [folders, setFolders] = useState<Folder[]>([]);
  const [folder, setFolder] = useState('INBOX');
  const [messages, setMessages] = useState<Message[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState<MessageDetail | null>(null);
  const [checked, setChecked] = useState<number[]>([]);
  const [query, setQuery] = useState('');
  const [activeQuery, setActiveQuery] = useState('');
  const [view, setView] = useState<'folders' | 'list' | 'message'>('list');
  const [organize, setOrganize] = useState<Organize | null>(null);
  const [organizing, setOrganizing] = useState(false);
  const [prompt, setPrompt] = useState<React.ComponentProps<typeof PromptDialog> | null>(null);
  const [rawFor, setRawFor] = useState<number | null>(null);
  const [sharing, setSharing] = useState<string | null>(null);
  const [moveOpen, setMoveOpen] = useState(false);
  const [moreOpen, setMoreOpen] = useState(false);
  const [notice, setNotice] = useState('');
  const [compose, setCompose] = useState<ComposeSeed | null>(null);
  const searchRef = useRef<HTMLInputElement>(null);

  const flash = (text: string) => {
    setNotice(text);
    window.setTimeout(() => setNotice((current) => (current === text ? '' : current)), 4000);
  };

  const loadFolders = useCallback(async () => setFolders(sortFolders(await api<Folder[]>('/api/folders'))), [api]);
  const loadOrganize = useCallback(() => api<Organize>('/api/organize').then(setOrganize).catch(() => setOrganize(null)), [api]);

  const loadMessages = useCallback(async (name: string, q: string, offset = 0) => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ limit: String(PAGE), offset: String(offset) });
      if (q) params.set('q', q);
      const page = await api<MessagePage>(`/api/folders/${encodeURIComponent(name)}/messages?${params}`);
      setTotal(page.total);
      setMessages((current) => (offset ? [...current, ...page.messages] : page.messages));
    } finally {
      setLoading(false);
    }
  }, [api]);

  const refresh = useCallback(async () => {
    await Promise.all([loadFolders(), loadMessages(folder, activeQuery)]);
    setChecked([]);
  }, [loadFolders, loadMessages, folder, activeQuery]);

  useEffect(() => {
    loadOrganize();
    refresh().catch((err) => flash((err as Error).message));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // New mail without a manual refresh.
  useEffect(() => {
    const id = window.setInterval(() => {
      if (document.visibilityState === 'visible' && !activeQuery) {
        loadFolders().catch(() => undefined);
        loadMessages(folder, '', 0).catch(() => undefined);
      }
    }, 60000);
    return () => window.clearInterval(id);
  }, [folder, activeQuery, loadFolders, loadMessages]);

  const current = useMemo(() => folders.find((f) => f.name === folder), [folders, folder]);
  const userFolders = useMemo(() => folders.filter(isUserFolder), [folders]);
  const selectedListItem = selected ? messages.find((m) => m.uid === selected.uid) : undefined;
  const selectedIndex = selected ? messages.findIndex((m) => m.uid === selected.uid) : -1;
  const suggested = messages.filter((m) => m.suggestion).length;

  async function chooseFolder(name: string) {
    setFolder(name);
    setSelected(null);
    setChecked([]);
    setQuery('');
    setActiveQuery('');
    setView('list');
    await loadMessages(name, '').catch((err) => flash((err as Error).message));
  }

  async function search(event?: React.FormEvent) {
    event?.preventDefault();
    setActiveQuery(query.trim());
    setSelected(null);
    await loadMessages(folder, query.trim());
  }

  async function openMessage(message: Message) {
    const detail = await api<MessageDetail>(`/api/folders/${encodeURIComponent(folder)}/messages/${message.uid}`);
    setSelected(detail);
    setView('message');
    setMoreOpen(false);
    setMoveOpen(false);
    if (!hasFlag(message.flags, '\\Seen') && can(current, 's')) {
      await api(`/api/folders/${encodeURIComponent(folder)}/messages/${message.uid}`, { method: 'PATCH', body: JSON.stringify({ seen: true }) });
      setMessages((list) => list.map((m) => (m.uid === message.uid ? { ...m, flags: [...m.flags, '\\Seen'] } : m)));
      loadFolders().catch(() => undefined);
    }
  }

  async function loadRemoteContent() {
    if (!selected) return;
    const detail = await api<MessageDetail>(`/api/folders/${encodeURIComponent(folder)}/messages/${selected.uid}?remote_content=1`);
    setSelected({ ...detail, has_remote_content: false });
  }

  /** Apply a bulk action; moves remove the messages from the list and select the next one. */
  async function act(action: string, uids: number[], target?: string) {
    if (!uids.length) return;
    if (!allowed(current, action)) {
      flash('Not possible in this shared folder');
      return;
    }
    const removes = ['archive', 'delete', 'junk', 'move'].includes(action);
    const next = removes && selected && uids.includes(selected.uid) ? messages.filter((m) => !uids.includes(m.uid))[Math.max(0, selectedIndex)] : undefined;
    try {
      await api(`/api/folders/${encodeURIComponent(folder)}/messages/bulk`, { method: 'POST', body: JSON.stringify({ action, uids, ...(target ? { target } : {}) }) });
    } catch (err) {
      flash((err as Error).message);
      return;
    }
    setChecked([]);
    setMoveOpen(false);
    if (removes) {
      setMessages((list) => list.filter((m) => !uids.includes(m.uid)));
      setTotal((t) => t - uids.length);
      if (selected && uids.includes(selected.uid)) {
        if (next) openMessage(next).catch(() => setSelected(null));
        else { setSelected(null); setView('list'); }
      }
      const verb = action === 'move' ? `Moved to ${target}` : action === 'archive' ? 'Archived' : action === 'junk' ? 'Moved to Junk' : 'Deleted';
      flash(`${verb}: ${uids.length} message${uids.length === 1 ? '' : 's'}`);
    } else {
      const flag = action.endsWith('flag') ? '\\Flagged' : '\\Seen';
      const present = action === 'flag' || action === 'mark_read';
      const update = (flags: string[]) => (present ? [...flags.filter((f) => f !== flag), flag] : flags.filter((f) => f !== flag));
      setMessages((list) => list.map((m) => (uids.includes(m.uid) ? { ...m, flags: update(m.flags) } : m)));
      if (selected && uids.includes(selected.uid)) setSelected({ ...selected, flags: update(selected.flags) });
    }
    loadFolders().catch(() => undefined);
  }

  async function resolveSuggestion(uid: number, action: 'accept' | 'dismiss') {
    try {
      await api(`/api/suggestions/${uid}/${action}`, { method: 'POST' });
    } catch (err) {
      flash((err as Error).message);
    }
    if (selected?.uid === uid && action === 'accept') { setSelected(null); setView('list'); }
    await refresh();
  }

  async function acceptAll() {
    await api('/api/suggestions/accept-all', { method: 'POST' }).catch((err) => flash((err as Error).message));
    setSelected(null);
    await refresh();
  }

  /** Refresh one message's labels and flags in the list and the reader. */
  async function reloadMessage(uid: number) {
    const detail = await api<MessageDetail>(`/api/folders/${encodeURIComponent(folder)}/messages/${uid}`).catch(() => null);
    if (!detail) return;
    setMessages((list) => list.map((m) => (m.uid === uid ? { ...m, flags: detail.flags, labels: detail.labels } : m)));
    setSelected((s) => (s && s.uid === uid ? { ...s, flags: detail.flags, labels: detail.labels } : s));
  }

  async function removeLabel(uid: number, label: Label) {
    await api(`/api/folders/${encodeURIComponent(folder)}/messages/${uid}`, { method: 'PATCH', body: JSON.stringify({ keywords: { [label.keyword]: false } }) }).catch((err) => flash((err as Error).message));
    await reloadMessage(uid);
  }

  function newFolder() {
    setPrompt({
      title: 'New folder', label: 'Name', confirm: 'Create', onClose: () => setPrompt(null),
      onSubmit: async (name) => { await api('/api/folders', { method: 'POST', body: JSON.stringify({ name }) }); await loadFolders(); },
    });
  }

  function renameFolder(name: string) {
    setPrompt({
      title: `Rename ${name}`, label: 'New name', initial: name, confirm: 'Rename', onClose: () => setPrompt(null),
      onSubmit: async (next) => {
        await api(`/api/folders/${encodeURIComponent(name)}`, { method: 'PATCH', body: JSON.stringify({ name: next }) });
        await loadFolders();
        if (folder === name) await chooseFolder(next);
      },
    });
  }

  function deleteFolder(name: string) {
    setPrompt({
      title: `Delete ${name}?`, confirm: 'Delete folder', danger: true, onClose: () => setPrompt(null),
      onSubmit: async () => {
        await api(`/api/folders/${encodeURIComponent(name)}`, { method: 'DELETE' });
        await loadFolders();
        if (folder === name) await chooseFolder('INBOX');
      },
    });
  }

  // Keyboard shortcuts, like most mail clients.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement;
      if (target.closest('input, textarea, select, [contenteditable], .dialog, .compose') || compose || event.metaKey || event.ctrlKey || event.altKey) return;
      const move = (delta: number) => {
        const index = selectedIndex < 0 ? (delta > 0 ? 0 : messages.length - 1) : selectedIndex + delta;
        const message = messages[index];
        if (message) openMessage(message).catch(() => undefined);
      };
      const uids = selected ? [selected.uid] : checked;
      switch (event.key) {
        case 'j': move(1); break;
        case 'k': move(-1); break;
        case 'e': act('archive', uids); break;
        case '#': case 'Delete': act('delete', uids); break;
        case '!': act('junk', uids); break;
        case 's': if (selected) act(hasFlag(selected.flags, '\\Flagged') ? 'unflag' : 'flag', [selected.uid]); break;
        case 'u': if (selected && allowed(current, 'mark_unread')) { act('mark_unread', [selected.uid]); setSelected(null); setView('list'); } break;
        case 'c': if (canSend) { event.preventDefault(); setCompose({}); } break;
        case 'r': if (canSend && selected) { event.preventDefault(); setCompose(replySeed(selected, folder, address, false)); } break;
        case 'a': if (canSend && selected) { event.preventDefault(); setCompose(replySeed(selected, folder, address, true)); } break;
        case 'f': if (canSend && selected) { event.preventDefault(); setCompose(forwardSeed(selected, folder)); } break;
        case '/': event.preventDefault(); searchRef.current?.focus(); break;
        case 'Escape':
          // Close an open menu first; only then the message.
          if (moveOpen || moreOpen) { setMoveOpen(false); setMoreOpen(false); }
          else { setSelected(null); setView('list'); }
          break;
        default: return;
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  });

  const allChecked = messages.length > 0 && checked.length === messages.length;
  const shared = !!current?.owner;
  const ownFolders = folders.filter((f) => !f.owner);
  const sharedFolders = folders.filter((f) => f.owner);

  const moveMenu = (uids: number[]) => (
    <div className="menu" role="menu">
      {userFolders.filter((f) => f.name !== folder).map((f) => <button key={f.name} role="menuitem" onClick={() => act('move', uids, f.name)}><FolderTree size={14} />{f.name}</button>)}
      {folders.filter((f) => !isUserFolder(f) && f.name !== folder && f.special_use !== '\\Drafts' && f.special_use !== '\\Sent').map((f) => {
        const Icon = folderIcon(f);
        return <button key={f.name} role="menuitem" onClick={() => act('move', uids, f.name)}><Icon size={14} />{folderLabel(f)}</button>;
      })}
      {userFolders.length === 0 && <p className="menu-empty">No folders yet.</p>}
      <button role="menuitem" className="menu-new" onClick={() => { setMoveOpen(false); newFolder(); }}><FolderPlus size={14} />New folder…</button>
    </div>
  );

  return (
    <main className={`app view-${view}`}>
      <aside className="sidebar">
        <div className="brand"><div className="logo">rM</div><div><strong>rMail</strong><span title={address}>{address}</span></div></div>
        {canSend && <button className="compose-button" onClick={() => { setCompose({}); setView('list'); }}><PenSquare size={16} />Compose</button>}
        <nav aria-label="Folders">
          {ownFolders.map((f) => {
            const Icon = folderIcon(f);
            return (
              <div key={f.name} className={`folder ${f.name === folder ? 'active' : ''}`}>
                <button className="folder-name" onClick={() => chooseFolder(f.name)} aria-current={f.name === folder ? 'page' : undefined}>
                  <Icon size={16} /><span>{folderLabel(f)}</span>{f.unread > 0 && <small className="count">{f.unread}</small>}
                </button>
                <span className="folder-actions">
                  <button aria-label={`Share ${folderLabel(f)}`} title="Share" onClick={() => setSharing(f.name)}><Share2 size={12} /></button>
                  {isUserFolder(f) && <>
                    <button aria-label={`Rename ${f.name}`} title="Rename" onClick={() => renameFolder(f.name)}><Pencil size={12} /></button>
                    <button aria-label={`Delete ${f.name}`} title="Delete" onClick={() => deleteFolder(f.name)}><Trash2 size={12} /></button>
                  </>}
                </span>
              </div>
            );
          })}
          <button className="new-folder" onClick={newFolder}><FolderPlus size={15} />New folder</button>
          {sharedFolders.length > 0 && <h3 className="folder-group">Shared with me</h3>}
          {sharedFolders.map((f) => (
            <div key={f.name} className={`folder ${f.name === folder ? 'active' : ''}`}>
              <button className="folder-name shared" onClick={() => chooseFolder(f.name)} aria-current={f.name === folder ? 'page' : undefined} title={`${sharedFolderName(f)}, shared by ${f.owner}${can(f, 'w') || can(f, 't') ? '' : ' (read only)'}`}>
                <Users size={16} /><span>{folderLabel(f)}<small>{f.owner}</small></span>{f.unread > 0 && <small className="count">{f.unread}</small>}
              </button>
            </div>
          ))}
        </nav>
        <div className="sidebar-foot">
          <button className="sidebar-link" onClick={() => setOrganizing(true)}><Sparkles size={15} />Organize my mail</button>
          <ThemeSwitch />
          <button className="sidebar-link" onClick={onLogout}><LogOut size={15} />Sign out</button>
        </div>
      </aside>

      <section className="mailbox">
        <header className="topbar">
          <IconButton label="Folders" className="mobile-only" onClick={() => setView('folders')}><Menu size={18} /></IconButton>
          <form className="search" onSubmit={search} role="search">
            <Search size={16} />
            <input ref={searchRef} value={query} onChange={(e) => setQuery(e.target.value)} placeholder={`Search ${current ? folderLabel(current) : 'mail'}`} aria-label="Search mail" />
            {activeQuery && <button type="button" className="clear" aria-label="Clear search" onClick={() => { setQuery(''); setActiveQuery(''); loadMessages(folder, ''); }}><X size={14} /></button>}
          </form>
          <IconButton label="Refresh" onClick={() => refresh().catch((err) => flash((err as Error).message))}><RefreshCw size={16} className={loading ? 'spin' : ''} /></IconButton>
        </header>
        <div className="toolbar">
          <input type="checkbox" aria-label="Select all" checked={allChecked} ref={(el) => { if (el) el.indeterminate = checked.length > 0 && !allChecked; }} onChange={(e) => setChecked(e.target.checked ? messages.map((m) => m.uid) : [])} />
          {checked.length > 0 ? (
            <div className="bulk">
              <span>{checked.length} selected</span>
              {!shared && <IconButton label="Archive (e)" onClick={() => act('archive', checked)}><Archive size={16} /></IconButton>}
              {allowed(current, 'delete') && <IconButton label="Delete (#)" onClick={() => act('delete', checked)}><Trash2 size={16} /></IconButton>}
              {!shared && <>
                <IconButton label="Junk (!)" onClick={() => act('junk', checked)}><AlertOctagon size={16} /></IconButton>
                <span className="menu-anchor">
                  <IconButton label="Move to…" onClick={() => setMoveOpen(!moveOpen)}><FolderInput size={16} /></IconButton>
                  {moveOpen && moveMenu(checked)}
                </span>
              </>}
              {allowed(current, 'mark_read') && <>
                <IconButton label="Mark read" onClick={() => act('mark_read', checked)}><MailOpen size={16} /></IconButton>
                <IconButton label="Mark unread" onClick={() => act('mark_unread', checked)}><Mail size={16} /></IconButton>
              </>}
              {allowed(current, 'flag') && <IconButton label="Star" onClick={() => act('flag', checked)}><Star size={16} /></IconButton>}
            </div>
          ) : (
            <strong className="folder-title">{activeQuery ? `Results for “${activeQuery}”` : current ? folderLabel(current) : folder}</strong>
          )}
          {folder === 'INBOX' && suggested > 0 && !checked.length && <button className="accept-all" onClick={acceptAll} title="Move every suggested message to its suggested folder"><FolderInput size={14} />Move {suggested} suggested</button>}
          <span className="total">{total ? `${messages.length < total ? `${messages.length} of ` : ''}${total}` : ''}</span>
        </div>
        <div className="message-list" role="list">
          {messages.map((m) => {
            const from = splitAddress(m.from);
            const unread = !hasFlag(m.flags, '\\Seen');
            const starred = hasFlag(m.flags, '\\Flagged');
            return (
              <div key={m.uid} role="listitem" className={`row ${unread ? 'unread' : ''} ${selected?.uid === m.uid ? 'selected' : ''} ${checked.includes(m.uid) ? 'checked' : ''}`}>
                <input type="checkbox" aria-label={`Select ${m.subject || 'message'}`} checked={checked.includes(m.uid)} onChange={(e) => setChecked(e.target.checked ? [...checked, m.uid] : checked.filter((id) => id !== m.uid))} />
                <button className={`star ${starred ? 'on' : ''}`} aria-label={starred ? 'Unstar' : 'Star'} aria-pressed={starred} disabled={!allowed(current, 'flag')} onClick={() => act(starred ? 'unflag' : 'flag', [m.uid])}><Star size={15} /></button>
                <button className="row-main" onClick={() => openMessage(m).catch((err) => flash((err as Error).message))}>
                  <span className="from" title={from.address}>{from.name || '(unknown)'}</span>
                  <span className="date">{m.has_attachments && <Paperclip size={12} aria-label="Has attachments" />}{formatListDate(m.internal_date)}</span>
                  <span className="subject">{m.subject || '(no subject)'}</span>
                  <span className="snippet">{m.snippet}</span>
                </button>
                {(m.labels?.length || m.suggestion) ? (
                  <div className="row-extra">
                    <LabelChips labels={m.labels || []} onRemove={can(current, 'w') ? (label) => removeLabel(m.uid, label) : undefined} />
                    {m.suggestion && <div className="suggestion-chip"><button className="chip-move" onClick={() => resolveSuggestion(m.uid, 'accept')} title={`Suggested from ${methodLabel[m.suggestion.method]}`}><FolderInput size={12} />{m.suggestion.folder}</button><button className="chip-dismiss" onClick={() => resolveSuggestion(m.uid, 'dismiss')} aria-label="Not this folder" title="Not this folder"><X size={12} /></button></div>}
                  </div>
                ) : null}
              </div>
            );
          })}
          {!loading && messages.length === 0 && <div className="empty-list">{activeQuery ? 'No messages match your search.' : 'No messages here.'}</div>}
          {messages.length < total && <button className="load-more" disabled={loading} onClick={() => loadMessages(folder, activeQuery, messages.length)}>{loading ? 'Loading…' : `Load ${Math.min(PAGE, total - messages.length)} more`}</button>}
        </div>
      </section>

      <article className="reader">
        {selected ? (
          <>
            <div className="reader-actions">
              <IconButton label="Back" className="mobile-only" onClick={() => setView('list')}><ChevronLeft size={18} /></IconButton>
              {canSend && (current?.special_use === '\\Drafts' || hasFlag(selected.flags, '\\Draft')
                ? <button className="secondary small-button" onClick={() => setCompose(draftSeed(selected, folder))}><Pencil size={14} />Edit draft</button>
                : <>
                  <IconButton label="Reply (r)" onClick={() => setCompose(replySeed(selected, folder, address, false))}><Reply size={16} /></IconButton>
                  <IconButton label="Reply all (a)" onClick={() => setCompose(replySeed(selected, folder, address, true))}><ReplyAll size={16} /></IconButton>
                  <IconButton label="Forward (f)" onClick={() => setCompose(forwardSeed(selected, folder))}><Forward size={16} /></IconButton>
                  <span className="divider" />
                </>)}
              {!shared && <IconButton label="Archive (e)" onClick={() => act('archive', [selected.uid])}><Archive size={16} /></IconButton>}
              {allowed(current, 'delete') && <IconButton label="Delete (#)" onClick={() => act('delete', [selected.uid])}><Trash2 size={16} /></IconButton>}
              {!shared && <>
                <IconButton label="Junk (!)" onClick={() => act('junk', [selected.uid])}><AlertOctagon size={16} /></IconButton>
                <span className="menu-anchor">
                  <IconButton label="Move to…" onClick={() => { setMoveOpen(!moveOpen); setMoreOpen(false); }}><FolderInput size={16} /></IconButton>
                  {moveOpen && !checked.length && moveMenu([selected.uid])}
                </span>
              </>}
              {allowed(current, 'flag') && <IconButton label={hasFlag(selected.flags, '\\Flagged') ? 'Unstar (s)' : 'Star (s)'} active={hasFlag(selected.flags, '\\Flagged')} onClick={() => act(hasFlag(selected.flags, '\\Flagged') ? 'unflag' : 'flag', [selected.uid])}><Star size={16} /></IconButton>}
              {allowed(current, 'mark_unread') && <IconButton label="Mark unread (u)" onClick={() => { act('mark_unread', [selected.uid]); setSelected(null); setView('list'); }}><Mail size={16} /></IconButton>}
              <span className="spacer" />
              <span className="menu-anchor">
                <IconButton label="More" onClick={() => { setMoreOpen(!moreOpen); setMoveOpen(false); }}><MoreHorizontal size={16} /></IconButton>
                {moreOpen && (
                  <div className="menu right" role="menu">
                    <button role="menuitem" onClick={() => { setRawFor(selected.uid); setMoreOpen(false); }}><Code2 size={14} />View source</button>
                    <a role="menuitem" href={`/api/folders/${encodeURIComponent(folder)}/messages/${selected.uid}/raw?download=1`} download onClick={() => setMoreOpen(false)}><Download size={14} />Download .eml</a>
                  </div>
                )}
              </span>
            </div>
            <div className="reader-scroll">
              {selectedListItem?.suggestion && (
                <div className="suggestion-banner"><FolderInput size={16} /><span>Suggested folder: <strong>{selectedListItem.suggestion.folder}</strong>, based on {methodLabel[selectedListItem.suggestion.method]}.</span><button onClick={() => resolveSuggestion(selected.uid, 'accept')}>Move</button><button onClick={() => resolveSuggestion(selected.uid, 'dismiss')}>Not this</button></div>
              )}
              <h1 className="subject-line">{selected.subject || '(no subject)'}</h1>
              <LabelChips labels={selected.labels} onRemove={can(current, 'w') ? (label) => removeLabel(selected.uid, label) : undefined} />
              <div className="message-head">
                <div className="avatar" aria-hidden="true">{(splitAddress(selected.from).name || '?').charAt(0).toUpperCase()}</div>
                <div className="head-text">
                  <div><strong>{splitAddress(selected.from).name}</strong> <span className="muted">&lt;{splitAddress(selected.from).address}&gt;</span></div>
                  <div className="muted small">To {selected.to || address}{selected.cc && <> · Cc {selected.cc}</>}</div>
                  {selected.reply_to && selected.reply_to !== selected.from && <div className="muted small">Reply to {selected.reply_to}</div>}
                </div>
                <time className="muted small" title={selected.date}>{formatFullDate(selected.internal_date)}</time>
              </div>
              {!shared && <AiPanel api={api} folder={folder} message={selected} organize={organize} onLabelsChanged={() => reloadMessage(selected.uid)} onOpenSettings={() => setOrganizing(true)} />}
              {selected.html_body && selected.has_remote_content && <div className="remote-banner"><ImageIcon size={16} /><span>Remote images are blocked to protect your privacy.</span><button onClick={loadRemoteContent}>Load images</button></div>}
              {selected.html_body
                ? <iframe className="html-message" title="Message" sandbox="allow-popups allow-popups-to-escape-sandbox" srcDoc={selected.html_body} />
                : <pre className="text-message">{selected.text_body}</pre>}
              <Attachments folder={folder} uid={selected.uid} attachments={selected.attachments} />
            </div>
          </>
        ) : (
          <div className="empty"><Mail size={32} /><p>Select a message</p><small>Shortcuts: j/k next and previous · e archive · # delete · s star · / search{canSend ? ' · c compose · r reply · a reply all · f forward' : ''}</small></div>
        )}
      </article>

      {compose && (
        <ComposeWindow
          key={JSON.stringify(compose.source ?? compose.draft_uid ?? 'new')}
          api={api}
          from={address}
          seed={compose}
          onClose={(note) => { setCompose(null); if (note) flash(note); }}
          onSent={() => { loadFolders().catch(() => undefined); if (current?.special_use === '\\Drafts' || current?.special_use === '\\Sent') loadMessages(folder, activeQuery).catch(() => undefined); }}
        />
      )}
      {notice && <div className="toast" role="status">{notice}</div>}
      {organizing && <OrganizeDialog api={api} onClose={() => setOrganizing(false)} onSaved={() => { refresh(); loadOrganize(); }} />}
      {prompt && <PromptDialog {...prompt} />}
      {sharing !== null && <ShareDialog api={api} folder={sharing} onClose={() => setSharing(null)} />}
      {rawFor !== null && <RawDialog api={api} folder={folder} uid={rawFor} onClose={() => setRawFor(null)} />}
    </main>
  );
}

// ---------------------------------------------------------------------------
// Sign-in

function App() {
  const [address, setAddress] = useState<string | null | undefined>(undefined);
  const [canSend, setCanSend] = useState(false);
  const [loginAddress, setLoginAddress] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const api = useApi(useCallback(() => setAddress(null), []));

  useEffect(() => {
    api<{ address: string; can_send: boolean }>('/api/session').then((s) => { setCanSend(s.can_send); setAddress(s.address); }).catch(() => setAddress(null));
  }, [api]);

  async function login(event: React.FormEvent) {
    event.preventDefault();
    setError('');
    setBusy(true);
    try {
      const session = await api<{ address: string; can_send: boolean }>('/api/login', { method: 'POST', body: JSON.stringify({ address: loginAddress, password }) });
      setPassword('');
      setCanSend(session.can_send);
      setAddress(session.address);
    } catch (err) {
      setError(err instanceof ApiError && err.status === 429 ? err.message : 'Invalid mailbox or password');
    } finally {
      setBusy(false);
    }
  }

  async function logout() {
    await api('/api/logout', { method: 'POST' }).catch(() => undefined);
    setAddress(null);
  }

  if (address === undefined) return <div className="boot">Loading…</div>;
  if (!address) {
    return (
      <main className="login-shell">
        <form className="login-panel" onSubmit={login}>
          <div className="brand"><div className="logo">rM</div><div><strong>rMail</strong><span>Webmail</span></div></div>
          <label className="field"><span>Mailbox</span><input value={loginAddress} onChange={(e) => setLoginAddress(e.target.value)} placeholder="you@example.com" autoComplete="username" autoFocus /></label>
          <label className="field"><span>Password</span><input value={password} onChange={(e) => setPassword(e.target.value)} type="password" autoComplete="current-password" /></label>
          {error && <p className="error">{error}</p>}
          <button type="submit" className="primary" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
        </form>
      </main>
    );
  }
  return <Mailbox api={api} address={address} canSend={canSend} onLogout={logout} />;
}

createRoot(document.getElementById('root')!).render(<App />);
