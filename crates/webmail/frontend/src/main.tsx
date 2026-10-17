import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  AlertOctagon, Archive, ChevronLeft, Code2, Download, File, FileText, FolderInput, FolderPlus, FolderTree, Image as ImageIcon,
  Forward, Inbox, LogOut, Mail, MailOpen, Menu, Monitor, Moon, MoreHorizontal, Paperclip, Pencil, PenSquare, RefreshCw, Reply,
  PenLine, ReplyAll, Search, Send, Share2, Sparkles, Star, Sun, Tag, Trash2, Users, X, CalendarDays, BookUser, ShieldCheck, Lock, HardDrive,
} from 'lucide-react';
import { useCrypto } from './crypto/hook';
const FilesDialog = React.lazy(() => import('./files').then((m) => ({ default: m.FilesDialog })));
const EncryptionDialog = React.lazy(() => import('./crypto/settings').then((m) => ({ default: m.EncryptionDialog })));
import { ENCRYPTED, ProtectedMessage } from './crypto/reader';
const OrganizeDialog = React.lazy(() => import('./organize').then((m) => ({ default: m.OrganizeDialog })));
import { ComposeSeed, ComposeWindow, draftSeed, forwardSeed, replySeed } from './compose';
const ComposeSettingsDialog = React.lazy(() => import('./settings').then((m) => ({ default: m.ComposeSettingsDialog })));
import { ContactSeed, ContactsDialog } from './contacts';
import { CalendarView } from './calendar';
import { SecurityDialog } from './security';
import { BookingCard, InvitationCard } from './invitation';
import { RelatedPanel } from './related';
import { FilterIcon, FiltersDialog, Vacation, VacationDialog, VacationIcon, vacationNote } from './rules';
import {
  Api, ApiError, Attachment, CalendarListing, ComposePrefs, DavCollection, Folder, Grant, Identity, Label, LabelPreview, Message, MessageDetail, MessagePage, Organize, SendResult,
  can, formatFullDate, formatListDate, formatSize, hasFlag, isUserFolder, methodLabel, providerName, sharedFolderName, sortFolders, splitAddress,
} from './types';
import './style.css';

const PAGE = 50;

type Notice = { text: string; action?: { label: string; run: () => void } };

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

function useApi(onUnauthorized: () => void, onSetupRequired?: () => void): Api {
  return useCallback(async <T,>(url: string, options?: RequestInit): Promise<T> => {
    // X-Rmail-Webmail marks the request as same-origin (CSRF protection).
    const res = await fetch(url, { ...options, credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-Rmail-Webmail': '1', ...(options?.headers || {}) } });
    if (res.status === 401 && !url.startsWith('/api/login') && !url.startsWith('/api/session')) onUnauthorized();
    if (!res.ok) {
      const text = await res.text();
      // Errors meant for the user come as {"error": "..."}; show just that.
      let message = text || res.statusText;
      try {
        const parsed = JSON.parse(text);
        if (parsed && typeof parsed.error === 'string') message = parsed.error;
        else if (parsed && parsed.two_factor === true) message = 'two_factor';
        // The domain started requiring 2FA while the app was open.
        if (res.status === 403 && parsed && parsed.two_factor_setup === true) onSetupRequired?.();
      } catch { /* plain text */ }
      throw new ApiError(message, res.status);
    }
    if (res.status === 204 || res.status === 201) return undefined as T;
    const type = res.headers.get('content-type') || '';
    return (type.includes('json') ? res.json() : res.text()) as Promise<T>;
  }, [onUnauthorized, onSetupRequired]) as Api;
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
function FolderShareDialog({ api, folder, onClose }: { api: Api; folder: string; onClose: () => void }) {
  const base = `/api/folders/${encodeURIComponent(folder)}/sharing`;
  const load = useCallback(() => api<Grant[]>(base), [api, base]);
  return (
    <ShareDialog api={api} base={base} load={load} name={folder === 'INBOX' ? 'Inbox' : folder} onClose={onClose}
      intro="People on this server you share with see the folder under “Shared with me” in webmail and under Other Users in mail apps. Read and starred marks are shared with them." />
  );
}

const davIntro = 'People on this server you share with see it in their calendar or contacts app (CalDAV/CardDAV) next to their own, read-only or with changes allowed. With changes allowed, invitations they send from a shared calendar come from you.';

/** The user's calendars and address books, shared from here since most calendar apps cannot share. */
function CalendarsDialog({ api, onClose }: { api: Api; onClose: () => void }) {
  const [listing, setListing] = useState<CalendarListing | null>(null);
  const [error, setError] = useState('');
  const [sharing, setSharing] = useState<DavCollection | null>(null);
  const load = useCallback(() => api<CalendarListing>('/api/calendars').then(setListing).catch((err) => setError((err as Error).message)), [api]);
  useEffect(() => { load(); }, [load]);
  const grantsOf = useCallback(async () => {
    const fresh = await api<CalendarListing>('/api/calendars');
    setListing(fresh);
    const found = fresh.own.find((c) => c.kind === sharing?.kind && c.name === sharing?.name);
    return (found?.grants ?? []).map((grant) => ({ ...grant, rights: '' }));
  }, [api, sharing]);
  if (sharing) {
    return (
      <ShareDialog api={api} base={`/api/calendars/${sharing.kind}/${encodeURIComponent(sharing.name)}/sharing`} load={grantsOf}
        name={sharing.displayname} intro={davIntro} onClose={() => setSharing(null)} />
    );
  }
  const icon = (kind: string) => (kind === 'calendar' ? <CalendarDays size={16} /> : <BookUser size={16} />);
  return (
    <div className="dialog-scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()} onKeyDown={(e) => e.key === 'Escape' && onClose()}>
      <section className="dialog" role="dialog" aria-label="Calendar sharing">
        <header><h2>Calendar sharing</h2><IconButton label="Close" onClick={onClose}><X size={16} /></IconButton></header>
        <p className="dialog-intro">Share your calendars and address books with other people on this server.</p>
        {error && <p className="error">{error}</p>}
        {listing === null ? <p className="muted">Loading…</p> : (
          <>
            <ul className="share-list">
              {listing.own.map((collection) => (
                <li key={`${collection.kind} ${collection.name}`}>
                  {icon(collection.kind)}
                  <span className="share-who" title={collection.displayname}>
                    {collection.displayname}
                    <small className="muted"> {collection.grants.length === 0 ? 'not shared' : `shared with ${collection.grants.length}`}</small>
                  </span>
                  <IconButton label={`Share ${collection.displayname}`} onClick={() => setSharing(collection)}><Share2 size={14} /></IconButton>
                </li>
              ))}
            </ul>
            {listing.shared.length > 0 && <h3 className="folder-group">Shared with me</h3>}
            <ul className="share-list">
              {listing.shared.map((collection) => (
                <li key={`${collection.kind} ${collection.owner} ${collection.name}`}>
                  {icon(collection.kind)}
                  <span className="share-who">{collection.displayname}<small className="muted"> from {collection.owner}{collection.access === 'read' ? ', read only' : ''}</small></span>
                </li>
              ))}
            </ul>
          </>
        )}
      </section>
    </div>
  );
}

/** Who something of the user's is shared with (grants loaded by `load`, changed by PUT to `base`). */
function ShareDialog({ api, base, load: fetchGrants, name, intro, onClose }: { api: Api; base: string; load: () => Promise<Grant[]>; name: string; intro: string; onClose: () => void }) {
  const [grants, setGrants] = useState<Grant[] | null>(null);
  const [address, setAddress] = useState('');
  const [access, setAccess] = useState<'read' | 'edit'>('read');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const load = useCallback(() => fetchGrants().then(setGrants).catch((err) => setError((err as Error).message)), [fetchGrants]);
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
      <section className="dialog" role="dialog" aria-label={`Share ${name}`}>
        <header><h2>Share {name}</h2><IconButton label="Close" onClick={onClose}><X size={16} /></IconButton></header>
        <p className="dialog-intro">{intro}</p>
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
type FoundEvent = { title: string; date: string; start: string | null; end: string | null; location: string | null };
type FoundContact = { name: string | null; email: string | null; phone: string | null; organization: string | null; title: string | null };
type Found = { events: FoundEvent[]; contact: FoundContact | null };

/** Unix seconds for a found event: its times in the user's zone, or the whole day. */
function eventTimes(event: FoundEvent): { start: number; end: number; all_day: boolean } {
  const [y, m, d] = event.date.split('-').map(Number);
  if (!event.start) {
    const start = Date.UTC(y, m - 1, d) / 1000;
    return { start, end: start + 86_400, all_day: true };
  }
  const at = (time: string) => { const [h, min] = time.split(':').map(Number); return new Date(y, m - 1, d, h, min).getTime() / 1000; };
  const start = at(event.start);
  const end = event.end ? at(event.end) : start + 3600;
  return { start, end: end > start ? end : start + 3600, all_day: false };
}

function describeEvent(event: FoundEvent): string {
  const [y, m, d] = event.date.split('-').map(Number);
  const day = new Date(y, m - 1, d).toLocaleDateString(undefined, { weekday: 'short', day: 'numeric', month: 'short', year: 'numeric' });
  return event.start ? `${day}, ${event.start}${event.end ? `–${event.end}` : ''}` : `${day}, all day`;
}

function AiPanel({ api, folder, message, organize, onLabelsChanged, onOpenSettings, onSaveContact }: { api: Api; folder: string; message: MessageDetail; organize: Organize | null; onLabelsChanged: () => void; onOpenSettings: () => void; onSaveContact: (seed: ContactSeed) => void }) {
  const [busy, setBusy] = useState<'summary' | 'labels' | 'extract' | null>(null);
  const [summary, setSummary] = useState<string | null>(null);
  const [preview, setPreview] = useState<LabelPreview | null>(null);
  const [found, setFound] = useState<Found | null>(null);
  const [added, setAdded] = useState<number[]>([]);
  const [adding, setAdding] = useState<number | null>(null);
  const [error, setError] = useState('');
  const [consentNeeded, setConsentNeeded] = useState<string | null>(null);
  useEffect(() => { setSummary(null); setPreview(null); setFound(null); setAdded([]); setAdding(null); setError(''); setConsentNeeded(null); }, [message.uid]);
  if (!organize || (!organize.ai_labels && !organize.ai_summary)) return null;
  const base = `/api/folders/${encodeURIComponent(folder)}/messages/${message.uid}`;
  // The fallback model's provider, when it is a cloud one.
  const cloud = organize.labels_cloud ? organize.cloud_providers[organize.cloud_providers.length - 1] : null;

  async function run(action: 'summary' | 'labels' | 'extract') {
    setBusy(action);
    setError('');
    setConsentNeeded(null);
    try {
      const result = await api<{ summary?: string } & LabelPreview & Found>(`${base}/ai`, { method: 'POST', body: JSON.stringify({ action }) });
      if (action === 'summary') setSummary(result.summary || '');
      else if (action === 'extract') setFound({ events: result.events ?? [], contact: result.contact ?? null });
      else setPreview(result);
    } catch (err) {
      const text = (err as Error).message;
      if (err instanceof ApiError && err.status === 403 && text.startsWith('consent:')) setConsentNeeded(text.slice('consent:'.length));
      else setError(text);
    } finally {
      setBusy(null);
    }
  }

  async function addEvent(event: FoundEvent, index: number) {
    // One event per click, however fast the clicks come.
    if (adding !== null) return;
    setAdding(index);
    try {
      await api('/api/events/own:default', { method: 'POST', body: JSON.stringify({
        summary: event.title, location: event.location ?? '',
        description: `From the message "${message.subject}" from ${message.from}.`,
        ...eventTimes(event), timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, repeat: 'none', attendees: [],
      }) });
      setAdded((list) => [...list, index]);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setAdding(null);
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
        {organize.ai_summary && <button className="chip-button" disabled={busy !== null} onClick={() => run('extract')} title={sends}>{busy === 'extract' ? 'Looking…' : 'Find dates and contacts'}</button>}
      </div>
      {found && (
        <div className="ai-found">
          {found.events.length === 0 && !found.contact && <span className="muted">No dates or contact details found.</span>}
          {found.events.map((event, index) => (
            <div key={index} className="ai-found-item">
              <CalendarDays size={15} />
              <span><strong>{event.title}</strong><small className="muted">{describeEvent(event)}{event.location ? ` · ${event.location}` : ''}</small></span>
              {added.includes(index)
                ? <span className="muted small">Added to your calendar</span>
                : <button className="secondary small-button" disabled={adding !== null} onClick={() => addEvent(event, index)}>{adding === index ? 'Adding…' : 'Add to calendar'}</button>}
            </div>
          ))}
          {found.contact && (
            <div className="ai-found-item">
              <BookUser size={15} />
              <span><strong>{found.contact.name || found.contact.email || found.contact.phone}</strong>
                <small className="muted">{[found.contact.title, found.contact.organization, found.contact.email, found.contact.phone].filter(Boolean).join(' · ')}</small></span>
              <button className="secondary small-button" onClick={() => onSaveContact({
                name: found.contact!.name ?? undefined, email: found.contact!.email ?? (splitAddress(message.from).address || undefined),
                phone: found.contact!.phone ?? undefined, org: found.contact!.organization ?? undefined, title: found.contact!.title ?? undefined,
              })}>Save contact</button>
            </div>
          )}
        </div>
      )}
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

function Mailbox({ api, address, canSend, files, onLogout }: { api: Api; address: string; canSend: boolean; files: boolean; onLogout: () => void }) {
  const [folders, setFolders] = useState<Folder[]>([]);
  const [folder, setFolder] = useState('INBOX');
  const [messages, setMessages] = useState<Message[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState<MessageDetail | null>(null);
  const [checked, setChecked] = useState<number[]>([]);
  const [query, setQuery] = useState('');
  const [activeQuery, setActiveQuery] = useState('');
  /** Search by meaning (the user's index) rather than by words. */
  const [byMeaning, setByMeaning] = useState(false);
  /** Whether the search shown (`activeQuery`) is by meaning. */
  const [activeMeaning, setActiveMeaning] = useState(false);
  const [view, setView] = useState<'folders' | 'list' | 'message'>('list');
  const [organize, setOrganize] = useState<Organize | null>(null);
  const [organizing, setOrganizing] = useState(false);
  const [prompt, setPrompt] = useState<React.ComponentProps<typeof PromptDialog> | null>(null);
  const [rawFor, setRawFor] = useState<number | null>(null);
  const [sharing, setSharing] = useState<string | null>(null);
  const [calendars, setCalendars] = useState(false);
  const [moveOpen, setMoveOpen] = useState(false);
  const [moreOpen, setMoreOpen] = useState(false);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [compose, setCompose] = useState<ComposeSeed | null>(null);
  const [prefs, setPrefs] = useState<ComposePrefs>({ format: 'html', language: '', undo_seconds: 0, ai_suggestions: false });
  const [identities, setIdentities] = useState<Identity[]>([]);
  const [composeSettings, setComposeSettings] = useState(false);
  const [contacts, setContacts] = useState<ContactSeed | null | false>(false);
  const [calendarMode, setCalendarMode] = useState(false);
  const [securityOpen, setSecurityOpen] = useState(false);
  const [encryptionOpen, setEncryptionOpen] = useState(false);
  const [filesOpen, setFilesOpen] = useState(false);
  const [crypto, cryptoPrompt] = useCrypto(api, address);
  const [vacation, setVacation] = useState<Vacation | null>(null);
  const [vacationOpen, setVacationOpen] = useState(false);
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [remoteLoaded, setRemoteLoaded] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);

  const flash = (text: string, action?: Notice['action'], seconds = 4) => {
    const next = { text, action };
    setNotice(next);
    window.setTimeout(() => setNotice((current) => (current === next ? null : current)), seconds * 1000);
  };

  const loadComposeSettings = useCallback(() => {
    if (!canSend) return;
    api<ComposePrefs>('/api/compose/settings').then(setPrefs).catch(() => undefined);
    api<Identity[]>('/api/identities').then(setIdentities).catch(() => undefined);
  }, [api, canSend]);
  useEffect(() => { loadComposeSettings(); }, [loadComposeSettings]);
  useEffect(() => { api<Vacation>('/api/vacation').then(setVacation).catch(() => undefined); }, [api]);
  const awayNote = vacationNote(vacation);

  /** Open the compose window once its seed (which may fetch the original's HTML) is ready. */
  const startCompose = (seed: ComposeSeed | Promise<ComposeSeed>) => {
    Promise.resolve(seed).then((ready) => { setCompose(ready); setView('list'); }).catch((err) => flash((err as Error).message));
  };

  async function openDraft(draftFolder: string, uid: number) {
    try {
      const detail = await api<MessageDetail>(`/api/folders/${encodeURIComponent(draftFolder)}/messages/${uid}`);
      startCompose(draftSeed(api, detail, draftFolder));
    } catch (err) {
      flash((err as Error).message);
    }
    loadFolders().catch(() => undefined);
    if (current?.special_use === '\\Drafts' || current?.special_use === '\\Sent') loadMessages(folder, activeQuery, 0, activeMeaning).catch(() => undefined);
  }

  /** After sending: offer to undo a message that waits (undo send, or send later). */
  function sent(result?: SendResult) {
    loadFolders().catch(() => undefined);
    if (current?.special_use === '\\Drafts' || current?.special_use === '\\Sent') loadMessages(folder, activeQuery, 0, activeMeaning).catch(() => undefined);
    const scheduled = result?.scheduled;
    if (!scheduled) return;
    const undo = async () => {
      setNotice(null);
      try {
        const draft = await api<{ folder: string; uid: number }>(`/api/scheduled/${scheduled.id}/cancel`, { method: 'POST' });
        await openDraft(draft.folder, draft.uid);
      } catch (err) {
        flash((err as Error).message);
      }
    };
    const wait = scheduled.send_at - Date.now() / 1000;
    if (wait <= 120) flash('Sending…', { label: 'Undo', run: undo }, Math.max(3, Math.ceil(wait)));
    else flash(`Scheduled for ${formatFullDate(scheduled.send_at)}`, { label: 'Undo', run: undo }, 8);
  }

  const loadFolders = useCallback(async () => setFolders(sortFolders(await api<Folder[]>('/api/folders'))), [api]);
  const loadOrganize = useCallback(() => api<Organize>('/api/organize').then(setOrganize).catch(() => setOrganize(null)), [api]);

  const loadMessages = useCallback(async (name: string, q: string, offset = 0, meaning = false) => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ limit: String(PAGE), offset: String(offset) });
      if (q) params.set('q', q);
      if (q && meaning) params.set('semantic', '1');
      const page = await api<MessagePage>(`/api/folders/${encodeURIComponent(name)}/messages?${params}`);
      setTotal(page.total);
      setMessages((current) => (offset ? [...current, ...page.messages] : page.messages));
    } finally {
      setLoading(false);
    }
  }, [api]);

  const refresh = useCallback(async () => {
    await Promise.all([loadFolders(), loadMessages(folder, activeQuery, 0, activeMeaning)]);
    setChecked([]);
  }, [loadFolders, loadMessages, folder, activeQuery, activeMeaning]);

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
    setCalendarMode(false);
    setFolder(name);
    setSelected(null);
    setChecked([]);
    setQuery('');
    setActiveQuery('');
    setActiveMeaning(false);
    setView('list');
    await loadMessages(name, '').catch((err) => flash((err as Error).message));
  }

  async function search(event?: React.FormEvent) {
    event?.preventDefault();
    const meaning = byMeaning && Boolean(organize?.search_enabled) && Boolean(query.trim());
    setActiveQuery(query.trim());
    setActiveMeaning(meaning);
    setSelected(null);
    await loadMessages(folder, query.trim(), 0, meaning).catch((err) => flash((err as Error).message));
  }

  async function openMessage(message: Message) {
    const detail = await api<MessageDetail>(`/api/folders/${encodeURIComponent(folder)}/messages/${message.uid}`);
    setSelected(detail);
    setRemoteLoaded(false);
    setView('message');
    setMoreOpen(false);
    setMoveOpen(false);
    if (!hasFlag(message.flags, '\\Seen') && can(current, 's')) {
      await api(`/api/folders/${encodeURIComponent(folder)}/messages/${message.uid}`, { method: 'PATCH', body: JSON.stringify({ seen: true }) });
      setMessages((list) => list.map((m) => (m.uid === message.uid ? { ...m, flags: [...m.flags, '\\Seen'] } : m)));
      loadFolders().catch(() => undefined);
    }
  }

  /** Open a related message, in its own folder. */
  async function openRelated(target: string, uid: number) {
    try {
      if (target !== folder) await chooseFolder(target);
      const detail = await api<MessageDetail>(`/api/folders/${encodeURIComponent(target)}/messages/${uid}`);
      setSelected(detail);
      setRemoteLoaded(false);
      setView('message');
      setMoreOpen(false);
      setMoveOpen(false);
      if (!hasFlag(detail.flags, '\\Seen') && can(folders.find((f) => f.name === target), 's')) {
        await api(`/api/folders/${encodeURIComponent(target)}/messages/${uid}`, { method: 'PATCH', body: JSON.stringify({ seen: true }) });
        setMessages((list) => list.map((m) => (m.uid === uid ? { ...m, flags: [...m.flags, '\\Seen'] } : m)));
        loadFolders().catch(() => undefined);
      }
    } catch (err) {
      flash((err as Error).message);
    }
  }

  async function loadRemoteContent() {
    if (!selected) return;
    const detail = await api<MessageDetail>(`/api/folders/${encodeURIComponent(folder)}/messages/${selected.uid}?remote_content=1`);
    setSelected({ ...detail, has_remote_content: false });
    setRemoteLoaded(true);
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
      if (calendarMode || target.closest('input, textarea, select, [contenteditable], .dialog, .compose') || compose || event.metaKey || event.ctrlKey || event.altKey) return;
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
        case 'r': if (canSend && selected) { event.preventDefault(); startCompose(replySeed(api, selected, folder, address, false, remoteLoaded)); } break;
        case 'a': if (canSend && selected) { event.preventDefault(); startCompose(replySeed(api, selected, folder, address, true, remoteLoaded)); } break;
        case 'f': if (canSend && selected) { event.preventDefault(); startCompose(forwardSeed(api, selected, folder, remoteLoaded)); } break;
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
    <main className={`app view-${view} ${calendarMode ? 'calendar-mode' : ''}`}>
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
          {canSend && <button className="sidebar-link" onClick={() => setComposeSettings(true)}><PenLine size={15} />Compose settings</button>}
          <button className="sidebar-link" onClick={() => setOrganizing(true)}><Sparkles size={15} />Organize my mail</button>
          <button className={`sidebar-link ${calendarMode ? 'active' : ''}`} aria-current={calendarMode ? 'page' : undefined} onClick={() => { setCalendarMode(true); setSelected(null); setChecked([]); setMoveOpen(false); setMoreOpen(false); setView('list'); }}><CalendarDays size={15} />Calendar</button>
          <button className="sidebar-link" onClick={() => setContacts(null)}><BookUser size={15} />Contacts</button>
          <button className="sidebar-link" onClick={() => setCalendars(true)}><CalendarDays size={15} />Calendar sharing</button>
          <button className="sidebar-link" onClick={() => setVacationOpen(true)} disabled={!vacation}><VacationIcon size={15} />Out of office{awayNote && <span className="sidebar-dot" aria-label="on" />}</button>
          <button className="sidebar-link" onClick={() => setFiltersOpen(true)}><FilterIcon size={15} />Filters</button>
          <button className="sidebar-link" onClick={() => setSecurityOpen(true)}><ShieldCheck size={15} />Security</button>
          <button className="sidebar-link" onClick={() => setEncryptionOpen(true)}><Lock size={15} />Encryption</button>
          {files && <button className="sidebar-link" onClick={() => setFilesOpen(true)}><HardDrive size={15} />Files</button>}
          <ThemeSwitch />
          <button className="sidebar-link" onClick={onLogout}><LogOut size={15} />Sign out</button>
        </div>
      </aside>

      <section className={`mailbox ${awayNote ? 'away' : ''}`}>
        <header className="topbar">
          <IconButton label="Folders" className="mobile-only" onClick={() => setView('folders')}><Menu size={18} /></IconButton>
          <form className="search" onSubmit={search} role="search">
            <Search size={16} />
            <input ref={searchRef} value={query} onChange={(e) => setQuery(e.target.value)} placeholder={`Search ${current ? folderLabel(current) : 'mail'}`} aria-label="Search mail" />
            {activeQuery && <button type="button" className="clear" aria-label="Clear search" onClick={() => { setQuery(''); setActiveQuery(''); setActiveMeaning(false); loadMessages(folder, ''); }}><X size={14} /></button>}
            {organize?.search_enabled && !current?.owner && <button type="button" className={`meaning ${byMeaning ? 'on' : ''}`} aria-pressed={byMeaning} title={byMeaning ? 'Searching by meaning (click for words)' : 'Search by words (click to search by meaning)'} onClick={() => setByMeaning(!byMeaning)}><Sparkles size={13} />By meaning</button>}
          </form>
          <IconButton label="Refresh" onClick={() => refresh().catch((err) => flash((err as Error).message))}><RefreshCw size={16} className={loading ? 'spin' : ''} /></IconButton>
        </header>
        {awayNote && <div className="away-banner"><VacationIcon size={15} /><span>{awayNote}</span><button className="link" onClick={() => setVacationOpen(true)}>Change</button></div>}
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
            <strong className="folder-title">{activeQuery ? `${activeMeaning ? 'Closest to' : 'Results for'} “${activeQuery}”` : current ? folderLabel(current) : folder}</strong>
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
          {messages.length < total && <button className="load-more" disabled={loading} onClick={() => loadMessages(folder, activeQuery, messages.length, activeMeaning)}>{loading ? 'Loading…' : `Load ${Math.min(PAGE, total - messages.length)} more`}</button>}
        </div>
      </section>

      {calendarMode && <CalendarView api={api} flash={flash} onShowFolders={() => setView('folders')} />}
      <article className="reader">
        {selected ? (
          <>
            <div className="reader-actions">
              <IconButton label="Back" className="mobile-only" onClick={() => setView('list')}><ChevronLeft size={18} /></IconButton>
              {canSend && (current?.special_use === '\\Drafts' || hasFlag(selected.flags, '\\Draft')
                ? <button className="secondary small-button" onClick={() => startCompose(draftSeed(api, selected, folder))}><Pencil size={14} />Edit draft</button>
                : <>
                  <IconButton label="Reply (r)" onClick={() => startCompose(replySeed(api, selected, folder, address, false, remoteLoaded))}><Reply size={16} /></IconButton>
                  <IconButton label="Reply all (a)" onClick={() => startCompose(replySeed(api, selected, folder, address, true, remoteLoaded))}><ReplyAll size={16} /></IconButton>
                  <IconButton label="Forward (f)" onClick={() => startCompose(forwardSeed(api, selected, folder, remoteLoaded))}><Forward size={16} /></IconButton>
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
                  <div><strong>{splitAddress(selected.from).name}</strong> <span className="muted">&lt;{splitAddress(selected.from).address}&gt;</span> <button className="link small" onClick={() => setContacts({ name: splitAddress(selected.from).name, email: splitAddress(selected.from).address })}>Add to contacts</button></div>
                  <div className="muted small">To {selected.to || address}{selected.cc && <> · Cc {selected.cc}</>}</div>
                  {selected.reply_to && selected.reply_to !== selected.from && <div className="muted small">Reply to {selected.reply_to}</div>}
                </div>
                <time className="muted small" title={selected.date}>{formatFullDate(selected.internal_date)}</time>
              </div>
              {!shared && <AiPanel api={api} folder={folder} message={selected} organize={organize} onLabelsChanged={() => reloadMessage(selected.uid)} onOpenSettings={() => setOrganizing(true)} onSaveContact={setContacts} />}
              {selected.invitation && <InvitationCard api={api} folder={folder} uid={selected.uid} invitation={selected.invitation} />}
              {selected.booking && <BookingCard api={api} booking={selected.booking} />}
              {selected.protection && <ProtectedMessage crypto={crypto} folder={folder} uid={selected.uid} protection={selected.protection} from={selected.from} textBody={selected.text_body} />}
              {selected.protection && ENCRYPTED.has(selected.protection) ? null : <>
              {selected.html_body && selected.has_remote_content && <div className="remote-banner"><ImageIcon size={16} /><span>Remote images are blocked to protect your privacy.</span><button onClick={loadRemoteContent}>Load images</button></div>}
              {selected.html_body
                ? <iframe className="html-message" title="Message" sandbox="allow-popups allow-popups-to-escape-sandbox" srcDoc={selected.html_body} />
                : <pre className="text-message">{selected.text_body}</pre>}
              <Attachments folder={folder} uid={selected.uid} attachments={selected.attachments} />
              </>}
              {!shared && organize?.search_enabled && <RelatedPanel api={api} folder={folder} uid={selected.uid} onOpen={openRelated} />}
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
          prefs={prefs}
          identities={identities}
          onClose={(note) => { setCompose(null); if (note) flash(note); }}
          onSent={sent}
          crypto={crypto}
        />
      )}
      {notice && <div className="toast" role="status">{notice.text}{notice.action && <button className="toast-action" onClick={notice.action.run}>{notice.action.label}</button>}</div>}
      {composeSettings && <React.Suspense fallback={null}><ComposeSettingsDialog api={api} prefs={prefs} identities={identities} onClose={() => setComposeSettings(false)} onSaved={loadComposeSettings} onOpenDraft={(f, uid) => { setComposeSettings(false); openDraft(f, uid); }} /></React.Suspense>}
      {organizing && <React.Suspense fallback={null}><OrganizeDialog api={api} onClose={() => setOrganizing(false)} onSaved={() => { refresh(); loadOrganize(); }} /></React.Suspense>}
      {prompt && <PromptDialog {...prompt} />}
      {sharing !== null && <FolderShareDialog api={api} folder={sharing} onClose={() => setSharing(null)} />}
      {calendars && <CalendarsDialog api={api} onClose={() => setCalendars(false)} />}
      {securityOpen && <SecurityDialog api={api} address={address} onClose={() => setSecurityOpen(false)} />}
      {encryptionOpen && <React.Suspense fallback={null}><EncryptionDialog crypto={crypto} onClose={() => setEncryptionOpen(false)} /></React.Suspense>}
      {cryptoPrompt}
      {filesOpen && <React.Suspense fallback={null}><FilesDialog address={address} onClose={() => setFilesOpen(false)} /></React.Suspense>}
      {contacts !== false && <ContactsDialog api={api} seed={contacts} onClose={() => setContacts(false)} onWrite={(to, name) => { setContacts(false); if (canSend) startCompose({ to: name ? `${name} <${to}>` : to }); }} />}
      {vacationOpen && vacation && <VacationDialog api={api} initial={vacation} onClose={() => setVacationOpen(false)} onSaved={setVacation} />}
      {filtersOpen && <FiltersDialog api={api} folders={folders} labels={organize?.labels ?? []} onClose={() => setFiltersOpen(false)} />}
      {rawFor !== null && <RawDialog api={api} folder={folder} uid={rawFor} onClose={() => setRawFor(null)} />}
    </main>
  );
}

// ---------------------------------------------------------------------------
// Sign-in

/** Why a single sign-on attempt came back without a session. */
const ssoErrors: Record<string, string> = {
  no_mailbox: 'That account has no mailbox here. Ask your administrator.',
  unverified: 'Your sign-in provider has not verified that email address.',
  cancelled: 'Sign-in was cancelled.',
  expired: 'That sign-in took too long or was already used. Try again.',
  provider: 'The sign-in provider could not be reached or refused the sign-in. Try again, or use your password.',
};

function App() {
  const [address, setAddress] = useState<string | null | undefined>(undefined);
  const [setupRequired, setSetupRequired] = useState(false);
  const [canSend, setCanSend] = useState(false);
  const [files, setFiles] = useState(false);
  const [loginAddress, setLoginAddress] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [needCode, setNeedCode] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [sso, setSso] = useState<{ enabled: boolean; label: string } | null>(null);
  const api = useApi(useCallback(() => setAddress(null), []), useCallback(() => setSetupRequired(true), []));

  useEffect(() => {
    api<{ address: string; can_send: boolean; two_factor_setup: boolean; files: boolean }>('/api/session').then((s) => { setCanSend(s.can_send); setFiles(Boolean(s.files)); setSetupRequired(s.two_factor_setup); setAddress(s.address); }).catch(() => setAddress(null));
  }, [api]);

  useEffect(() => {
    api<{ enabled: boolean; label: string }>('/api/oidc').then(setSso).catch(() => undefined);
    // Back from the provider without signing in: say why, once.
    const reason = new URLSearchParams(window.location.search).get('sso_error');
    if (reason) {
      setError(ssoErrors[reason] ?? ssoErrors.provider);
      window.history.replaceState(null, '', '/');
    }
  }, [api]);

  async function login(event: React.FormEvent) {
    event.preventDefault();
    setError('');
    setBusy(true);
    try {
      const session = await api<{ address: string; can_send: boolean; two_factor_setup: boolean; files: boolean }>('/api/login', { method: 'POST', body: JSON.stringify({ address: loginAddress, password, ...(needCode ? { code } : {}) }) });
      setPassword('');
      setCode('');
      setNeedCode(false);
      setCanSend(session.can_send);
      setFiles(Boolean(session.files));
      setSetupRequired(session.two_factor_setup);
      setAddress(session.address);
    } catch (err) {
      if (err instanceof ApiError && err.message === 'two_factor') {
        setNeedCode(true);
      } else if (err instanceof ApiError && err.status === 429) {
        setError(err.message);
      } else {
        setError(needCode ? 'That code is not right. Try the newest one, or a recovery code.' : 'Invalid mailbox or password');
        setCode('');
      }
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
          <label className="field"><span>Password</span><input value={password} onChange={(e) => setPassword(e.target.value)} type="password" autoComplete="current-password" disabled={needCode} /></label>
          {needCode && (
            <label className="field"><span>Code from your authenticator app</span>
              <input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" placeholder="123456 or a recovery code" autoFocus />
            </label>
          )}
          {error && <p className="error">{error}</p>}
          <button type="submit" className="primary" disabled={busy || (needCode && !code.trim())}>{busy ? 'Signing in…' : needCode ? 'Verify' : 'Sign in'}</button>
          {needCode && <button type="button" className="link" onClick={() => { setNeedCode(false); setCode(''); setPassword(''); setError(''); }}>Start over</button>}
          {sso?.enabled && !needCode && <>
            <div className="login-or"><span>or</span></div>
            <a className="button sso-button" href="/api/oidc/start">{sso.label}</a>
          </>}
        </form>
      </main>
    );
  }
  if (setupRequired) {
    const recheck = () => api<{ two_factor_setup: boolean }>('/api/session').then((s) => setSetupRequired(s.two_factor_setup)).catch(() => undefined);
    return <main className="login-shell"><SecurityDialog api={api} address={address} required onClose={logout} onChanged={recheck} /></main>;
  }
  return <Mailbox api={api} address={address} canSend={canSend} files={files} onLogout={logout} />;
}

createRoot(document.getElementById('root')!).render(<App />);
