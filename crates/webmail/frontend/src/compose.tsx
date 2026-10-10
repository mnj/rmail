import { useEffect, useRef, useState } from 'react';
import { CalendarClock, ChevronDown, Paperclip, Send, Trash2, Type, X } from 'lucide-react';
import { EditorHandle, RichEditor, escapeHtml, textToHtml } from './editor';
import {
  Api, Attachment, ComposePrefs, Contact, Identity, MessageDetail, SendResult, formatAddress, formatFullDate, formatSize, splitAddress,
} from './types';

const MAX_BYTES = 10 * 1024 * 1024;
/** Seconds between automatic draft saves while there are unsaved changes. */
const AUTOSAVE_SECONDS = 20;

type Upload = { filename: string; content_type: string; data: string; size: number };
type Stored = { folder: string; uid: number; index: number; filename: string; size: number };
type Format = 'html' | 'text';

/** What the compose window starts from: blank, a reply, a forward or a draft. */
export type ComposeSeed = {
  to?: string; cc?: string; bcc?: string; subject?: string;
  /** The body as plain text, and as editor HTML when there is any. */
  text?: string; html?: string;
  /** A draft keeps its format; otherwise the user's default applies. */
  format?: Format;
  in_reply_to?: string; references?: string;
  stored?: Stored[];
  source?: { folder: string; uid: number; kind: 'reply' | 'forward' };
  draft_uid?: number;
};

function addressList(value: string): string[] {
  return value.split(/[,;\n]/).map((part) => part.trim()).filter(Boolean);
}

const prefixed = (subject: string, prefix: 'Re' | 'Fwd') =>
  new RegExp(`^${prefix}:`, 'i').test(subject.trim()) ? subject.trim() : `${prefix}: ${subject.trim()}`;

/** The original's HTML cleaned for the editor (inline images included, remote ones only if the user loaded them). */
async function sourceHtml(api: Api, folder: string, uid: number, remote: boolean): Promise<string | null> {
  try {
    const result = await api<{ html: string | null }>(`/api/folders/${encodeURIComponent(folder)}/messages/${uid}/compose${remote ? '?remote_content=1' : ''}`);
    return result.html;
  } catch {
    return null;
  }
}

/** Seed for replying to `message`; reply-all adds the other recipients, never yourself. */
export async function replySeed(api: Api, message: MessageDetail, folder: string, self: string, all: boolean, remote = false): Promise<ComposeSeed> {
  const sender = message.reply_to || message.from;
  const me = self.toLowerCase();
  const others = all
    ? [...addressList(message.to), ...addressList(message.cc)].filter((a) => splitAddress(a).address.toLowerCase() !== me && splitAddress(a).address.toLowerCase() !== splitAddress(sender).address.toLowerCase())
    : [];
  const intro = `On ${formatFullDate(message.internal_date)}, ${message.from} wrote:`;
  const original = message.html_body ? await sourceHtml(api, folder, message.uid, remote) : null;
  return {
    to: sender,
    cc: others.join(', '),
    subject: prefixed(message.subject, 'Re'),
    text: `\n\n${intro}\n${message.text_body.split('\n').map((line) => `> ${line}`).join('\n')}\n`,
    html: `<div><br></div><div>${escapeHtml(intro)}</div><blockquote type="cite">${original || textToHtml(message.text_body)}</blockquote>`,
    in_reply_to: message.message_id || undefined,
    references: [message.references, message.message_id].filter(Boolean).join(' ') || undefined,
    source: { folder, uid: message.uid, kind: 'reply' },
  };
}

export async function forwardSeed(api: Api, message: MessageDetail, folder: string, remote = false): Promise<ComposeSeed> {
  const head: [string, string][] = [['From', message.from], ['Date', formatFullDate(message.internal_date)], ['Subject', message.subject], ['To', message.to]];
  if (message.cc) head.push(['Cc', message.cc]);
  const original = message.html_body ? await sourceHtml(api, folder, message.uid, remote) : null;
  return {
    subject: prefixed(message.subject, 'Fwd'),
    text: `\n\n---------- Forwarded message ----------\n${head.map(([k, v]) => `${k}: ${v}`).join('\n')}\n\n${message.text_body}\n`,
    html: `<div><br></div><div>---------- Forwarded message ----------</div>${head.map(([k, v]) => `<div>${k}: ${escapeHtml(v)}</div>`).join('')}<div><br></div>${original || textToHtml(message.text_body)}`,
    // Inline images travel in the HTML; only real attachments are re-attached.
    stored: message.attachments.map((a: Attachment) => ({ folder, uid: message.uid, index: a.index, filename: a.filename, size: a.size })),
    source: { folder, uid: message.uid, kind: 'forward' },
  };
}

/** Continue editing a saved draft, in the format it was saved in. */
export async function draftSeed(api: Api, message: MessageDetail, folder: string): Promise<ComposeSeed> {
  const html = message.html_body ? await sourceHtml(api, folder, message.uid, true) : null;
  return {
    to: message.to, cc: message.cc, bcc: message.bcc, subject: message.subject, text: message.text_body,
    html: html ?? undefined, format: html ? 'html' : 'text',
    in_reply_to: message.in_reply_to || undefined, references: message.references || undefined,
    stored: message.attachments.map((a) => ({ folder, uid: message.uid, index: a.index, filename: a.filename, size: a.size })),
    draft_uid: message.uid,
  };
}

function readFile(file: File): Promise<Upload> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = String(reader.result);
      resolve({ filename: file.name, content_type: file.type || 'application/octet-stream', data: result.slice(result.indexOf(',') + 1), size: file.size });
    };
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(file);
  });
}

const signatureHtml = (identity?: Identity) =>
  identity && (identity.html_signature || identity.text_signature)
    ? `<div data-rmail-signature="1"><div>-- </div>${identity.html_signature || textToHtml(identity.text_signature)}</div>`
    : '';
const signatureText = (identity?: Identity) => (identity?.text_signature ? `\n\n-- \n${identity.text_signature}` : '');

/** An address field that suggests people from the address books and recent recipients while typing. */
function AddressInput({ api, label, value, onChange, autoFocus, lang }: { api: Api; label: string; value: string; onChange: (value: string) => void; autoFocus?: boolean; lang?: string }) {
  const [suggestions, setSuggestions] = useState<Contact[]>([]);
  const [active, setActive] = useState(0);
  const timer = useRef<number | undefined>(undefined);
  const query = (text: string) => text.split(/[,;]/).pop()!.trim();

  function changed(text: string) {
    onChange(text);
    window.clearTimeout(timer.current);
    const q = query(text);
    if (q.length < 1) { setSuggestions([]); return; }
    timer.current = window.setTimeout(() => {
      api<Contact[]>(`/api/contacts?q=${encodeURIComponent(q)}`)
        .then((list) => {
          const chosen = addressList(text).map((a) => splitAddress(a).address.toLowerCase());
          setSuggestions(list.filter((c) => !chosen.slice(0, -1).includes(c.email.toLowerCase())));
          setActive(0);
        })
        .catch(() => setSuggestions([]));
    }, 120);
  }

  function choose(contact: Contact) {
    const parts = value.split(/[,;]/);
    parts.pop();
    const kept = parts.map((p) => p.trim()).filter(Boolean);
    onChange([...kept, formatAddress(contact.name, contact.email)].join(', ') + ', ');
    setSuggestions([]);
  }

  return (
    <label className="address-field">
      <span>{label}</span>
      <input
        value={value}
        lang={lang}
        onChange={(e) => changed(e.target.value)}
        onBlur={() => window.setTimeout(() => setSuggestions([]), 150)}
        onKeyDown={(e) => {
          if (!suggestions.length) return;
          if (e.key === 'ArrowDown') { e.preventDefault(); setActive((active + 1) % suggestions.length); }
          else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((active - 1 + suggestions.length) % suggestions.length); }
          else if (e.key === 'Enter' || e.key === 'Tab') { if (!e.ctrlKey && !e.metaKey) { e.preventDefault(); choose(suggestions[active]); } }
          else if (e.key === 'Escape') { e.stopPropagation(); setSuggestions([]); }
        }}
        autoFocus={autoFocus}
        autoComplete="off"
        spellCheck={false}
        placeholder={label === 'To' ? 'name@example.com, …' : undefined}
        role="combobox"
        aria-expanded={suggestions.length > 0}
        aria-autocomplete="list"
        aria-label={label}
      />
      {suggestions.length > 0 && (
        <ul className="suggestions" role="listbox">
          {suggestions.map((contact, i) => (
            <li key={contact.email} role="option" aria-selected={i === active} className={i === active ? 'active' : ''} onMouseDown={(e) => { e.preventDefault(); choose(contact); }}>
              <strong>{contact.name || contact.email}</strong>{contact.name && <small>{contact.email}</small>}
              {contact.source === 'recent' && <em>recent</em>}
            </li>
          ))}
        </ul>
      )}
    </label>
  );
}

function localInput(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

/** Suggested times for "send later": tomorrow morning and next Monday morning. */
function laterChoices(): [string, Date][] {
  const tomorrow = new Date();
  tomorrow.setDate(tomorrow.getDate() + 1);
  tomorrow.setHours(8, 0, 0, 0);
  const monday = new Date();
  monday.setDate(monday.getDate() + (((8 - monday.getDay()) % 7) || 7));
  monday.setHours(8, 0, 0, 0);
  const fmt = (d: Date) => d.toLocaleString(undefined, { weekday: 'short', hour: '2-digit', minute: '2-digit' });
  return [[`Tomorrow, ${fmt(tomorrow)}`, tomorrow], [`Monday, ${fmt(monday)}`, monday]];
}

export function ComposeWindow({ api, from, seed, prefs, identities, onClose, onSent }: {
  api: Api; from: string; seed: ComposeSeed; prefs: ComposePrefs; identities: Identity[];
  onClose: (note?: string) => void; onSent: (result?: SendResult) => void;
}) {
  const defaultIdentity = identities.find((i) => i.email.toLowerCase() === from.toLowerCase()) || identities[0];
  const [identityId, setIdentityId] = useState(defaultIdentity?.id || '');
  const identity = identities.find((i) => i.id === identityId);
  const isDraft = seed.draft_uid !== undefined;
  const [format, setFormat] = useState<Format>(seed.format || prefs.format);
  const [to, setTo] = useState(seed.to || '');
  const [cc, setCc] = useState(seed.cc || '');
  const [bcc, setBcc] = useState(seed.bcc || '');
  const [showCopies, setShowCopies] = useState(Boolean(seed.cc || seed.bcc));
  const [subject, setSubject] = useState(seed.subject || '');
  const [text, setText] = useState(() => {
    if (isDraft) return seed.text || '';
    // New text: the signature goes above a quote.
    return signatureText(defaultIdentity) + (seed.text || '');
  });
  const initialHtml = useRef(isDraft ? seed.html || textToHtml(seed.text || '') : `<div><br></div>${signatureHtml(defaultIdentity)}${seed.html || ''}`);
  const [uploads, setUploads] = useState<Upload[]>([]);
  const [stored, setStored] = useState<Stored[]>(seed.stored || []);
  const [draftUid, setDraftUid] = useState<number | undefined>(seed.draft_uid);
  const [draftFolder, setDraftFolder] = useState<string | null>(null);
  const [busy, setBusy] = useState<'send' | 'draft' | null>(null);
  const [error, setError] = useState('');
  const [savedAt, setSavedAt] = useState<Date | null>(null);
  const [laterOpen, setLaterOpen] = useState(false);
  const [laterValue, setLaterValue] = useState(() => localInput(laterChoices()[0][1]));
  const [dragging, setDragging] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const bodyRef = useRef<HTMLTextAreaElement>(null);
  const editorRef = useRef<EditorHandle>(null);
  const dirty = useRef(false);
  const busyRef = useRef(busy);
  busyRef.current = busy;
  const total = uploads.reduce((sum, u) => sum + u.size, 0) + stored.reduce((sum, s) => sum + s.size, 0);
  const touch = () => { dirty.current = true; };

  useEffect(() => {
    // Replies start typing above the quote.
    if (!seed.to) return;
    if (format === 'html') editorRef.current?.focus('start');
    else if (bodyRef.current) { bodyRef.current.focus(); bodyRef.current.setSelectionRange(0, 0); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const body = () => (format === 'html' ? { html: editorRef.current?.getHTML() || '', text: '' } : { text });
  const hasContent = () => Boolean(to.trim() || subject.trim() || (format === 'html' ? editorRef.current?.getText().trim() : text.trim()) || uploads.length);

  const payload = () => ({
    to: addressList(to), cc: addressList(cc), bcc: addressList(bcc), subject, ...body(),
    identity_id: identityId || undefined,
    in_reply_to: seed.in_reply_to, references: seed.references,
    attachments: uploads.map(({ filename, content_type, data }) => ({ filename, content_type, data })),
    stored_attachments: stored.map(({ folder, uid, index }) => ({ folder, uid, index })),
    source: seed.source, draft_uid: draftUid,
  });

  async function addFiles(files: File[]) {
    if (!files.length) return;
    const added = await Promise.all(files.map(readFile));
    if (total + added.reduce((sum, u) => sum + u.size, 0) > MAX_BYTES) {
      setError('Attachments can be at most 10 MB in total.');
      return;
    }
    touch();
    setUploads((list) => [...list, ...added]);
  }

  async function send(sendAt?: Date) {
    if (busyRef.current) return;
    if (!addressList(to).length && !addressList(cc).length && !addressList(bcc).length) {
      setError('Add at least one recipient.');
      return;
    }
    busyRef.current = 'send';
    setBusy('send');
    setError('');
    setLaterOpen(false);
    try {
      const timing = sendAt ? { send_at: Math.floor(sendAt.getTime() / 1000) } : prefs.undo_seconds > 0 ? { delay: prefs.undo_seconds } : {};
      const result = await api<SendResult>('/api/send', { method: 'POST', body: JSON.stringify({ ...payload(), ...timing }) });
      dirty.current = false;
      onSent(result);
      onClose(result.scheduled ? undefined : 'Message sent');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(null);
    }
  }

  async function saveDraft(closeAfter: boolean, quiet = false) {
    if (busyRef.current) return;
    busyRef.current = 'draft';
    setBusy('draft');
    if (!quiet) setError('');
    try {
      const saved = await api<{ folder: string; uid: number }>('/api/drafts', { method: 'POST', body: JSON.stringify(payload()) });
      dirty.current = false;
      onSent();
      if (closeAfter) {
        onClose('Draft saved');
        return;
      }
      // Keep editing the saved copy; its attachments now live there.
      const draft = await api<MessageDetail>(`/api/folders/${encodeURIComponent(saved.folder)}/messages/${saved.uid}`);
      setStored(draft.attachments.map((a) => ({ folder: saved.folder, uid: saved.uid, index: a.index, filename: a.filename, size: a.size })));
      setDraftUid(saved.uid);
      setDraftFolder(saved.folder);
      setUploads([]);
      setSavedAt(new Date());
    } catch (err) {
      if (!quiet) setError((err as Error).message);
    } finally {
      setBusy(null);
    }
  }

  // Autosave: a draft is written while there are unsaved changes.
  const saveRef = useRef(saveDraft);
  saveRef.current = saveDraft;
  useEffect(() => {
    const id = window.setInterval(() => {
      if (dirty.current && !busyRef.current && hasContent()) saveRef.current(false, true);
    }, AUTOSAVE_SECONDS * 1000);
    return () => window.clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function close() {
    if (dirty.current && hasContent()) saveDraft(true);
    else onClose(savedAt ? 'Draft saved' : undefined);
  }

  async function discard() {
    // A draft this window saved on its own goes too; one the user opened stays.
    if (draftUid !== undefined && draftFolder && !isDraft) {
      await api(`/api/folders/${encodeURIComponent(draftFolder)}/messages/bulk`, { method: 'POST', body: JSON.stringify({ action: 'delete', uids: [draftUid] }) }).catch(() => undefined);
      onSent();
    }
    onClose(isDraft ? undefined : 'Discarded');
  }

  function switchFormat(next: Format) {
    if (next === format) return;
    if (next === 'text') {
      const plain = editorRef.current?.getText() || '';
      setText(plain.replace(/\n{3,}/g, '\n\n'));
    } else {
      initialHtml.current = textToHtml(text);
    }
    touch();
    setFormat(next);
  }

  function changeIdentity(id: string) {
    const next = identities.find((i) => i.id === id);
    if (format === 'html' && editorRef.current) {
      const doc = new DOMParser().parseFromString(editorRef.current.getHTML(), 'text/html');
      const old = doc.querySelector('[data-rmail-signature]');
      const replacement = signatureHtml(next);
      if (old) old.outerHTML = replacement;
      else if (replacement) doc.body.insertAdjacentHTML('afterbegin', `<div><br></div>${replacement}`);
      editorRef.current.setHTML(doc.body.innerHTML);
    } else {
      const oldSig = signatureText(identity);
      setText(oldSig && text.includes(oldSig) ? text.replace(oldSig, signatureText(next)) : text);
    }
    setIdentityId(id);
    touch();
  }

  const title = seed.source?.kind === 'reply' ? 'Reply' : seed.source?.kind === 'forward' ? 'Forward' : draftUid !== undefined && isDraft ? 'Draft' : 'New message';
  const mod = /Mac|iP(hone|ad)/.test(navigator.platform) ? '⌘' : 'Ctrl+';

  return (
    <div
      className={`compose ${dragging ? 'dragging' : ''}`}
      role="dialog"
      aria-label={title}
      onKeyDown={(e) => {
        if (e.key === 'Escape' && !e.defaultPrevented) { if (laterOpen) setLaterOpen(false); else close(); }
        // The editor handles its own Ctrl+Enter (and prevents the default).
        if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && !e.defaultPrevented) { e.preventDefault(); send(); }
        if (e.key.toLowerCase() === 's' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); saveDraft(false); }
      }}
      onDragOver={(e) => { if (e.dataTransfer.types.includes('Files')) { e.preventDefault(); setDragging(true); } }}
      onDragLeave={(e) => { if (e.currentTarget === e.target) setDragging(false); }}
      onDrop={(e) => { setDragging(false); if (e.dataTransfer.files.length) { e.preventDefault(); addFiles(Array.from(e.dataTransfer.files)); } }}
    >
      <header>
        <strong>{title}</strong>
        <button className="icon" aria-label="Close (saves a draft)" title="Close (saves a draft)" onClick={close}><X size={16} /></button>
      </header>
      <div className="compose-fields">
        <div className="compose-from">
          <span>From</span>
          {identities.length > 1 ? (
            <select aria-label="From" value={identityId} onChange={(e) => changeIdentity(e.target.value)}>
              {identities.map((i) => <option key={i.id} value={i.id}>{formatAddress(i.name, i.email)}</option>)}
            </select>
          ) : <span className="from-value">{identity ? formatAddress(identity.name, identity.email) : from}</span>}
        </div>
        <div className="address-row">
          <AddressInput api={api} label="To" value={to} onChange={(v) => { setTo(v); touch(); }} autoFocus={!seed.to} />
          {!showCopies && <button type="button" className="link" onClick={() => setShowCopies(true)}>Cc/Bcc</button>}
        </div>
        {showCopies && <AddressInput api={api} label="Cc" value={cc} onChange={(v) => { setCc(v); touch(); }} />}
        {showCopies && <AddressInput api={api} label="Bcc" value={bcc} onChange={(v) => { setBcc(v); touch(); }} />}
        <label><span>Subject</span><input value={subject} lang={prefs.language || undefined} spellCheck onChange={(e) => { setSubject(e.target.value); touch(); }} /></label>
      </div>
      {format === 'html' ? (
        <RichEditor
          ref={editorRef}
          initialHtml={initialHtml.current}
          lang={prefs.language}
          label="Message"
          className="compose-editor"
          onChange={touch}
          onSubmit={() => send()}
          onFiles={addFiles}
        />
      ) : (
        <textarea ref={bodyRef} className="compose-body" value={text} lang={prefs.language || undefined} spellCheck onChange={(e) => { setText(e.target.value); touch(); }} aria-label="Message" />
      )}
      {(uploads.length > 0 || stored.length > 0) && (
        <div className="compose-attachments">
          {stored.map((s, i) => (
            <span className="file-chip" key={`s${i}`}><Paperclip size={12} />{s.filename}<small>{formatSize(s.size)}</small><button aria-label={`Remove ${s.filename}`} onClick={() => { touch(); setStored((list) => list.filter((_, j) => j !== i)); }}><X size={12} /></button></span>
          ))}
          {uploads.map((u, i) => (
            <span className="file-chip" key={`u${i}`}><Paperclip size={12} />{u.filename}<small>{formatSize(u.size)}</small><button aria-label={`Remove ${u.filename}`} onClick={() => { touch(); setUploads((list) => list.filter((_, j) => j !== i)); }}><X size={12} /></button></span>
          ))}
        </div>
      )}
      {dragging && <div className="drop-hint" aria-hidden="true"><Paperclip size={18} />Drop files to attach (images dropped in the text are placed inline)</div>}
      {error && <p className="error compose-error">{error}</p>}
      <footer>
        <span className="send-group menu-anchor">
          <button className="primary" disabled={busy !== null} onClick={() => send()} title={`Send (${mod}Enter)`}><Send size={14} />{busy === 'send' ? 'Sending…' : 'Send'}</button>
          <button className="primary send-more" disabled={busy !== null} aria-label="Send later" title="Send later" aria-expanded={laterOpen} onClick={() => setLaterOpen(!laterOpen)}><ChevronDown size={14} /></button>
          {laterOpen && (
            <div className="menu send-later" role="menu">
              {laterChoices().map(([label, date]) => <button key={label} role="menuitem" onClick={() => send(date)}><CalendarClock size={14} />{label}</button>)}
              <form className="later-custom" onSubmit={(e) => { e.preventDefault(); const at = new Date(laterValue); if (at.getTime() > Date.now()) send(at); else setError('Pick a time in the future.'); }}>
                <input type="datetime-local" aria-label="Send at" value={laterValue} min={localInput(new Date())} onChange={(e) => setLaterValue(e.target.value)} />
                <button className="secondary small-button">Schedule</button>
              </form>
            </div>
          )}
        </span>
        <input ref={fileRef} type="file" multiple hidden onChange={(e) => { addFiles(Array.from(e.target.files || [])); e.target.value = ''; }} />
        <button className="icon" aria-label="Attach files" title="Attach files (or drop them here)" onClick={() => fileRef.current?.click()}><Paperclip size={16} /></button>
        <button className={`icon ${format === 'html' ? 'active' : ''}`} aria-pressed={format === 'html'} aria-label={format === 'html' ? 'Switch to plain text' : 'Switch to formatted text'} title={format === 'html' ? 'Formatted text (click for plain text)' : 'Plain text (click for formatted text)'} onClick={() => switchFormat(format === 'html' ? 'text' : 'html')}><Type size={16} /></button>
        <span className="spacer" />
        <span className="save-state muted small">{busy === 'draft' ? 'Saving…' : savedAt ? `Saved ${savedAt.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })}` : ''}</span>
        <button className="secondary" disabled={busy !== null} onClick={() => saveDraft(false)} title={`Save draft (${mod}S)`}>Save draft</button>
        <button className="icon" aria-label="Discard" title="Discard" onClick={discard}><Trash2 size={16} /></button>
      </footer>
    </div>
  );
}
