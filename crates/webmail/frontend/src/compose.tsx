import { useEffect, useRef, useState } from 'react';
import { CalendarClock, ChevronDown, Link2, Lock, Paperclip, Send, Sparkles, Trash2, Type, X } from 'lucide-react';
import { FileListing, Linked, uploadAsLink } from './filelinks';
import { Crypto } from './crypto/hook';
import { Security, Technology, protect, technologies } from './crypto/compose';
import { REWRITE_STYLES, RewriteStyle, assist, attachTextareaGhost, ghostTextPlugin, insertIntoTextarea } from './assist';
import { EditorHandle, EditorPlugin, RichEditor, escapeHtml, textToHtml } from './editor';
import {
  Api, Attachment, ComposePrefs, Contact, Identity, MessageDetail, SendResult, formatAddress, formatFullDate, formatSize, splitAddress,
} from './types';

const MAX_BYTES = 10 * 1024 * 1024;
/** Seconds between automatic draft saves while there are unsaved changes. */
const AUTOSAVE_SECONDS = 20;
/** Longest selection a rewrite takes (rmail_common::compose_ai::MAX_SELECTION_CHARS). */
const MAX_REWRITE_CHARS = 4000;

type Upload = { filename: string; content_type: string; data: string; size: number };
type Stored = { folder: string; uid: number; index: number; filename: string; size: number };
type Format = 'html' | 'text';
/** Selected text, and how to replace exactly it later (false when it has changed since). */
type SelectedText = { text: string; replace: (text: string) => boolean };
/** An AI rewrite of the selection, shown before it replaces anything. */
type Rewrite = { style: RewriteStyle; label: string; selection: SelectedText; result: string | null; error: string; controller: AbortController };

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

/**
 * Plain text from the editor's HTML, keeping where links go: a link whose
 * text is not its address gets the address after it (a reopened draft's
 * file links, say, would otherwise lose their URLs).
 */
function htmlToTextWithLinks(html: string): string {
  const doc = new DOMParser().parseFromString(html, 'text/html');
  for (const link of Array.from(doc.querySelectorAll('a[href]'))) {
    const href = link.getAttribute('href') || '';
    if (/^(https?:|mailto:)/i.test(href) && link.textContent?.trim() !== href.replace(/^mailto:/i, '')) {
      link.after(doc.createTextNode(` <${href}>`));
    }
  }
  for (const br of Array.from(doc.querySelectorAll('br'))) br.replaceWith(doc.createTextNode('\n'));
  for (const block of Array.from(doc.querySelectorAll('p, div, li, h1, h2, h3, h4, h5, h6, blockquote, tr, pre'))) {
    if (block.tagName === 'LI') block.prepend(doc.createTextNode('- '));
    block.append(doc.createTextNode('\n'));
  }
  return (doc.body.textContent || '').replace(/\u00a0/g, ' ').replace(/[ \t]+\n/g, '\n').trim();
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

export function ComposeWindow({ api, from, seed, prefs, identities, onClose, onSent, crypto }: {
  api: Api; from: string; seed: ComposeSeed; prefs: ComposePrefs; identities: Identity[];
  onClose: (note?: string) => void; onSent: (result?: SendResult) => void;
  /** The user's keys, for signing and encrypting. */
  crypto?: Crypto;
}) {
  const kinds = crypto ? technologies(crypto) : [];
  const [security, setSecurity] = useState<Security>('none');
  const [technology, setTechnology] = useState<Technology | null>(null);
  const tech: Technology | undefined = technology && kinds.includes(technology) ? technology : kinds[0];
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
  // Files too large to attach, sent as download links instead.
  const [linkSettings, setLinkSettings] = useState<FileListing | null>(null);
  const [links, setLinks] = useState<Linked[]>([]);
  const [offer, setOffer] = useState<File[] | null>(null);
  const [linking, setLinking] = useState<{ name: string; sent: number; size: number } | null>(null);
  useEffect(() => { api<FileListing>('/api/files').then(setLinkSettings).catch(() => setLinkSettings(null)); }, [api]);
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
  // AI writing suggestions: offered by the server and turned on by the user.
  const aiOn = Boolean(prefs.ai?.available && prefs.ai_suggestions);
  const subjectRef = useRef(subject);
  subjectRef.current = subject;
  // The editor attaches plugins once, when it is created.
  const plugins = useRef<EditorPlugin[] | null>(null);
  plugins.current ??= aiOn ? [ghostTextPlugin(api, () => subjectRef.current)] : [];
  const [rewriteOpen, setRewriteOpen] = useState(false);
  const [rewrite, setRewrite] = useState<Rewrite | null>(null);
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

  useEffect(() => {
    if (!aiOn || format !== 'text' || !bodyRef.current) return;
    return attachTextareaGhost(api, () => subjectRef.current, bodyRef.current);
  }, [aiOn, format, api]);

  /** The selection in whichever editor is showing. */
  function captureSelection(): SelectedText | null {
    if (format === 'html') return editorRef.current?.captureSelection() ?? null;
    const textarea = bodyRef.current;
    if (!textarea) return null;
    const [start, end] = [textarea.selectionStart, textarea.selectionEnd];
    const selected = textarea.value.slice(start, end);
    if (!selected.trim()) return null;
    return {
      text: selected,
      replace: (value) => {
        if (textarea.value.slice(start, end) !== selected) return false;
        insertIntoTextarea(textarea, value, start, end);
        return true;
      },
    };
  }

  async function runRewrite(style: RewriteStyle, label: string, selection: SelectedText | null) {
    setRewriteOpen(false);
    if (!selection) {
      setError('Select the text to rewrite first.');
      return;
    }
    // The server refuses longer selections rather than rewriting only their
    // start, which would drop the rest on replace. UTF-16 length is at least
    // the character count the server checks.
    if (selection.text.trim().length > MAX_REWRITE_CHARS) {
      setError(`Select at most ${MAX_REWRITE_CHARS} characters to rewrite.`);
      return;
    }
    setError('');
    rewrite?.controller.abort();
    const controller = new AbortController();
    const settle = (change: Partial<Rewrite>) => setRewrite((current) => (current?.controller === controller ? { ...current, ...change } : current));
    setRewrite({ style, label, selection, result: null, error: '', controller });
    try {
      const text = await assist(api, { kind: 'rewrite', style, selection: selection.text, subject }, controller.signal);
      if (!controller.signal.aborted) settle(text.trim() ? { result: text } : { error: 'No rewrite came back; try again.' });
    } catch (err) {
      if (!controller.signal.aborted) settle({ error: (err as Error).message });
    }
  }

  function closeRewrite() {
    rewrite?.controller.abort();
    setRewrite(null);
  }

  function applyRewrite() {
    if (!rewrite?.result) return;
    if (!rewrite.selection.replace(rewrite.result)) {
      setRewrite({ ...rewrite, result: null, error: 'The selected text has changed; select it again.' });
      return;
    }
    touch();
    setRewrite(null);
  }

  /** The links to large files, after the message's own text. */
  const until = () => new Date(Math.min(...links.map((l) => l.expires)) * 1000).toLocaleDateString();
  const linksText = () => links.length
    ? `\n\nFiles (download until ${until()}):\n${links.map((l) => `${l.name} (${formatSize(l.size)}): ${l.url}`).join('\n')}`
    : '';
  const linksHtml = () => links.length
    ? `<p>Files (download until ${escapeHtml(until())}):<br>${links.map((l) => `<a href="${escapeHtml(l.url)}">${escapeHtml(l.name)}</a> (${formatSize(l.size)})`).join('<br>')}</p>`
    : '';
  const body = () => (format === 'html' ? { html: (editorRef.current?.getHTML() || '') + linksHtml(), text: '' } : { text: text + linksText() });
  const hasContent = () => Boolean(to.trim() || subject.trim() || (format === 'html' ? editorRef.current?.getText().trim() : text.trim()) || uploads.length || links.length);

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
    if (total + files.reduce((sum, f) => sum + f.size, 0) > MAX_BYTES) {
      if (linkSettings?.enabled) setOffer(files);
      else setError('Attachments can be at most 10 MB in total.');
      return;
    }
    const added = await Promise.all(files.map(readFile));
    touch();
    setUploads((list) => [...list, ...added]);
  }

  async function sendAsLinks(files: File[]) {
    setOffer(null);
    setError('');
    const chunk = linkSettings?.chunk_bytes ?? 8 * 1024 * 1024;
    for (const file of files) {
      if (linkSettings && file.size > linkSettings.max_file_bytes) {
        setError(`${file.name} is larger than ${formatSize(linkSettings.max_file_bytes)}, the most this server shares.`);
        continue;
      }
      setLinking({ name: file.name, sent: 0, size: file.size });
      try {
        const linked = await uploadAsLink(api, file, chunk, (sent) => setLinking({ name: file.name, sent, size: file.size }));
        touch();
        setLinks((list) => [...list, linked]);
      } catch (err) {
        setError((err as Error).message);
      }
    }
    setLinking(null);
  }

  async function removeLink(link: Linked) {
    try {
      await api(`/api/files/${link.id}`, { method: 'DELETE' });
      touch();
      setLinks((list) => list.filter((l) => l.id !== link.id));
    } catch (err) {
      setError(`${link.name} could not be removed: ${(err as Error).message}`);
    }
  }

  async function send(sendAt?: Date) {
    if (busyRef.current) return;
    if (linking) {
      setError('Wait until the file has been uploaded.');
      return;
    }
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
      const entity = security !== 'none' && crypto && tech ? await protect(crypto, payload(), security, tech) : undefined;
      const result = await api<SendResult>('/api/send', { method: 'POST', body: JSON.stringify({ ...payload(), ...timing, ...(entity ? { entity } : {}) }) });
      dirty.current = false;
      onSent(result);
      onClose(result.scheduled ? undefined : 'Message sent');
    } catch (err) {
      if ((err as Error).message !== 'cancelled') setError((err as Error).message);
    } finally {
      setBusy(null);
    }
  }

  async function saveDraft(closeAfter: boolean, quiet = false) {
    if (busyRef.current || linking) return;
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
    // Closing mid-upload would lose the file (or leave it shared with no message).
    if (linking) {
      setError('Wait until the file has been uploaded, or remove it.');
      return;
    }
    if (dirty.current && hasContent()) saveDraft(true);
    else onClose(savedAt ? 'Draft saved' : undefined);
  }

  async function discard() {
    if (linking) {
      setError('Wait until the file has been uploaded, or remove it.');
      return;
    }
    // Shared files of a discarded message are not left behind.
    for (const link of links) await api(`/api/files/${link.id}`, { method: 'DELETE' }).catch(() => undefined);
    // A draft this window saved on its own goes too; one the user opened stays.
    if (draftUid !== undefined && draftFolder && !isDraft) {
      await api(`/api/folders/${encodeURIComponent(draftFolder)}/messages/bulk`, { method: 'POST', body: JSON.stringify({ action: 'delete', uids: [draftUid] }) }).catch(() => undefined);
      onSent();
    }
    onClose(isDraft ? undefined : 'Discarded');
  }

  function switchFormat(next: Format) {
    if (next === format) return;
    // A pending rewrite belongs to the editor that is going away.
    closeRewrite();
    if (next === 'text') {
      const plain = htmlToTextWithLinks(editorRef.current?.getHTML() || '');
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
        if (e.key === 'Escape' && !e.defaultPrevented) {
          if (laterOpen) setLaterOpen(false);
          else if (rewriteOpen) setRewriteOpen(false);
          else if (rewrite) closeRewrite();
          else close();
        }
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
          plugins={plugins.current}
        />
      ) : (
        <textarea ref={bodyRef} className="compose-body" value={text} lang={prefs.language || undefined} spellCheck onChange={(e) => { setText(e.target.value); touch(); }} aria-label="Message" />
      )}
      {offer && (
        <div className="link-offer" role="alert">
          <Link2 size={15} />
          <span>{offer.length === 1 ? `${offer[0].name} is` : 'These files are'} too large to attach (10 MB in all). Send {offer.length === 1 ? 'it' : 'them'} as a download link instead? Links work for {linkSettings?.days ?? 30} days.</span>
          <button type="button" className="primary small-button" onClick={() => sendAsLinks(offer)}>Send as link</button>
          <button type="button" className="secondary small-button" onClick={() => setOffer(null)}>Cancel</button>
        </div>
      )}
      {linking && <div className="link-offer" role="status"><Link2 size={15} /><span>Uploading {linking.name}… {Math.round((linking.sent / Math.max(1, linking.size)) * 100)}%</span><progress max={linking.size} value={linking.sent} /></div>}
      {(uploads.length > 0 || stored.length > 0 || links.length > 0) && (
        <div className="compose-attachments">
          {links.map((l) => (
            <span className="file-chip link" key={l.id} title={`Sent as a link: ${l.url}`}><Link2 size={12} />{l.name}<small>{formatSize(l.size)} · link</small><button aria-label={`Remove ${l.name}`} onClick={() => removeLink(l)}><X size={12} /></button></span>
          ))}
          {stored.map((s, i) => (
            <span className="file-chip" key={`s${i}`}><Paperclip size={12} />{s.filename}<small>{formatSize(s.size)}</small><button aria-label={`Remove ${s.filename}`} onClick={() => { touch(); setStored((list) => list.filter((_, j) => j !== i)); }}><X size={12} /></button></span>
          ))}
          {uploads.map((u, i) => (
            <span className="file-chip" key={`u${i}`}><Paperclip size={12} />{u.filename}<small>{formatSize(u.size)}</small><button aria-label={`Remove ${u.filename}`} onClick={() => { touch(); setUploads((list) => list.filter((_, j) => j !== i)); }}><X size={12} /></button></span>
          ))}
        </div>
      )}
      {rewrite && (
        <div className="rewrite-panel" role="region" aria-label="Rewrite suggestion" aria-live="polite">
          <div className="rewrite-head">
            <Sparkles size={14} /><strong>{rewrite.label}</strong>
            {!rewrite.result && !rewrite.error && <span className="muted small">Rewriting…</span>}
            <span className="spacer" />
            <button type="button" className="icon" aria-label="Discard rewrite" title="Discard" onClick={closeRewrite}><X size={14} /></button>
          </div>
          {rewrite.result && <p className="rewrite-result">{rewrite.result}</p>}
          {rewrite.error && <p className="error">{rewrite.error}</p>}
          {(rewrite.result || rewrite.error) && (
            <div className="rewrite-actions">
              {rewrite.result && <button type="button" className="primary small-button" onClick={applyRewrite}>Replace selection</button>}
              <button type="button" className="secondary small-button" onClick={() => runRewrite(rewrite.style, rewrite.label, rewrite.selection)}>Try again</button>
              {rewrite.result && <span className="muted small">{mod}Z undoes it</span>}
            </div>
          )}
        </div>
      )}
      {dragging && <div className="drop-hint" aria-hidden="true"><Paperclip size={18} />Drop files to attach (images dropped in the text are placed inline)</div>}
      {error && <p className="error compose-error">{error}</p>}
      <footer>
        <span className="send-group menu-anchor">
          <button className="primary" disabled={busy !== null || linking !== null} onClick={() => send()} title={`Send (${mod}Enter)`}><Send size={14} />{busy === 'send' ? 'Sending…' : 'Send'}</button>
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
        {aiOn && (
          <span className="menu-anchor">
            <button type="button" className={`icon ${rewriteOpen ? 'active' : ''}`} aria-label="Rewrite selection" title="Rewrite the selected text" aria-expanded={rewriteOpen} onMouseDown={(e) => e.preventDefault()} onClick={() => setRewriteOpen(!rewriteOpen)}><Sparkles size={16} /></button>
            {rewriteOpen && (
              <div className="menu rewrite-menu" role="menu" aria-label="Rewrite selection">
                {REWRITE_STYLES.map(([style, label]) => (
                  <button key={style} type="button" role="menuitem" onMouseDown={(e) => e.preventDefault()} onClick={() => runRewrite(style, label, captureSelection())}>{label}</button>
                ))}
              </div>
            )}
          </span>
        )}
        <button className={`icon ${format === 'html' ? 'active' : ''}`} aria-pressed={format === 'html'} aria-label={format === 'html' ? 'Switch to plain text' : 'Switch to formatted text'} title={format === 'html' ? 'Formatted text (click for plain text)' : 'Plain text (click for formatted text)'} onClick={() => switchFormat(format === 'html' ? 'text' : 'html')}><Type size={16} /></button>
        {kinds.length > 0 && (
          <span className={`compose-security ${security !== 'none' ? 'on' : ''}`}>
            <Lock size={14} aria-hidden="true" />
            <select aria-label="Sign or encrypt" value={security} onChange={(e) => setSecurity(e.target.value as Security)}>
              <option value="none">Not signed</option>
              <option value="sign">Sign</option>
              <option value="encrypt">Encrypt</option>
              <option value="sign-encrypt">Sign and encrypt</option>
            </select>
            {kinds.length > 1 && security !== 'none' && (
              <select aria-label="With" value={tech} onChange={(e) => setTechnology(e.target.value as Technology)}>
                <option value="pgp">OpenPGP</option>
                <option value="smime">S/MIME</option>
              </select>
            )}
          </span>
        )}
        <span className="spacer" />
        <span className="save-state muted small">{busy === 'draft' ? 'Saving…' : savedAt ? `Saved ${savedAt.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })}` : ''}</span>
        <button className="secondary" disabled={busy !== null || linking !== null} onClick={() => saveDraft(false)} title={`Save draft (${mod}S)`}>Save draft</button>
        <button className="icon" aria-label="Discard" title="Discard" onClick={discard}><Trash2 size={16} /></button>
      </footer>
    </div>
  );
}
