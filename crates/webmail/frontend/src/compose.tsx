import { useEffect, useRef, useState } from 'react';
import { Paperclip, Send, Trash2, X } from 'lucide-react';
import { Api, Attachment, MessageDetail, formatFullDate, formatSize, splitAddress } from './types';

const MAX_BYTES = 10 * 1024 * 1024;

type Upload = { filename: string; content_type: string; data: string; size: number };
type Stored = { folder: string; uid: number; index: number; filename: string; size: number };

/** What the compose window starts from: blank, a reply, a forward or a draft. */
export type ComposeSeed = {
  to?: string; cc?: string; bcc?: string; subject?: string; text?: string;
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

function quote(message: MessageDetail): string {
  const lines = message.text_body.split('\n').map((line) => `> ${line}`).join('\n');
  return `\n\nOn ${formatFullDate(message.internal_date)}, ${message.from} wrote:\n${lines}\n`;
}

/** Seed for replying to `message`; reply-all adds the other recipients, never yourself. */
export function replySeed(message: MessageDetail, folder: string, self: string, all: boolean): ComposeSeed {
  const sender = message.reply_to || message.from;
  const me = self.toLowerCase();
  const others = all
    ? [...addressList(message.to), ...addressList(message.cc)].filter((a) => splitAddress(a).address.toLowerCase() !== me && splitAddress(a).address.toLowerCase() !== splitAddress(sender).address.toLowerCase())
    : [];
  return {
    to: sender,
    cc: others.join(', '),
    subject: prefixed(message.subject, 'Re'),
    text: quote(message),
    in_reply_to: message.message_id || undefined,
    references: [message.references, message.message_id].filter(Boolean).join(' ') || undefined,
    source: { folder, uid: message.uid, kind: 'reply' },
  };
}

export function forwardSeed(message: MessageDetail, folder: string): ComposeSeed {
  return {
    subject: prefixed(message.subject, 'Fwd'),
    text: `\n\n---------- Forwarded message ----------\nFrom: ${message.from}\nDate: ${formatFullDate(message.internal_date)}\nSubject: ${message.subject}\nTo: ${message.to}${message.cc ? `\nCc: ${message.cc}` : ''}\n\n${message.text_body}\n`,
    stored: message.attachments.map((a: Attachment) => ({ folder, uid: message.uid, index: a.index, filename: a.filename, size: a.size })),
    source: { folder, uid: message.uid, kind: 'forward' },
  };
}

/** Continue editing a saved draft. */
export function draftSeed(message: MessageDetail, folder: string): ComposeSeed {
  return {
    to: message.to, cc: message.cc, bcc: message.bcc, subject: message.subject, text: message.text_body,
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

export function ComposeWindow({ api, from, seed, onClose, onSent }: { api: Api; from: string; seed: ComposeSeed; onClose: (note?: string) => void; onSent: () => void }) {
  const [to, setTo] = useState(seed.to || '');
  const [cc, setCc] = useState(seed.cc || '');
  const [bcc, setBcc] = useState(seed.bcc || '');
  const [showCopies, setShowCopies] = useState(Boolean(seed.cc || seed.bcc));
  const [subject, setSubject] = useState(seed.subject || '');
  const [text, setText] = useState(seed.text || '');
  const [uploads, setUploads] = useState<Upload[]>([]);
  const [stored, setStored] = useState<Stored[]>(seed.stored || []);
  const [draftUid, setDraftUid] = useState<number | undefined>(seed.draft_uid);
  const [busy, setBusy] = useState<'send' | 'draft' | null>(null);
  const [error, setError] = useState('');
  const fileRef = useRef<HTMLInputElement>(null);
  const bodyRef = useRef<HTMLTextAreaElement>(null);
  const initial = useRef(JSON.stringify({ to, cc, bcc, subject, text, n: stored.length }));
  const total = uploads.reduce((sum, u) => sum + u.size, 0) + stored.reduce((sum, s) => sum + s.size, 0);
  const dirty = JSON.stringify({ to, cc, bcc, subject, text, n: stored.length }) !== initial.current || uploads.length > 0;

  useEffect(() => {
    // Replies start typing above the quote.
    if (seed.to && bodyRef.current) {
      bodyRef.current.focus();
      bodyRef.current.setSelectionRange(0, 0);
    }
  }, [seed.to]);

  const payload = () => ({
    to: addressList(to), cc: addressList(cc), bcc: addressList(bcc), subject, text,
    in_reply_to: seed.in_reply_to, references: seed.references,
    attachments: uploads.map(({ filename, content_type, data }) => ({ filename, content_type, data })),
    stored_attachments: stored.map(({ folder, uid, index }) => ({ folder, uid, index })),
    source: seed.source, draft_uid: draftUid,
  });

  async function addFiles(files: FileList | null) {
    if (!files) return;
    const added = await Promise.all(Array.from(files).map(readFile));
    if (total + added.reduce((sum, u) => sum + u.size, 0) > MAX_BYTES) {
      setError('Attachments can be at most 10 MB in total.');
      return;
    }
    setUploads((list) => [...list, ...added]);
  }

  async function send() {
    if (!addressList(to).length && !addressList(cc).length && !addressList(bcc).length) {
      setError('Add at least one recipient.');
      return;
    }
    setBusy('send');
    setError('');
    try {
      await api('/api/send', { method: 'POST', body: JSON.stringify(payload()) });
      onSent();
      onClose('Message sent');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(null);
    }
  }

  async function saveDraft(closeAfter: boolean) {
    setBusy('draft');
    setError('');
    try {
      const saved = await api<{ folder: string; uid: number }>('/api/drafts', { method: 'POST', body: JSON.stringify(payload()) });
      onSent();
      if (closeAfter) {
        onClose('Draft saved');
        return;
      }
      // Keep editing the saved copy; its attachments now live there.
      const draft = await api<MessageDetail>(`/api/folders/${encodeURIComponent(saved.folder)}/messages/${saved.uid}`);
      const nextStored = draft.attachments.map((a) => ({ folder: saved.folder, uid: saved.uid, index: a.index, filename: a.filename, size: a.size }));
      setDraftUid(saved.uid);
      setUploads([]);
      setStored(nextStored);
      initial.current = JSON.stringify({ to, cc, bcc, subject, text, n: nextStored.length });
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(null);
    }
  }

  function close() {
    if (dirty && (text.trim() || subject.trim() || to.trim())) saveDraft(true);
    else onClose();
  }

  return (
    <div className="compose" role="dialog" aria-label="New message" onKeyDown={(e) => {
      if (e.key === 'Escape') close();
      if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) send();
    }}>
      <header>
        <strong>{seed.source?.kind === 'reply' ? 'Reply' : seed.source?.kind === 'forward' ? 'Forward' : draftUid ? 'Draft' : 'New message'}</strong>
        <button className="icon" aria-label="Close (saves a draft)" title="Close (saves a draft)" onClick={close}><X size={16} /></button>
      </header>
      <div className="compose-fields">
        <div className="compose-from"><span>From</span>{from}</div>
        <label><span>To</span><input value={to} onChange={(e) => setTo(e.target.value)} autoFocus={!seed.to} placeholder="name@example.com, …" />{!showCopies && <button type="button" className="link" onClick={() => setShowCopies(true)}>Cc/Bcc</button>}</label>
        {showCopies && <label><span>Cc</span><input value={cc} onChange={(e) => setCc(e.target.value)} /></label>}
        {showCopies && <label><span>Bcc</span><input value={bcc} onChange={(e) => setBcc(e.target.value)} /></label>}
        <label><span>Subject</span><input value={subject} onChange={(e) => setSubject(e.target.value)} /></label>
      </div>
      <textarea ref={bodyRef} className="compose-body" value={text} onChange={(e) => setText(e.target.value)} aria-label="Message" />
      {(uploads.length > 0 || stored.length > 0) && (
        <div className="compose-attachments">
          {stored.map((s, i) => (
            <span className="file-chip" key={`s${i}`}><Paperclip size={12} />{s.filename}<small>{formatSize(s.size)}</small><button aria-label={`Remove ${s.filename}`} onClick={() => setStored((list) => list.filter((_, j) => j !== i))}><X size={12} /></button></span>
          ))}
          {uploads.map((u, i) => (
            <span className="file-chip" key={`u${i}`}><Paperclip size={12} />{u.filename}<small>{formatSize(u.size)}</small><button aria-label={`Remove ${u.filename}`} onClick={() => setUploads((list) => list.filter((_, j) => j !== i))}><X size={12} /></button></span>
          ))}
        </div>
      )}
      {error && <p className="error compose-error">{error}</p>}
      <footer>
        <button className="primary" disabled={busy !== null} onClick={send} title="Send (Ctrl+Enter)"><Send size={14} />{busy === 'send' ? 'Sending…' : 'Send'}</button>
        <input ref={fileRef} type="file" multiple hidden onChange={(e) => { addFiles(e.target.files); e.target.value = ''; }} />
        <button className="icon" aria-label="Attach files" title="Attach files" onClick={() => fileRef.current?.click()}><Paperclip size={16} /></button>
        <span className="spacer" />
        <button className="secondary" disabled={busy !== null} onClick={() => saveDraft(false)}>{busy === 'draft' ? 'Saving…' : 'Save draft'}</button>
        <button className="icon" aria-label="Discard" title="Discard" onClick={() => onClose(draftUid ? undefined : 'Discarded')}><Trash2 size={16} /></button>
      </footer>
    </div>
  );
}
