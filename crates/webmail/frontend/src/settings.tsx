// Compose settings: default format, spellchecking language, undo send, AI
// writing suggestions (when the server offers them), names and signatures
// per identity, messages waiting to be sent, and large files shared as links.

import { useEffect, useRef, useState } from 'react';
import { CalendarClock, Copy, Link2, Sparkles, Trash2, X } from 'lucide-react';
import { FileListing, SharedFile } from './filelinks';
import { EditorHandle, RichEditor } from './editor';
import { Api, ComposePrefs, Identity, Scheduled, formatFullDate, formatSize } from './types';

/** Languages offered for spellchecking; the browser needs a dictionary for the one chosen. */
const LANGUAGES = ['en', 'en-US', 'en-GB', 'da', 'de', 'nl', 'fr', 'es', 'it', 'pt', 'pt-BR', 'sv', 'nb', 'nn', 'fi', 'is', 'pl', 'cs', 'uk', 'ru', 'el', 'tr', 'ja', 'zh'];

function languageName(tag: string): string {
  try {
    return new Intl.DisplayNames(undefined, { type: 'language' }).of(tag) || tag;
  } catch {
    return tag;
  }
}

function SignatureEditor({ identity, editorRef, onName, lang }: { identity: Identity; editorRef: (handle: EditorHandle | null) => void; onName: (name: string) => void; lang: string }) {
  return (
    <div className="identity-card">
      <label className="field"><span>Name shown to recipients ({identity.email})</span><input value={identity.name} onChange={(e) => onName(e.target.value)} placeholder="Your name" /></label>
      <div className="field">
        <span>Signature</span>
        <RichEditor ref={editorRef} compact initialHtml={identity.html_signature || identity.text_signature.split('\n').map((l) => `<div>${l.replace(/&/g, '&amp;').replace(/</g, '&lt;') || '<br>'}</div>`).join('')} lang={lang} label={`Signature for ${identity.email}`} className="signature-editor" />
      </div>
    </div>
  );
}

export function ComposeSettingsDialog({ api, prefs, identities, onClose, onSaved, onOpenDraft }: {
  api: Api; prefs: ComposePrefs; identities: Identity[]; onClose: () => void; onSaved: () => void;
  onOpenDraft: (folder: string, uid: number) => void;
}) {
  const [draft, setDraft] = useState(prefs);
  const [names, setNames] = useState<Record<string, string>>(() => Object.fromEntries(identities.map((i) => [i.id, i.name])));
  const [scheduled, setScheduled] = useState<Scheduled[] | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const editors = useRef<Record<string, EditorHandle | null>>({});

  const [files, setFiles] = useState<FileListing | null>(null);
  useEffect(() => {
    api<Scheduled[]>('/api/scheduled').then(setScheduled).catch(() => setScheduled([]));
    api<FileListing>('/api/files').then(setFiles).catch(() => setFiles(null));
  }, [api]);

  async function removeFile(file: SharedFile) {
    if (!window.confirm(`Delete ${file.name}? Its link stops working.`)) return;
    try {
      await api(`/api/files/${file.id}`, { method: 'DELETE' });
      setFiles((current) => current && { ...current, files: current.files.filter((f) => f.id !== file.id), used: current.used - file.size });
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function save(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      await api('/api/compose/settings', { method: 'PUT', body: JSON.stringify(draft) });
      for (const identity of identities) {
        const handle = editors.current[identity.id];
        const html = handle?.getHTML() ?? identity.html_signature;
        // The text version follows what is in the editor, so clearing the
        // signature clears it for plain-text messages too.
        const text = handle ? handle.getText().replace(/\n+$/, '') : identity.text_signature;
        await api(`/api/identities/${encodeURIComponent(identity.id)}`, { method: 'PUT', body: JSON.stringify({ name: names[identity.id] ?? identity.name, html_signature: html, text_signature: text }) });
      }
      onSaved();
      onClose();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function cancel(item: Scheduled) {
    try {
      const draftAt = await api<{ folder: string; uid: number }>(`/api/scheduled/${item.id}/cancel`, { method: 'POST' });
      setScheduled((list) => (list || []).filter((s) => s.id !== item.id));
      onOpenDraft(draftAt.folder, draftAt.uid);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <div className="dialog-scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()} onKeyDown={(e) => e.key === 'Escape' && !e.defaultPrevented && onClose()}>
      <form className="dialog settings-dialog" role="dialog" aria-label="Compose settings" onSubmit={save}>
        <header><h2>Compose settings</h2><button type="button" className="icon" aria-label="Close" title="Close" onClick={onClose}><X size={16} /></button></header>
        <div className="settings-grid">
          <label className="field"><span>New messages</span>
            <select value={draft.format} onChange={(e) => setDraft({ ...draft, format: e.target.value as ComposePrefs['format'] })}>
              <option value="html">Formatted text (HTML)</option>
              <option value="text">Plain text</option>
            </select>
          </label>
          <label className="field"><span>Spellchecking language</span>
            <select value={draft.language} onChange={(e) => setDraft({ ...draft, language: e.target.value })}>
              <option value="">Browser default</option>
              {LANGUAGES.map((tag) => <option key={tag} value={tag}>{languageName(tag)}</option>)}
            </select>
          </label>
          <label className="field"><span>Undo send</span>
            <select value={draft.undo_seconds} onChange={(e) => setDraft({ ...draft, undo_seconds: Number(e.target.value) })}>
              <option value={0}>Off</option>
              {[5, 10, 20, 30, 60].map((s) => <option key={s} value={s}>{s} seconds</option>)}
            </select>
          </label>
        </div>
        <p className="dialog-hint">Spelling is checked by your browser, in the language chosen here when the browser has a dictionary for it. With undo send, messages wait on the server for the chosen time (up to 15 seconds more) before they go out.</p>
        {prefs.ai?.available && (
          <>
            <label className="check-row">
              <input type="checkbox" checked={draft.ai_suggestions} onChange={(e) => setDraft({ ...draft, ai_suggestions: e.target.checked })} />
              <span><Sparkles size={14} />Writing suggestions</span>
            </label>
            <p className="dialog-hint">
              Grey suggestions appear after the cursor when you pause typing; Tab (or a tap) accepts them, Esc or typing on dismisses them. The rewrite button makes selected text shorter, more formal, friendlier or fixes its grammar.
              {' '}While this is on, the text around the cursor, the subject and the message you reply to are sent to {prefs.ai.provider ? <strong>{prefs.ai.provider}</strong> : 'the AI service'} through this server. Nothing else from your mailbox is sent.
            </p>
          </>
        )}
        <h3 className="dialog-section">Signatures</h3>
        {identities.map((identity) => (
          <SignatureEditor key={identity.id} identity={{ ...identity, name: names[identity.id] ?? identity.name }} lang={draft.language} editorRef={(handle) => { editors.current[identity.id] = handle; }} onName={(name) => setNames({ ...names, [identity.id]: name })} />
        ))}
        <h3 className="dialog-section"><CalendarClock size={15} />Scheduled messages</h3>
        {scheduled === null ? <p className="muted">Loading…</p> : scheduled.length === 0 ? <p className="muted">Nothing is waiting to be sent.</p> : (
          <ul className="scheduled-list">
            {scheduled.map((item) => (
              <li key={item.id}>
                <span><strong>{item.subject || '(no subject)'}</strong><small>{formatFullDate(item.send_at)} · to {item.recipients.join(', ')}</small></span>
                <button type="button" className="secondary small-button" onClick={() => cancel(item)} title="Stop sending and open it as a draft">Edit</button>
              </li>
            ))}
          </ul>
        )}
        {files?.enabled && <>
          <h3 className="dialog-section"><Link2 size={15} />Large files shared as links</h3>
          <p className="dialog-hint">Files too large to attach are sent as download links. Anyone with a link can download the file until it expires. {formatSize(files.used)} of {formatSize(files.per_user_bytes)} used.</p>
          {files.files.length === 0 ? <p className="muted">No shared files.</p> : (
            <ul className="scheduled-list">
              {files.files.map((file) => (
                <li key={file.id}>
                  <span><strong>{file.name}</strong><small>{formatSize(file.size)} · until {formatFullDate(file.expires)} · {file.downloads} download{file.downloads === 1 ? '' : 's'}</small></span>
                  <button type="button" className="icon" aria-label={`Copy the link to ${file.name}`} title="Copy link" onClick={() => navigator.clipboard?.writeText(`${window.location.origin}${file.url}`)}><Copy size={14} /></button>
                  <button type="button" className="icon" aria-label={`Delete ${file.name}`} title="Delete" onClick={() => removeFile(file)}><Trash2 size={14} /></button>
                </li>
              ))}
            </ul>
          )}
        </>}
        {error && <p className="error">{error}</p>}
        <footer><button type="button" className="secondary" onClick={onClose}>Cancel</button><button className="primary" disabled={busy}>{busy ? 'Saving…' : 'Save'}</button></footer>
      </form>
    </div>
  );
}
