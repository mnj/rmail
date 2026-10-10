// Compose settings: default format, spellchecking language, undo send,
// names and signatures per identity, and messages waiting to be sent.

import { useEffect, useRef, useState } from 'react';
import { CalendarClock, X } from 'lucide-react';
import { EditorHandle, RichEditor } from './editor';
import { Api, ComposePrefs, Identity, Scheduled, formatFullDate } from './types';

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

  useEffect(() => {
    api<Scheduled[]>('/api/scheduled').then(setScheduled).catch(() => setScheduled([]));
  }, [api]);

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
        {error && <p className="error">{error}</p>}
        <footer><button type="button" className="secondary" onClick={onClose}>Cancel</button><button className="primary" disabled={busy}>{busy ? 'Saving…' : 'Save'}</button></footer>
      </form>
    </div>
  );
}
