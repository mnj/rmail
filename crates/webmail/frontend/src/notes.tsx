// Notes: the account's Notes folder, the same notes iPhone and Mac Notes
// sync over IMAP and phones get over ActiveSync. The first line is the title.
import { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, ChevronLeft, Menu, Plus, Trash2 } from 'lucide-react';
import { Api } from './types';

type Note = { id: string; title: string; text: string; created: number; modified: number };

function when(seconds: number): string {
  const date = new Date(seconds * 1000);
  const today = new Date();
  return date.toDateString() === today.toDateString()
    ? date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
    : date.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: date.getFullYear() !== today.getFullYear() ? 'numeric' : undefined });
}

/** What follows the title, for the list. */
function preview(note: Note): string {
  const lines = note.text.split('\n').map((l) => l.trim()).filter(Boolean);
  return (lines[0] === note.title ? lines.slice(1) : lines).join(' ').slice(0, 120);
}

export function NotesView({ api, onShowFolders, flash }: { api: Api; onShowFolders: () => void; flash: (text: string) => void }) {
  const [notes, setNotes] = useState<Note[] | null>(null);
  const [open, setOpen] = useState<string | 'new' | null>(null);
  const [draft, setDraft] = useState('');
  const [saved, setSaved] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [query, setQuery] = useState('');

  const load = useCallback(() => api<{ notes: Note[] }>('/api/notes')
    .then((data) => { setNotes(data.notes); setError(''); return data.notes; })
    .catch((err) => { setError((err as Error).message); return [] as Note[]; }), [api]);
  useEffect(() => { load(); }, [load]);

  const dirty = draft !== saved;
  function select(id: string | 'new' | null) {
    if (dirty && draft.trim() && !window.confirm('Discard the changes to this note?')) return;
    const note = notes?.find((n) => n.id === id);
    setOpen(id);
    setDraft(note?.text ?? '');
    setSaved(note?.text ?? '');
    setError('');
  }

  async function save() {
    if (busy || !dirty || !draft.trim()) return;
    setBusy(true);
    try {
      const path = open && open !== 'new' ? `/api/notes/${encodeURIComponent(open)}` : '/api/notes';
      const reply = await api<{ note: Note }>(path, { method: open && open !== 'new' ? 'PUT' : 'POST', body: JSON.stringify({ text: draft }) });
      setOpen(reply.note.id);
      setSaved(reply.note.text);
      setDraft(reply.note.text);
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    if (!open || open === 'new') { setOpen(null); setDraft(''); setSaved(''); return; }
    const note = notes?.find((n) => n.id === open);
    if (!window.confirm(`Delete "${note?.title || 'this note'}"?`)) return;
    try {
      await api(`/api/notes/${encodeURIComponent(open)}`, { method: 'DELETE' });
      setOpen(null);
      setDraft('');
      setSaved('');
      flash('Note deleted.');
      await load();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  const needle = query.trim().toLowerCase();
  const shown = (notes ?? []).filter((n) => !needle || n.text.toLowerCase().includes(needle));

  return (
    <section className={`calendar-pane notes-pane ${open ? 'editing' : ''}`} aria-label="Notes">
      <header className="calendar-bar">
        <button className="icon mobile-only" aria-label="Folders" title="Folders" onClick={onShowFolders}><Menu size={18} /></button>
        <h2>Notes</h2>
        {notes && <span className="muted small">{notes.length}</span>}
        <span className="spacer" />
        <button className="primary small-button" onClick={() => select('new')}><Plus size={14} />New note</button>
      </header>
      {error && <p className="error calendar-error" role="alert"><AlertTriangle size={14} /> {error}</p>}
      <div className="notes-body">
        <div className="notes-list">
          <input className="notes-search" aria-label="Search notes" placeholder="Search notes" value={query} onChange={(e) => setQuery(e.target.value)} />
          {notes === null && !error && <p className="muted tasks-empty">Loading…</p>}
          {notes && shown.length === 0 && <p className="muted tasks-empty">{needle ? 'No notes match.' : 'No notes yet. Notes from iPhone and Mac Notes show here too.'}</p>}
          <ul>
            {shown.map((note) => (
              <li key={note.id}>
                <button type="button" className={`note-item ${open === note.id ? 'active' : ''}`} onClick={() => select(note.id)}>
                  <strong>{note.title || '(untitled)'}</strong>
                  <span className="muted small"><time>{when(note.modified)}</time> {preview(note)}</span>
                </button>
              </li>
            ))}
          </ul>
        </div>
        <div className="note-editor">
          {open ? <>
            <div className="note-actions">
              <button className="icon mobile-only" aria-label="Back to notes" title="Back" onClick={() => select(null)}><ChevronLeft size={18} /></button>
              <span className="muted small">{open === 'new' ? 'New note' : dirty ? 'Changed' : 'Saved'}</span>
              <span className="spacer" />
              <button className="secondary small-button danger-quiet" onClick={remove}><Trash2 size={14} />{open === 'new' ? 'Discard' : 'Delete'}</button>
              <button className="primary small-button" disabled={busy || !dirty || !draft.trim()} onClick={save}>{busy ? 'Saving…' : 'Save'}</button>
            </div>
            <textarea aria-label="Note" autoFocus value={draft} maxLength={100000} placeholder="Title on the first line, then the note" onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => { if ((e.metaKey || e.ctrlKey) && e.key === 's') { e.preventDefault(); save(); } }} />
          </> : <div className="empty"><p>Select a note</p><small>Or start a new one.</small></div>}
        </div>
      </div>
    </section>
  );
}
