// Tasks: the to-dos of the user's calendars (and those shared with them),
// the same ones Apple Reminders, Thunderbird and phones show.
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { AlertTriangle, Flag, Menu, Plus, Repeat, Trash2, X } from 'lucide-react';
import { Api } from './types';

type TaskList = { id: string; displayname: string; color: string | null; owner: string | null; writable: boolean };
type Task = {
  list: string; name: string; etag: string;
  summary: string; notes: string; due: number | null; due_all_day: boolean; priority: number; completed: boolean;
  completed_at: number | null; recurring: boolean; editable: boolean;
};
type Fields = Pick<Task, 'summary' | 'notes' | 'due' | 'due_all_day' | 'priority' | 'completed'>;

const priorities: { value: number; label: string }[] = [
  { value: 0, label: 'None' }, { value: 1, label: 'High' }, { value: 5, label: 'Medium' }, { value: 9, label: 'Low' },
];
const priorityName = (p: number) => (p >= 1 && p <= 4 ? 'High' : p === 5 ? 'Medium' : p >= 6 ? 'Low' : '');

const pad = (n: number) => String(n).padStart(2, '0');
/** A due date as the user sees it: a date-only due is a UTC date. */
function dueDate(task: Pick<Task, 'due' | 'due_all_day'>): Date | null {
  if (task.due == null) return null;
  const d = new Date(task.due * 1000);
  return task.due_all_day ? new Date(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()) : d;
}
function startOfToday(): Date { const d = new Date(); d.setHours(0, 0, 0, 0); return d; }

function dueLabel(task: Task): string {
  const date = dueDate(task);
  if (!date) return '';
  const today = startOfToday();
  const days = Math.round((new Date(date.getFullYear(), date.getMonth(), date.getDate()).getTime() - today.getTime()) / 86_400_000);
  const day = days === 0 ? 'Today' : days === 1 ? 'Tomorrow' : days === -1 ? 'Yesterday'
    : date.toLocaleDateString(undefined, { weekday: days > 1 && days < 7 ? 'long' : undefined, day: 'numeric', month: 'short', year: date.getFullYear() !== today.getFullYear() ? 'numeric' : undefined });
  return task.due_all_day ? day : `${day}, ${date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })}`;
}

type Group = 'overdue' | 'today' | 'upcoming' | 'someday' | 'done';
const groupTitles: Record<Group, string> = { overdue: 'Overdue', today: 'Today', upcoming: 'Upcoming', someday: 'No date', done: 'Done' };

function groupOf(task: Task): Group {
  if (task.completed) return 'done';
  const date = dueDate(task);
  if (!date) return 'someday';
  const today = startOfToday();
  // The next calendar day (not 24 hours: clock changes make days 23 or 25).
  const tomorrow = new Date(today.getFullYear(), today.getMonth(), today.getDate() + 1);
  if (task.due_all_day ? date < today : date.getTime() < Date.now()) return 'overdue';
  return date < tomorrow ? 'today' : 'upcoming';
}

export function TasksView({ api, onShowFolders, flash }: { api: Api; onShowFolders: () => void; flash: (text: string) => void }) {
  const [lists, setLists] = useState<TaskList[]>([]);
  const [tasks, setTasks] = useState<Task[] | null>(null);
  const [error, setError] = useState('');
  const [shown, setShown] = useState<string>('all');
  const [showDone, setShowDone] = useState(false);
  const [title, setTitle] = useState('');
  const [editing, setEditing] = useState<Task | null>(null);

  const load = useCallback(() => api<{ lists: TaskList[]; tasks: Task[] }>('/api/tasks')
    .then((data) => { setLists(data.lists); setTasks(data.tasks); setError(''); })
    .catch((err) => setError((err as Error).message)), [api]);
  useEffect(() => { load(); }, [load]);

  const writable = lists.filter((l) => l.writable);
  const target = shown !== 'all' && writable.some((l) => l.id === shown) ? shown : writable[0]?.id;
  const visible = (tasks ?? []).filter((t) => shown === 'all' || t.list === shown);
  const grouped = useMemo(() => {
    const out: Record<Group, Task[]> = { overdue: [], today: [], upcoming: [], someday: [], done: [] };
    for (const task of visible) out[groupOf(task)].push(task);
    const byDue = (a: Task, b: Task) => (a.due ?? Infinity) - (b.due ?? Infinity) || (a.priority || 10) - (b.priority || 10) || a.summary.localeCompare(b.summary);
    (['overdue', 'today', 'upcoming', 'someday'] as Group[]).forEach((g) => out[g].sort(byDue));
    out.done.sort((a, b) => (b.completed_at ?? 0) - (a.completed_at ?? 0));
    return out;
  }, [visible]);
  const listOf = (id: string) => lists.find((l) => l.id === id);

  async function save(list: string, name: string | null, fields: Fields, etag: string | null) {
    const path = name ? `/api/tasks/${encodeURIComponent(list)}/${encodeURIComponent(name)}` : `/api/tasks/${encodeURIComponent(list)}`;
    await api(path, { method: name ? 'PUT' : 'POST', body: JSON.stringify({ ...fields, etag }) });
    await load();
  }

  async function add(event: React.FormEvent) {
    event.preventDefault();
    if (!title.trim() || !target) return;
    try {
      await save(target, null, { summary: title.trim(), notes: '', due: null, due_all_day: false, priority: 0, completed: false }, null);
      setTitle('');
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function toggle(task: Task) {
    try {
      await save(task.list, task.name, { ...task, completed: !task.completed }, task.etag);
      if (!task.completed) flash(task.recurring ? 'Marked done (the whole repeating task).' : 'Marked done.');
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function remove(task: Task) {
    if (!window.confirm(`Delete "${task.summary}"?`)) return;
    try {
      await api(`/api/tasks/${encodeURIComponent(task.list)}/${encodeURIComponent(task.name)}?etag=${encodeURIComponent(task.etag)}`, { method: 'DELETE' });
      setEditing(null);
      flash('Task deleted.');
      await load();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  const groups: Group[] = showDone ? ['overdue', 'today', 'upcoming', 'someday', 'done'] : ['overdue', 'today', 'upcoming', 'someday'];
  const open = visible.filter((t) => !t.completed).length;

  return (
    <section className="calendar-pane tasks-pane" aria-label="Tasks">
      <header className="calendar-bar">
        <button className="icon mobile-only" aria-label="Folders" title="Folders" onClick={onShowFolders}><Menu size={18} /></button>
        <h2>Tasks</h2>
        {tasks && <span className="muted small">{open} open</span>}
        <span className="spacer" />
        {lists.length > 1 && (
          <select aria-label="List" value={shown} onChange={(e) => setShown(e.target.value)}>
            <option value="all">All lists</option>
            {lists.map((l) => <option key={l.id} value={l.id}>{l.displayname}{l.owner ? ` (${l.owner})` : ''}</option>)}
          </select>
        )}
        <label className="check-row small"><input type="checkbox" checked={showDone} onChange={(e) => setShowDone(e.target.checked)} /><span>Show done</span></label>
      </header>
      {error && <p className="error calendar-error" role="alert"><AlertTriangle size={14} /> {error}</p>}
      <div className="tasks-body">
        {target && (
          <form className="task-add" onSubmit={add}>
            <Plus size={16} aria-hidden="true" />
            <input aria-label="New task" placeholder={`Add a task${lists.length > 1 ? ` to ${listOf(target)?.displayname}` : ''}`} value={title} maxLength={500} onChange={(e) => setTitle(e.target.value)} />
          </form>
        )}
        {tasks === null && !error && <p className="muted tasks-empty">Loading…</p>}
        {tasks && visible.length === 0 && <p className="muted tasks-empty">No tasks yet. Tasks from Reminders, Thunderbird and your phone show here too.</p>}
        {groups.filter((g) => grouped[g].length > 0).map((g) => (
          <section key={g} className={`task-group ${g}`}>
            <h3>{groupTitles[g]} <span className="muted">{grouped[g].length}</span></h3>
            <ul>
              {grouped[g].map((task) => {
                const list = listOf(task.list);
                return (
                  <li key={`${task.list}/${task.name}`} className={`task-row ${task.completed ? 'done' : ''}`}>
                    <input type="checkbox" aria-label={task.completed ? `Mark "${task.summary}" not done` : `Mark "${task.summary}" done`} checked={task.completed} disabled={!task.editable} onChange={() => toggle(task)} />
                    <button type="button" className="task-main" onClick={() => setEditing(task)}>
                      <span className="task-title">{task.summary || '(no title)'}</span>
                      <span className="task-meta">
                        {task.due != null && <span className={g === 'overdue' ? 'overdue' : ''}>{dueLabel(task)}</span>}
                        {task.recurring && <span title="Repeats"><Repeat size={12} /></span>}
                        {priorityName(task.priority) && <span className={`task-priority p${priorityName(task.priority).toLowerCase()}`}><Flag size={12} />{priorityName(task.priority)}</span>}
                        {lists.length > 1 && shown === 'all' && list && <span>{list.displayname}</span>}
                        {task.notes && <span className="task-notes">{task.notes.split('\n')[0]}</span>}
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          </section>
        ))}
      </div>
      {editing && <TaskEditor task={editing} list={listOf(editing.list)} onClose={() => setEditing(null)} onDelete={() => remove(editing)} onSave={async (fields) => { await save(editing.list, editing.name, fields, editing.etag); setEditing(null); }} />}
    </section>
  );
}

function TaskEditor({ task, list, onClose, onSave, onDelete }: { task: Task; list: TaskList | undefined; onClose: () => void; onSave: (fields: Fields) => Promise<void>; onDelete: () => void }) {
  const due = dueDate(task);
  const [summary, setSummary] = useState(task.summary);
  const [notes, setNotes] = useState(task.notes);
  const [date, setDate] = useState(due ? `${due.getFullYear()}-${pad(due.getMonth() + 1)}-${pad(due.getDate())}` : '');
  const [time, setTime] = useState(due && !task.due_all_day ? `${pad(due.getHours())}:${pad(due.getMinutes())}` : '');
  const [priority, setPriority] = useState(task.priority);
  const [completed, setCompleted] = useState(task.completed);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const readOnly = !task.editable;

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    let dueSeconds: number | null = null;
    if (date) {
      const [y, m, d] = date.split('-').map(Number);
      if (time) {
        const [h, min] = time.split(':').map(Number);
        dueSeconds = new Date(y, m - 1, d, h, min).getTime() / 1000;
      } else {
        dueSeconds = Date.UTC(y, m - 1, d) / 1000;
      }
    }
    try {
      await onSave({ summary, notes, due: dueSeconds, due_all_day: Boolean(date) && !time, priority, completed });
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  }

  return (
    <div className="dialog-scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()} onKeyDown={(e) => e.key === 'Escape' && onClose()}>
      <form className="dialog small" role="dialog" aria-modal="true" aria-label="Task" onSubmit={submit}>
        <header><h2>Task</h2><button type="button" className="icon" aria-label="Close" title="Close" onClick={onClose}><X size={16} /></button></header>
        <fieldset className="rules-fieldset" disabled={readOnly}>
          <label className="field"><span>Title</span><input autoFocus value={summary} maxLength={500} onChange={(e) => setSummary(e.target.value)} required /></label>
          <div className="settings-grid two">
            <label className="field"><span>Due date</span><input type="date" value={date} onChange={(e) => setDate(e.target.value)} /></label>
            <label className="field"><span>Time (optional)</span><input type="time" value={time} disabled={!date} onChange={(e) => setTime(e.target.value)} /></label>
          </div>
          <label className="field"><span>Priority</span>
            <select value={priority} onChange={(e) => setPriority(Number(e.target.value))}>
              {!priorities.some((p) => p.value === priority) && <option value={priority}>{priorityName(priority)}</option>}
              {priorities.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
            </select>
          </label>
          <label className="field"><span>Notes</span><textarea rows={5} value={notes} maxLength={20000} onChange={(e) => setNotes(e.target.value)} /></label>
          <label className="check-row"><input type="checkbox" checked={completed} onChange={(e) => setCompleted(e.target.checked)} /><span>Done</span></label>
        </fieldset>
        {task.recurring && <p className="dialog-hint">This task repeats; its repeat rule is kept as it is.</p>}
        {list && <p className="dialog-hint">In {list.displayname}{list.owner ? `, shared by ${list.owner}` : ''}{readOnly ? ' (read-only)' : ''}.</p>}
        {error && <p className="error" role="alert">{error}</p>}
        <footer>
          {!readOnly && <button type="button" className="secondary danger-quiet" onClick={onDelete}><Trash2 size={14} />Delete</button>}
          <span className="spacer" />
          <button type="button" className="secondary" onClick={onClose}>Cancel</button>
          {!readOnly && <button className="primary" disabled={busy || !summary.trim()}>{busy ? 'Saving…' : 'Save'}</button>}
        </footer>
      </form>
    </div>
  );
}
