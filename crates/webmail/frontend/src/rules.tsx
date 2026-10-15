// Out-of-office replies and mail filters. Filters are kept as the
// account's Sieve script on the server, so they run on delivery whichever
// app the mail is read in; a hand-written script is shown as text.

import React, { useEffect, useState } from 'react';
import { ArrowDown, ArrowUp, Filter, Plane, Plus, Trash2, X } from 'lucide-react';
import { Api, ApiError, Folder, Label } from './types';

export type Vacation = { enabled: boolean; from: number | null; until: number | null; subject: string; text: string };

type Field = 'from' | 'to' | 'subject' | 'header' | 'size';
type Op = 'contains' | 'not_contains' | 'is' | 'is_not' | 'over' | 'under';
type Condition = { field: Field; header?: string; op: Op; value: string };
type Action =
  | { type: 'move'; folder: string }
  | { type: 'mark_read' }
  | { type: 'star' }
  | { type: 'label'; keyword: string }
  | { type: 'forward'; address: string; keep: boolean }
  | { type: 'delete' };
type Rule = { name: string; enabled: boolean; any: boolean; conditions: Condition[]; actions: Action[]; stop: boolean };
type Filters = { mode: 'rules' | 'script' | 'none'; rules: Rule[]; script?: string; script_name?: string };

// ---------------------------------------------------------------------------
// Out of office

/** A local calendar date (`YYYY-MM-DD`) for an input, from Unix seconds. */
function dateInput(seconds: number | null, endExclusive = false): string {
  if (seconds == null) return '';
  const date = new Date((seconds - (endExclusive ? 1 : 0)) * 1000);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

/** Local midnight at the start of `value` (or of the day after it). */
function fromDateInput(value: string, dayAfter = false): number | null {
  if (!value) return null;
  const [year, month, day] = value.split('-').map(Number);
  return Math.floor(new Date(year, month - 1, day + (dayAfter ? 1 : 0)).getTime() / 1000);
}

/** Whether replies are going out now, and until when, for the banner. */
export function vacationNote(vacation: Vacation | null): string | null {
  if (!vacation?.enabled) return null;
  const now = Date.now() / 1000;
  if (vacation.until != null && now >= vacation.until) return null;
  const day = (seconds: number) => new Date(seconds * 1000).toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
  if (vacation.from != null && now < vacation.from) {
    return `Out-of-office replies start ${day(vacation.from)}${vacation.until != null ? ` and end ${day(vacation.until - 1)}` : ''}.`;
  }
  return vacation.until != null ? `Out-of-office replies are on until ${day(vacation.until - 1)}.` : 'Out-of-office replies are on.';
}

export function VacationDialog({ api, initial, onClose, onSaved }: { api: Api; initial: Vacation; onClose: () => void; onSaved: (vacation: Vacation) => void }) {
  const [draft, setDraft] = useState(initial);
  const [from, setFrom] = useState(dateInput(initial.from));
  const [until, setUntil] = useState(dateInput(initial.until, true));
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function save(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const body = { ...draft, from: fromDateInput(from), until: fromDateInput(until, true) };
      onSaved(await api<Vacation>('/api/vacation', { method: 'PUT', body: JSON.stringify(body) }));
      onClose();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="dialog-scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()} onKeyDown={(e) => e.key === 'Escape' && onClose()}>
      <form className="dialog" role="dialog" aria-modal="true" aria-label="Out of office" onSubmit={save}>
        <header><h2>Out of office</h2><button type="button" className="icon" aria-label="Close" title="Close" onClick={onClose}><X size={16} /></button></header>
        <p className="dialog-intro">People who write to you get this reply once a week each. Mailing lists, automated mail and your own messages get none.</p>
        <label className="check-row"><input type="checkbox" autoFocus checked={draft.enabled} onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })} /><span>Send out-of-office replies</span></label>
        <fieldset className="rules-fieldset" disabled={!draft.enabled}>
          <div className="settings-grid two">
            <label className="field"><span>From (optional)</span><input type="date" value={from} onChange={(e) => setFrom(e.target.value)} /></label>
            <label className="field"><span>Until, including (optional)</span><input type="date" value={until} min={from || undefined} onChange={(e) => setUntil(e.target.value)} /></label>
          </div>
          <label className="field"><span>Subject</span><input value={draft.subject} maxLength={200} placeholder="Out of office" onChange={(e) => setDraft({ ...draft, subject: e.target.value })} /></label>
          <label className="field"><span>Reply</span><textarea rows={7} value={draft.text} maxLength={20000} placeholder="I'm away until Monday and will answer when I'm back." onChange={(e) => setDraft({ ...draft, text: e.target.value })} /></label>
        </fieldset>
        {error && <p className="error">{error}</p>}
        <footer><button type="button" className="secondary" onClick={onClose}>Cancel</button><button className="primary" disabled={busy}>{busy ? 'Saving…' : 'Save'}</button></footer>
      </form>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Filters

const fieldNames: Record<Field, string> = { from: 'From', to: 'To or Cc', subject: 'Subject', header: 'Header', size: 'Size' };
const textOps: { op: Op; label: string }[] = [
  { op: 'contains', label: 'contains' }, { op: 'not_contains', label: 'doesn’t contain' },
  { op: 'is', label: 'is' }, { op: 'is_not', label: 'isn’t' },
];
const sizeOps: { op: Op; label: string }[] = [{ op: 'over', label: 'is over' }, { op: 'under', label: 'is under' }];
const actionNames: Record<Action['type'], string> = {
  move: 'Move to folder', mark_read: 'Mark as read', star: 'Star', label: 'Add label', forward: 'Forward to', delete: 'Delete',
};

function newRule(): Rule {
  return { name: '', enabled: true, any: false, conditions: [{ field: 'from', op: 'contains', value: '' }], actions: [{ type: 'move', folder: '' }], stop: false };
}

function newAction(type: Action['type'], folders: Folder[], labels: Label[]): Action {
  switch (type) {
    case 'move': return { type, folder: folders[0]?.name ?? '' };
    case 'label': return { type, keyword: labels[0]?.keyword ?? '' };
    case 'forward': return { type, address: '', keep: true };
    default: return { type } as Action;
  }
}

/** One line describing a rule, for the collapsed list. */
function describe(rule: Rule, labels: Label[]): string {
  const when = rule.conditions.length === 0 ? 'Every message' : rule.conditions.map((c) => {
    const field = c.field === 'header' ? (c.header || 'header') : fieldNames[c.field].toLowerCase();
    const op = [...textOps, ...sizeOps].find((o) => o.op === c.op)?.label ?? c.op;
    return `${field} ${op} “${c.value}”`;
  }).join(rule.any ? ' or ' : ' and ');
  const then = rule.actions.map((a) => {
    switch (a.type) {
      case 'move': return `move to ${a.folder}`;
      case 'label': return `label ${labels.find((l) => l.keyword === a.keyword)?.name ?? a.keyword}`;
      case 'forward': return `forward to ${a.address}${a.keep ? '' : ' (no copy kept)'}`;
      default: return actionNames[a.type].toLowerCase();
    }
  }).join(', ');
  return `${when}: ${then}`;
}

function RuleEditor({ rule, folders, labels, onChange, onDone, onDelete }: {
  rule: Rule; folders: Folder[]; labels: Label[]; onChange: (rule: Rule) => void; onDone: () => void; onDelete: () => void;
}) {
  const setCondition = (index: number, condition: Condition) => onChange({ ...rule, conditions: rule.conditions.map((c, i) => (i === index ? condition : c)) });
  const setAction = (index: number, action: Action) => onChange({ ...rule, actions: rule.actions.map((a, i) => (i === index ? action : a)) });
  const actionTypes = (Object.keys(actionNames) as Action['type'][]).filter((type) => type !== 'label' || labels.length > 0);
  return (
    <div className="rule-editor">
      <label className="field"><span>Name</span><input value={rule.name} maxLength={100} placeholder="e.g. Newsletters" onChange={(e) => onChange({ ...rule, name: e.target.value })} /></label>
      <div className="rule-section">
        <span className="rule-heading">When
          <select aria-label="Match" value={rule.any ? 'any' : 'all'} onChange={(e) => onChange({ ...rule, any: e.target.value === 'any' })}>
            <option value="all">all</option><option value="any">any</option>
          </select> of these match
        </span>
        {rule.conditions.map((condition, index) => (
          <div className="rule-row" key={index}>
            <select aria-label="Field" value={condition.field} onChange={(e) => {
              const field = e.target.value as Field;
              const op = field === 'size' ? 'over' : (condition.op === 'over' || condition.op === 'under' ? 'contains' : condition.op);
              setCondition(index, { ...condition, field, op, value: field === 'size' ? '1M' : condition.field === 'size' ? '' : condition.value });
            }}>
              {(Object.keys(fieldNames) as Field[]).map((field) => <option key={field} value={field}>{fieldNames[field]}</option>)}
            </select>
            {condition.field === 'header' && <input aria-label="Header name" className="narrow" placeholder="List-Id" value={condition.header ?? ''} onChange={(e) => setCondition(index, { ...condition, header: e.target.value })} />}
            <select aria-label="Comparison" value={condition.op} onChange={(e) => setCondition(index, { ...condition, op: e.target.value as Op })}>
              {(condition.field === 'size' ? sizeOps : textOps).map(({ op, label }) => <option key={op} value={op}>{label}</option>)}
            </select>
            <input aria-label="Value" value={condition.value} placeholder={condition.field === 'size' ? '1M' : ''} onChange={(e) => setCondition(index, { ...condition, value: e.target.value })} />
            <button type="button" className="icon" aria-label="Remove condition" title="Remove condition" onClick={() => onChange({ ...rule, conditions: rule.conditions.filter((_, i) => i !== index) })}><X size={14} /></button>
          </div>
        ))}
        <button type="button" className="link add-link" onClick={() => onChange({ ...rule, conditions: [...rule.conditions, { field: 'subject', op: 'contains', value: '' }] })}><Plus size={13} />Add condition</button>
        {rule.conditions.length === 0 && <p className="dialog-hint">With no conditions, the rule applies to every message.</p>}
      </div>
      <div className="rule-section">
        <span className="rule-heading">Then</span>
        {rule.actions.map((action, index) => (
          <div className="rule-row" key={index}>
            <select aria-label="Action" value={action.type} onChange={(e) => setAction(index, newAction(e.target.value as Action['type'], folders, labels))}>
              {actionTypes.map((type) => <option key={type} value={type}>{actionNames[type]}</option>)}
            </select>
            {action.type === 'move' && (
              <select aria-label="Folder" value={action.folder} onChange={(e) => setAction(index, { ...action, folder: e.target.value })}>
                {!folders.some((f) => f.name === action.folder) && <option value={action.folder}>{action.folder || 'Choose a folder'}</option>}
                {folders.map((f) => <option key={f.name} value={f.name}>{f.name}</option>)}
              </select>
            )}
            {action.type === 'label' && (
              <select aria-label="Label" value={action.keyword} onChange={(e) => setAction(index, { ...action, keyword: e.target.value })}>
                {labels.map((l) => <option key={l.keyword} value={l.keyword}>{l.name}</option>)}
              </select>
            )}
            {action.type === 'forward' && <>
              <input aria-label="Forward to" type="email" placeholder="name@example.com" value={action.address} onChange={(e) => setAction(index, { ...action, address: e.target.value })} />
              <label className="inline-check"><input type="checkbox" checked={action.keep} onChange={(e) => setAction(index, { ...action, keep: e.target.checked })} />Keep a copy</label>
            </>}
            <button type="button" className="icon" aria-label="Remove action" title="Remove action" onClick={() => onChange({ ...rule, actions: rule.actions.filter((_, i) => i !== index) })}><X size={14} /></button>
          </div>
        ))}
        <button type="button" className="link add-link" onClick={() => onChange({ ...rule, actions: [...rule.actions, newAction('mark_read', folders, labels)] })}><Plus size={13} />Add action</button>
      </div>
      <label className="inline-check"><input type="checkbox" checked={rule.stop} onChange={(e) => onChange({ ...rule, stop: e.target.checked })} />Don’t apply later rules to matching messages</label>
      <div className="rule-buttons">
        <button type="button" className="secondary small-button danger-quiet" onClick={onDelete}><Trash2 size={13} />Delete rule</button>
        <button type="button" className="secondary small-button" onClick={onDone}>Done</button>
      </div>
    </div>
  );
}

export function FiltersDialog({ api, folders, labels, onClose }: { api: Api; folders: Folder[]; labels: Label[]; onClose: () => void }) {
  const [filters, setFilters] = useState<Filters | null>(null);
  const [rules, setRules] = useState<Rule[]>([]);
  const [editing, setEditing] = useState<number | null>(null);
  const [script, setScript] = useState('');
  const [replacing, setReplacing] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const own = folders.filter((f) => !f.owner && f.name !== 'INBOX');

  const loaded = (next: Filters) => {
    setFilters(next);
    setRules(next.rules);
    setScript(next.script ?? '');
  };
  useEffect(() => { api<Filters>('/api/filters').then(loaded).catch((err) => setError((err as Error).message)); }, [api]);

  const update = (index: number, rule: Rule) => setRules(rules.map((r, i) => (i === index ? rule : r)));
  const move = (index: number, by: number) => {
    const next = [...rules];
    const [rule] = next.splice(index, 1);
    next.splice(index + by, 0, rule);
    setRules(next);
    setEditing(editing === index ? index + by : editing);
  };

  async function saveRules() {
    setBusy(true);
    setError('');
    try {
      loaded(await api<Filters>('/api/filters', { method: 'PUT', body: JSON.stringify({ rules, replace_script: replacing }) }));
      setEditing(null);
      setReplacing(false);
      onClose();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function saveScript() {
    setBusy(true);
    setError('');
    try {
      loaded(await api<Filters>('/api/filters/script', { method: 'PUT', body: JSON.stringify({ script }) }));
      onClose();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : (err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const showScript = filters?.mode === 'script' && !replacing;
  return (
    <div className="dialog-scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()} onKeyDown={(e) => e.key === 'Escape' && onClose()}>
      <section className="dialog filters-dialog" role="dialog" aria-modal="true" aria-label="Filters">
        <header><h2>Filters</h2><button type="button" className="icon" aria-label="Close" title="Close" autoFocus onClick={onClose}><X size={16} /></button></header>
        {filters === null && !error && <p className="muted">Loading…</p>}
        {showScript && <>
          <p className="dialog-intro">Your filters are a Sieve script{filters.script_name ? <> named <strong>{filters.script_name}</strong></> : null}, probably set up in another mail app. Edit it here, or replace it with rules (the script is kept, switched off).</p>
          <textarea className="script-editor" aria-label="Sieve script" spellCheck={false} value={script} onChange={(e) => setScript(e.target.value)} />
          {error && <p className="error">{error}</p>}
          <footer>
            <button type="button" className="secondary" onClick={() => { setReplacing(true); setRules([]); setError(''); }}>Replace with rules</button>
            <span className="spacer" />
            <button type="button" className="secondary" onClick={onClose}>Cancel</button>
            <button type="button" className="primary" disabled={busy} onClick={saveScript}>{busy ? 'Saving…' : 'Save script'}</button>
          </footer>
        </>}
        {filters && !showScript && <>
          <p className="dialog-intro">Rules run on the server as mail arrives, top to bottom, so they work in every mail app.</p>
          {replacing && <p className="dialog-hint">Saving replaces your Sieve script with these rules. The script is kept, switched off.</p>}
          {rules.length === 0 && <p className="muted">No rules yet.</p>}
          <ol className="rule-list">
            {rules.map((rule, index) => (
              <li key={index} className={rule.enabled ? '' : 'disabled'}>
                {editing === index ? (
                  <RuleEditor rule={rule} folders={own} labels={labels} onChange={(r) => update(index, r)} onDone={() => setEditing(null)}
                    onDelete={() => { setRules(rules.filter((_, i) => i !== index)); setEditing(null); }} />
                ) : (
                  <div className="rule-summary">
                    <input type="checkbox" aria-label={`Rule ${rule.name || index + 1} on`} checked={rule.enabled} onChange={(e) => update(index, { ...rule, enabled: e.target.checked })} />
                    <button type="button" className="rule-text" onClick={() => setEditing(index)}>
                      <strong>{rule.name || `Rule ${index + 1}`}</strong>
                      <span className="muted small">{describe(rule, labels)}</span>
                    </button>
                    <button type="button" className="icon" aria-label="Move up" title="Move up" disabled={index === 0} onClick={() => move(index, -1)}><ArrowUp size={14} /></button>
                    <button type="button" className="icon" aria-label="Move down" title="Move down" disabled={index === rules.length - 1} onClick={() => move(index, 1)}><ArrowDown size={14} /></button>
                  </div>
                )}
              </li>
            ))}
          </ol>
          <div><button type="button" className="secondary small-button" onClick={() => { setRules([...rules, newRule()]); setEditing(rules.length); }}><Plus size={13} />New rule</button></div>
          {error && <p className="error">{error}</p>}
          <footer>
            {replacing && <button type="button" className="secondary" onClick={() => { setReplacing(false); loaded(filters); }}>Back to the script</button>}
            <span className="spacer" />
            <button type="button" className="secondary" onClick={onClose}>Cancel</button>
            <button type="button" className="primary" disabled={busy} onClick={saveRules}>{busy ? 'Saving…' : 'Save'}</button>
          </footer>
        </>}
        {filters === null && error && <p className="error">{error}</p>}
      </section>
    </div>
  );
}

export { Filter as FilterIcon, Plane as VacationIcon };
