import React, { createContext, useCallback, useContext, useEffect, useId, useMemo, useRef, useState } from 'react';
import { AlertTriangle, ArrowDown, ArrowUp, ArrowUpDown, Check, CheckCircle2, Circle, Info, X } from 'lucide-react';
import { errorMessage, PasswordPolicy } from './api';

// ---------------------------------------------------------------------------
// Formatting

export const numberFmt = new Intl.NumberFormat();

export function formatBytes(value: number): string {
  if (value >= 1024 ** 3) return `${(value / 1024 ** 3).toFixed(1)} GiB`;
  if (value >= 1024 ** 2) return `${(value / 1024 ** 2).toFixed(1)} MiB`;
  return `${Math.ceil(value / 1024)} KiB`;
}

export function formatRelative(epochSeconds: number | null | undefined): string {
  if (!epochSeconds) return '—';
  const delta = epochSeconds - Date.now() / 1000;
  const abs = Math.abs(delta);
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
  if (abs < 60) return rtf.format(Math.round(delta), 'second');
  if (abs < 3600) return rtf.format(Math.round(delta / 60), 'minute');
  if (abs < 86400) return rtf.format(Math.round(delta / 3600), 'hour');
  return rtf.format(Math.round(delta / 86400), 'day');
}

export function formatDate(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toLocaleString();
}

export function plural(count: number, word: string, many = `${word}s`): string {
  return `${numberFmt.format(count)} ${count === 1 ? word : many}`;
}

// ---------------------------------------------------------------------------
// Data loading

// Resources subscribe to a topic; invalidate(topic) reloads every mounted
// subscriber, so a change on one page refreshes what other parts show.
const topics = new Map<string, Set<() => void>>();

export function invalidate(topic: string) {
  topics.get(topic)?.forEach((reload) => reload());
}

export function useResource<T>(load: () => Promise<T>, deps: React.DependencyList, refreshMs?: number, topic?: string) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const loadRef = useRef(load);
  loadRef.current = load;

  const reload = useCallback(async () => {
    setLoading(true);
    try {
      setData(await loadRef.current());
      setError('');
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    reload();
    if (!refreshMs) return;
    const id = window.setInterval(() => {
      if (document.visibilityState === 'visible') reload();
    }, refreshMs);
    return () => window.clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, refreshMs]);

  useEffect(() => {
    if (!topic) return;
    const set = topics.get(topic) ?? new Set();
    topics.set(topic, set);
    set.add(reload);
    return () => { set.delete(reload); };
  }, [topic, reload]);

  return { data, error, loading, reload, setData };
}

// ---------------------------------------------------------------------------
// Unsaved changes

// One guard at a time: the page with unsaved edits. The console asks it
// before switching pages; the browser asks before unloading.
let leaveGuard: (() => Promise<boolean>) | null = null;

export function confirmLeave(): Promise<boolean> {
  return leaveGuard ? leaveGuard() : Promise.resolve(true);
}

export function useUnsavedChanges(count: number) {
  const { confirm } = useFeedback();
  useEffect(() => {
    if (count === 0) return;
    const guard = () => confirm({
      title: 'Discard unsaved changes?',
      message: `You have ${plural(count, 'unsaved change')} on this page. Leaving discards ${count === 1 ? 'it' : 'them'}.`,
      confirmLabel: 'Discard and leave',
      danger: true,
    });
    const onBeforeUnload = (event: BeforeUnloadEvent) => event.preventDefault();
    leaveGuard = guard;
    window.addEventListener('beforeunload', onBeforeUnload);
    return () => {
      if (leaveGuard === guard) leaveGuard = null;
      window.removeEventListener('beforeunload', onBeforeUnload);
    };
  }, [count, confirm]);
}

// ---------------------------------------------------------------------------
// Sorting

export type Sort<K extends string> = { key: K; dir: 'asc' | 'desc' };

export function useSort<T, K extends string>(rows: T[], initial: Sort<K>, value: (row: T, key: K) => string | number) {
  const [sort, setSort] = useState(initial);
  const sorted = useMemo(() => {
    const factor = sort.dir === 'asc' ? 1 : -1;
    return [...rows].sort((a, b) => {
      const x = value(a, sort.key);
      const y = value(b, sort.key);
      return factor * (typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y)));
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows, sort]);
  // Numbers read best largest-first; text alphabetically.
  const toggle = (key: K, numeric = false) => setSort((current) => current.key === key
    ? { key, dir: current.dir === 'asc' ? 'desc' : 'asc' }
    : { key, dir: numeric ? 'desc' : 'asc' });
  return { sorted, sort, toggle };
}

export function SortHeader<K extends string>({ label, column, sort, onSort, numeric }: { label: string; column: K; sort: Sort<K>; onSort: (key: K, numeric?: boolean) => void; numeric?: boolean }) {
  const active = sort.key === column;
  const Icon = !active ? ArrowUpDown : sort.dir === 'asc' ? ArrowUp : ArrowDown;
  return (
    <th className={numeric ? 'num' : undefined} aria-sort={active ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <button type="button" className="sortButton" data-active={active} onClick={() => onSort(column, numeric)}>{label}<Icon size={12} /></button>
    </th>
  );
}

// ---------------------------------------------------------------------------
// Toasts and confirmation dialogs

type Toast = { id: number; kind: 'success' | 'error' | 'info'; message: string };
type ConfirmOptions = { title: string; message: React.ReactNode; confirmLabel?: string; danger?: boolean };

type FeedbackApi = {
  notify: (kind: Toast['kind'], message: string) => void;
  confirm: (options: ConfirmOptions) => Promise<boolean>;
  /** Run an action, reporting success or failure as a toast. */
  run: (action: () => Promise<unknown>, success?: string) => Promise<boolean>;
};

const FeedbackContext = createContext<FeedbackApi | null>(null);

export function useFeedback(): FeedbackApi {
  const value = useContext(FeedbackContext);
  if (!value) throw new Error('FeedbackProvider missing');
  return value;
}

export function FeedbackProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [pending, setPending] = useState<(ConfirmOptions & { resolve: (ok: boolean) => void }) | null>(null);
  const nextId = useRef(1);

  const notify = useCallback((kind: Toast['kind'], message: string) => {
    const id = nextId.current++;
    setToasts((list) => [...list.slice(-3), { id, kind, message }]);
    window.setTimeout(() => setToasts((list) => list.filter((toast) => toast.id !== id)), kind === 'error' ? 8000 : 4000);
  }, []);

  const confirm = useCallback((options: ConfirmOptions) => new Promise<boolean>((resolve) => setPending({ ...options, resolve })), []);

  const run = useCallback(async (action: () => Promise<unknown>, success?: string) => {
    try {
      await action();
      if (success) notify('success', success);
      return true;
    } catch (err) {
      notify('error', errorMessage(err));
      return false;
    }
  }, [notify]);

  const close = (ok: boolean) => {
    pending?.resolve(ok);
    setPending(null);
  };

  const api = useMemo(() => ({ notify, confirm, run }), [notify, confirm, run]);

  return (
    <FeedbackContext.Provider value={api}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {toasts.map((toast) => {
          const Icon = toast.kind === 'success' ? CheckCircle2 : toast.kind === 'error' ? AlertTriangle : Info;
          return (
            <div key={toast.id} className={`toast ${toast.kind}`}>
              <Icon size={18} />
              <span>{toast.message}</span>
              <button className="toastClose" aria-label="Dismiss" onClick={() => setToasts((list) => list.filter((item) => item.id !== toast.id))}><X size={14} /></button>
            </div>
          );
        })}
      </div>
      {pending && (
        <Modal title={pending.title} onClose={() => close(false)} footer={<>
          <button className="button" onClick={() => close(false)}>Cancel</button>
          <button className={`button ${pending.danger ? 'dangerSolid' : 'primary'}`} data-autofocus onClick={() => close(true)}>{pending.confirmLabel || 'Confirm'}</button>
        </>}>
          <div className="confirmBody">{pending.message}</div>
        </Modal>
      )}
    </FeedbackContext.Provider>
  );
}

// ---------------------------------------------------------------------------
// Primitives

const focusable = 'a[href], button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex="-1"])';

/** Dialog that keeps keyboard focus inside while open and returns it to the opener on close. */
export function Modal({ title, children, footer, onClose, wide }: { title: string; children: React.ReactNode; footer?: React.ReactNode; onClose: () => void; wide?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;
  // Captured during the first render: autoFocus in the children moves focus before effects run.
  const [opener] = useState(() => document.activeElement as HTMLElement | null);

  useEffect(() => {
    const dialog = ref.current;
    if (dialog && !dialog.contains(document.activeElement)) {
      const first = dialog.querySelector<HTMLElement>('[data-autofocus], [autofocus]') ?? dialog.querySelector<HTMLElement>(`.modalBody ${focusable}`) ?? dialog;
      first.focus();
    }
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.stopPropagation();
        onCloseRef.current();
      } else if (event.key === 'Tab' && dialog) {
        const items = Array.from(dialog.querySelectorAll<HTMLElement>(focusable));
        if (!items.length) return;
        const first = items[0];
        const last = items[items.length - 1];
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
      }
    };
    dialog?.addEventListener('keydown', onKey);
    return () => {
      dialog?.removeEventListener('keydown', onKey);
      if (opener && document.contains(opener)) opener.focus();
    };
  }, [opener]);

  return (
    <div className="modalScrim" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <div ref={ref} tabIndex={-1} className={`modal ${wide ? 'wide' : ''}`} role="dialog" aria-modal="true" aria-labelledby={titleId}>
        <div className="modalHead"><h2 id={titleId}>{title}</h2><IconButton label="Close" onClick={onClose}><X size={16} /></IconButton></div>
        <div className="modalBody">{children}</div>
        {footer && <div className="modalFoot">{footer}</div>}
      </div>
    </div>
  );
}

/** Icon-only button. The label is both the accessible name and the tooltip. */
export function IconButton({ label, children, danger, className, ...props }: { label: string; danger?: boolean } & Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, 'aria-label' | 'title'>) {
  return <button type="button" {...props} className={`iconButton ${danger ? 'danger' : ''} ${className || ''}`} aria-label={label} title={label}>{children}</button>;
}

export function Toggle({ checked, onChange, label, disabled }: { checked: boolean; onChange: (value: boolean) => void; label: string; disabled?: boolean }) {
  return (
    <button type="button" role="switch" aria-checked={checked} aria-label={label} disabled={disabled} className={`toggle ${checked ? 'on' : ''}`} onClick={() => onChange(!checked)}>
      <i />
    </button>
  );
}

/** Labelled form control. The label names the control; the hint describes it. */
export function Field({ label, hint, children }: { label: string; hint?: React.ReactNode; children: React.ReactElement<{ id?: string; 'aria-describedby'?: string }> }) {
  const id = useId();
  // Composite controls (an input plus buttons) label themselves.
  const composite = children.type === 'div';
  return (
    <div className="field">
      <label className="fieldLabel" htmlFor={composite ? undefined : id}>{label}</label>
      {composite ? children : React.cloneElement(children, { id, 'aria-describedby': hint ? `${id}-hint` : undefined })}
      {hint && <small className="fieldHint" id={`${id}-hint`}>{hint}</small>}
    </div>
  );
}

export function Panel({ title, subtitle, actions, children, className }: { title: string; subtitle?: React.ReactNode; actions?: React.ReactNode; children: React.ReactNode; className?: string }) {
  return (
    <article className={`panel ${className || ''}`}>
      <div className="panelHead">
        <div><h2>{title}</h2>{subtitle && <small>{subtitle}</small>}</div>
        {actions && <div className="panelActions">{actions}</div>}
      </div>
      {children}
    </article>
  );
}

export function Empty({ children }: { children: React.ReactNode }) {
  return <div className="empty">{children}</div>;
}

/** Placeholder table rows while the first load is in flight. */
export function SkeletonRows({ rows = 4, cols }: { rows?: number; cols: number }) {
  return (
    <>
      {Array.from({ length: rows }, (_, row) => (
        <tr key={row} aria-hidden="true">
          {Array.from({ length: cols }, (_, col) => <td key={col}><span className="skeleton" style={{ width: col === 0 ? '70%' : '45%' }} /></td>)}
        </tr>
      ))}
    </>
  );
}

export function ErrorBanner({ error }: { error: string }) {
  return error ? <div className="banner" role="alert"><AlertTriangle size={16} /> {error}</div> : null;
}

export function generatePassword(length = 20): string {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_';
  const bytes = new Uint32Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (value) => alphabet[value % alphabet.length]).join('');
}

// ---------------------------------------------------------------------------
// Admin password policy (mirrors AdminPasswordPolicy::check on the server)

export const defaultPasswordPolicy: PasswordPolicy = {
  min_length: 10,
  max_length: 128,
  require_lowercase: false,
  require_uppercase: false,
  require_digit: false,
  require_symbol: false,
  forbid_username: true,
};

export function passwordRules(policy: PasswordPolicy, username: string, password: string): { label: string; met: boolean }[] {
  const chars = Array.from(password);
  const rules = [{ label: `${policy.min_length}–${policy.max_length} characters`, met: chars.length >= policy.min_length && chars.length <= policy.max_length }];
  if (policy.require_lowercase) rules.push({ label: 'A lowercase letter', met: chars.some((c) => c !== c.toUpperCase()) });
  if (policy.require_uppercase) rules.push({ label: 'An uppercase letter', met: chars.some((c) => c !== c.toLowerCase()) });
  if (policy.require_digit) rules.push({ label: 'A digit', met: /[0-9]/.test(password) });
  if (policy.require_symbol) rules.push({ label: 'A symbol', met: /[^\p{L}\p{N}\s]/u.test(password) });
  const name = username.trim().toLowerCase();
  if (policy.forbid_username && name) rules.push({ label: 'Does not contain the username', met: password !== '' && !password.toLowerCase().includes(name) });
  return rules;
}

export function PasswordRules({ rules }: { rules: { label: string; met: boolean }[] }) {
  return (
    <ul className="policyList" aria-label="Password requirements">
      {rules.map((rule) => (
        <li key={rule.label} className={rule.met ? 'met' : ''}>
          {rule.met ? <Check size={13} /> : <Circle size={11} />}
          {rule.label}<span className="visuallyHidden">{rule.met ? ' (met)' : ' (not met)'}</span>
        </li>
      ))}
    </ul>
  );
}
