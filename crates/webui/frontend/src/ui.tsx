import React, { createContext, useCallback, useContext, useEffect, useId, useRef, useState } from 'react';
import { AlertTriangle, CheckCircle2, Info, X } from 'lucide-react';
import { errorMessage } from './api';

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

// ---------------------------------------------------------------------------
// Data loading

export function useResource<T>(load: () => Promise<T>, deps: React.DependencyList, refreshMs?: number) {
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
  }, deps);

  return { data, error, loading, reload, setData };
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

  return (
    <FeedbackContext.Provider value={{ notify, confirm, run }}>
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
          <button className={`button ${pending.danger ? 'dangerSolid' : 'primary'}`} autoFocus onClick={() => close(true)}>{pending.confirmLabel || 'Confirm'}</button>
        </>}>
          <div className="confirmBody">{pending.message}</div>
        </Modal>
      )}
    </FeedbackContext.Provider>
  );
}

// ---------------------------------------------------------------------------
// Primitives

export function Modal({ title, children, footer, onClose, wide }: { title: string; children: React.ReactNode; footer?: React.ReactNode; onClose: () => void; wide?: boolean }) {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => event.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);
  return (
    <div className="modalScrim" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <div className={`modal ${wide ? 'wide' : ''}`} role="dialog" aria-modal="true" aria-label={title}>
        <div className="modalHead"><h2>{title}</h2><button className="iconButton" aria-label="Close" onClick={onClose}><X size={16} /></button></div>
        <div className="modalBody">{children}</div>
        {footer && <div className="modalFoot">{footer}</div>}
      </div>
    </div>
  );
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

export function ErrorBanner({ error }: { error: string }) {
  return error ? <div className="banner"><AlertTriangle size={16} /> {error}</div> : null;
}

export function generatePassword(length = 20): string {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_';
  const bytes = new Uint32Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (value) => alphabet[value % alphabet.length]).join('');
}
