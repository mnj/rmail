// Thin fetch wrapper for the admin API.
//
// Every request carries X-Rmail-Admin: the server rejects state-changing
// requests without it (CSRF protection) and omits the Basic-auth challenge
// for requests that have it, so the browser never shows its native dialog.

export class ApiError extends Error {
  constructor(message: string, public status: number) {
    super(message);
  }
}

let unauthorizedHandler: () => void = () => undefined;

export function onUnauthorized(handler: () => void) {
  unauthorizedHandler = handler;
}

type Method = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

async function send(url: string, method: Method, body?: unknown): Promise<Response> {
  const headers: Record<string, string> = { 'X-Rmail-Admin': '1' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(url, {
    method,
    credentials: 'same-origin',
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    let message = text || `${res.status} ${res.statusText}`;
    try {
      const parsed = JSON.parse(text);
      if (parsed && typeof parsed.error === 'string') message = parsed.error;
    } catch {
      // plain-text error body
    }
    if (res.status === 401 && !url.startsWith('/api/login') && !url.startsWith('/api/session')) unauthorizedHandler();
    throw new ApiError(message, res.status);
  }
  return res;
}

export async function api<T>(url: string, method: Method = 'GET', body?: unknown): Promise<T> {
  const res = await send(url, method, body);
  const text = await res.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

export async function apiText(url: string): Promise<string> {
  return (await send(url, 'GET')).text();
}

export function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// ---------------------------------------------------------------------------
// Types returned by the server

export type Session = { authenticated: boolean; user: string | null; setup_required: boolean; settings_managed: boolean };
export type Stats = { mailboxes: number; total_messages: number; delivered_count: number; outbound_pending: number };
export type Account = { address: string; auth: string; folders: number; messages: number; unseen: number; used_bytes: number; quota_bytes: number | null };
export type QueueSummary = { queued: number; inflight: number; sent: number; failed: number };
export type Overview = {
  accounts: number;
  folders: number;
  total_messages: number;
  unseen_messages: number;
  aliases: number;
  catchalls: number;
  domains: { domain: string; accounts: number; messages: number; unseen: number }[];
  top_mailboxes: { address: string; messages: number; unseen: number; folders: number }[];
  queue: QueueSummary;
};
export type QueueControl = { attempts?: number; max_attempts?: number; priority?: number; next_try?: number | null; last_error?: string | null };
export type QueueItem = { name: string; control?: QueueControl | null };
export type Spool = 'queue' | 'inflight' | 'failed' | 'sent';
export type DmarcRow = { domain: string; events: number };
export type Routing = { aliases: { address: string; targets: string[] }[]; catchalls: { domain: string; target: string }[] };
export type ReadinessCheck = { status: 'ok' | 'error' | 'skipped'; error?: string };
export type Readiness = { ready: boolean; checks: Record<string, ReadinessCheck> };

export type SettingKind =
  | { type: 'bool' }
  | { type: 'integer'; min: number; max: number }
  | { type: 'text' }
  | { type: 'secret' }
  | { type: 'list' }
  | { type: 'address_list' }
  | { type: 'choice'; options: string[] }
  | { type: 'multi_choice'; options: string[] };

export type Setting = {
  key: string;
  group: string;
  label: string;
  help: string;
  kind: SettingKind;
  services: string[];
  value: unknown;
  default: unknown;
  is_set: boolean;
};

export type ServiceState = {
  service: string;
  pid: number;
  host: string | null;
  started_at: number;
  settings_revision: number;
  restart_required: boolean;
  pending_changes: string[];
};

export type SettingsView =
  | { managed: false }
  | {
      managed: true;
      revision: number;
      imported_from: string | null;
      groups: { id: string; label: string; description: string }[];
      settings: Setting[];
      other: { key: string; value: unknown }[];
      services: ServiceState[];
    };

export async function readiness(): Promise<Readiness> {
  // /readyz answers 503 with a full report when a dependency is down.
  const res = await fetch('/readyz', { credentials: 'same-origin' });
  const report = (await res.json()) as Readiness;
  if (!report.checks) throw new Error('/readyz returned an invalid readiness report');
  return report;
}
