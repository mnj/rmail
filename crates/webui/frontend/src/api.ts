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

export type PasswordPolicy = {
  min_length: number;
  max_length: number;
  require_lowercase: boolean;
  require_uppercase: boolean;
  require_digit: boolean;
  require_symbol: boolean;
  forbid_username: boolean;
};
export type Session = { authenticated: boolean; user: string | null; setup_required: boolean; settings_managed: boolean; password_policy?: PasswordPolicy };
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
  used_bytes: number;
  near_quota: { address: string; used_bytes: number; quota_bytes: number }[];
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
      restart_available?: boolean;
    };

export type CertificateInfo = { subject: string; names: string[]; issuer: string; not_before: number; not_after: number; serial: string; self_signed: boolean };
export type AcmeRun = { trigger: string; dry_run: boolean; started_at: number; finished_at: number | null; ok: boolean | null; error: string | null; names: string[]; log: { at: number; message: string }[] };
export type Certificates = {
  managed: boolean;
  enabled: boolean;
  names: string[];
  names_error: string | null;
  challenge: 'http-01' | 'dns-01';
  directory: string | null;
  cert_path: string;
  key_path: string;
  certificate: CertificateInfo | null;
  certificate_error: string | null;
  renewal: { due: boolean; reason: string; due_at: number | null } | null;
  running: boolean;
  status: {
    last_run: AcmeRun | null;
    last_success_at: number | null;
    issued_by: string | null;
    consecutive_failures: number;
    retry_after: number | null;
    renewal_window: [number, number] | null;
  };
  http_listeners: string[];
  warnings: string[];
};

export type ModelKind = 'embedding' | 'chat';
export type CatalogModel = { id: string; name: string; kind: ModelKind; file: string; url: string; sha256: string | null; size_mb: number; ram_mb: number; license: string; prefix: string; notes: string };
export type InstalledModel = { file: string; size: number; meta: { kind: ModelKind; url: string; sha256: string; size: number; downloaded_at: number } | null };
export type ModelDownload = { file: string; received: number; total: number; status: { state: 'running' } | { state: 'done'; sha256: string } | { state: 'failed'; error: string } };
export type LoadedModel = { file: string; load_ms: number; cloud: string | null };
export type EmbedProvider = 'local' | 'openrouter';
export type ChatProvider = 'local' | 'openrouter' | 'jev';
export type ClassifierStatus = {
  enabled: boolean;
  local_models: boolean;
  embed_model: LoadedModel | null;
  chat_model: LoadedModel | null;
  errors: string[];
  accounts: { opted_in?: number; opted_out?: number; cloud_consented?: number };
  cloud_providers?: string[];
  loaded_at: number;
  last_cycle: { finished_at: number; duration_ms: number; report: { accounts: number; learned: number; classified: number; suggested: number; moved: number; labeled?: number; awaiting_consent?: number; errors: string[] } } | null;
};
export type Organization = {
  managed: boolean;
  models_dir: string;
  catalog: CatalogModel[];
  installed: InstalledModel[];
  downloads: ModelDownload[];
  settings: Record<string, unknown>;
  daemon: { running: true; status: ClassifierStatus } | { running: false; error: string };
};

export async function readiness(): Promise<Readiness> {
  // /readyz answers 503 with a full report when a dependency is down.
  const res = await fetch('/readyz', { credentials: 'same-origin' });
  const report = (await res.json()) as Readiness;
  if (!report.checks) throw new Error('/readyz returned an invalid readiness report');
  return report;
}
