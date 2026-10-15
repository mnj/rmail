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
export type Session = { authenticated: boolean; user: string | null; setup_required: boolean; password_policy?: PasswordPolicy };
export type Stats = { mailboxes: number; total_messages: number; delivered_count: number; outbound_pending: number };
export type Account = { address: string; auth: string; folders: number; messages: number; unseen: number; used_bytes: number; quota_bytes: number | null };
/** A folder one account shares with another (IMAP ACL); rights are RFC 4314 letters. */
export type FolderShare = { owner: string; folder: string; mailbox_id: string; grantee: string; rights: string };
export type DavShare = { owner: string; kind: 'calendar' | 'addressbook'; name: string; collection_id: number; grantee: string; access: 'read' | 'read-write' };
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
export type FeedbackReport = {
  id: number;
  received_at: number;
  recipient: string;
  reporter: string | null;
  feedback_type: string;
  user_agent: string | null;
  incidents: number;
  source_ip: string | null;
  arrival_date: string | null;
  original_mail_from: string | null;
  original_rcpt_to: string | null;
  reported_domain: string | null;
  auth_failure: string | null;
  original_from: string | null;
  original_subject: string | null;
  original_message_id: string | null;
  account: string | null;
  domain: string | null;
  attributed_by: string | null;
  authenticated: boolean;
};
export type FeedbackSender = { sender: string; complaints: number; unverified: number; last_received_at: number };
export type FeedbackOverview = { addresses: string[]; threshold: number; days: number; senders: FeedbackSender[]; reports: FeedbackReport[] };
export type DnsRecord = { name: string; type: string; value: string; purpose: string };
export type DkimKey = { domain: string; selector: string; algorithm: 'rsa' | 'ed25519'; arc: boolean; created_at: number; dns_record: string };
export type Discovery = { hostname: string; domains: { domain: string; records: DnsRecord[]; dkim: DkimKey[] }[] };
export type DnsStatus = 'ok' | 'improve' | 'missing' | 'different' | 'problem' | 'unknown';
export type Need = 'required' | 'recommended' | 'optional';
/** The live verdict on one suggested record; name, type and value match its DnsRecord. */
export type DnsCheck = { name: string; type: string; value: string; need: Need; status: DnsStatus; published: string[]; detail: string | null };
export type SetupStep = { id: string; need: Need; title: string; why: string; state: 'done' | 'todo' | 'unknown'; detail: string | null; page: 'domains' | 'settings' | 'certificates' | 'routing' | 'delivery' | null };
/** Whether other mail servers answer on port 25 over one address family. */
export type Reach = { state: 'open'; target: string } | { state: 'blocked'; error: string } | { state: 'unavailable' } | { state: 'unknown'; error: string };
export type BlocklistResult = { zone: string; name: string; status: 'clean' | 'listed' | 'unknown'; code: string | null; detail: string | null };
/** An address the server sends from: reported by the probed server, read from the interface, or taken from the host's DNS record. */
export type OutboundAddress = { address: string; source: 'seen' | 'local' | 'dns'; reverse: { status: DnsStatus; names: string[]; detail: string | null }; blocklists: BlocklistResult[] };
export type Deliverability = { port25: { v4: Reach; v6: Reach }; addresses: OutboundAddress[] };
/** Totals of the DMARC aggregate reports other mail systems sent about a domain. */
export type DmarcReportSummary = { domain: string; reports: number; reporters: string[]; messages: number; passed: number; begin: number; end: number; failing: { source_ip: string; messages: number; dkim: string; spf: string }[] };
/** A DNS host whose control panel has quirks the console can warn about. */
export type DnsProvider = 'cloudflare' | 'route53';
/** How a signed test message from a domain fared when verified like inbound mail. */
export type AuthTest = { domain: string; address: string | null; checks: { name: string; result: string; ok: boolean; detail: string }[] };
/** Something the server noticed that the admin may want to act on. */
export type Recommendation = { id: string; title: string; detail: string; page: 'domains' | 'settings' | 'certificates' | 'routing' | 'delivery' };
export type DnsChecks = {
  checked_at: number;
  hostname: string;
  addresses: string[];
  server: SetupStep[];
  domains: { domain: string; records: DnsCheck[]; steps: SetupStep[]; dmarc_reports: DmarcReportSummary | null; provider: DnsProvider | null }[];
  /** Null when a smarthost sends the mail, so the server's own address does not matter. */
  outbound: Deliverability | null;
  recommendations: Recommendation[];
};
/** Required records that are published wrongly or not at all. */
export function failingRequired(records: DnsCheck[]): DnsCheck[] {
  return records.filter((record) => record.need === 'required' && ['missing', 'different', 'problem'].includes(record.status));
}
export type Route =
  | { domain: string; action: 'relay'; host: string; port: number; implicit_tls: boolean; username: string | null; has_password: boolean }
  | { domain: string; action: 'reject'; reply: string; has_password: boolean };
export type Routing = { aliases: { address: string; targets: string[] }[]; catchalls: { domain: string; target: string }[]; routes: Route[] };
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
  /** Whether the feature is worth turning on for most servers, or is clearly optional. */
  advice: { level: 'recommended' | 'optional'; why: string } | null;
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

export type SettingsView = {
      revision: number;
      groups: { id: string; label: string; description: string }[];
      settings: Setting[];
      services: ServiceState[];
      restart_available?: boolean;
    };

export type CertificateInfo = { subject: string; names: string[]; issuer: string; not_before: number; not_after: number; serial: string; self_signed: boolean };
export type AcmeRun = { trigger: string; dry_run: boolean; started_at: number; finished_at: number | null; ok: boolean | null; error: string | null; names: string[]; log: { at: number; message: string }[] };
export type Certificates = {
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
export type EmbedProvider = 'local' | 'openrouter' | 'openai';
export type ChatProvider = 'local' | 'openrouter' | 'openai' | 'anthropic' | 'jev';
export type BackgroundTier = 'standard' | 'flex';
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
