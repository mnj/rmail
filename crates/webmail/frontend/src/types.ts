// Shapes returned by the webmail API, and small helpers shared by the views.

/** `owner` and `rights` (RFC 4314 letters) are set on folders other accounts share with the user. */
export type Folder = { name: string; special_use: string | null; messages: number; unread: number; owner?: string; rights?: string };
export type Grant = { address: string; rights: string; access: 'read' | 'edit' | null };
/** One of the user's calendars or address books, with whom it is shared. */
export type DavCollection = { kind: 'calendar' | 'addressbook'; name: string; displayname: string; grants: { address: string; access: 'read' | 'edit' }[] };
export type CalendarListing = {
  own: DavCollection[];
  shared: { kind: 'calendar' | 'addressbook'; owner: string; displayname: string; access: 'read' | 'edit' }[];
};
export type Suggestion = { folder: string; score: number; method: 'sender' | 'knn' | 'llm' };
export type Label = { name: string; keyword: string; description: string; origin?: 'user' | 'starter' | 'ai' };
export type Message = {
  uid: number; flags: string[]; size: number; internal_date: number;
  from: string; to: string; subject: string; snippet: string;
  has_attachments: boolean; suggestion?: Suggestion; labels?: Label[];
};
export type MessagePage = { total: number; messages: Message[] };
export type Attachment = { index: number; filename: string; content_type: string; size: number; inline: boolean };
export type MessageDetail = {
  uid: number; flags: string[]; size: number; internal_date: number;
  from: string; to: string; cc: string; bcc: string; reply_to: string; message_id: string;
  in_reply_to: string; references: string;
  subject: string; date: string; text_body: string; html_body: string | null;
  has_remote_content: boolean; attachments: Attachment[]; labels: Label[];
};
export type OrganizeFolder = { name: string; learned: number; accepted: number; dismissed: number; excluded: boolean; autofile: boolean };
export type OrganizeLabel = Label & { count: number; origin: 'user' | 'starter' | 'ai' };
export type Organize = {
  server_enabled: boolean; enabled: boolean; pending: number; folders: OrganizeFolder[];
  cloud_providers: string[]; cloud_consent: boolean; cloud_required: boolean;
  labels_enabled: boolean; labels_available: boolean; labels_cloud: boolean; labels: OrganizeLabel[];
  folder_ideas: { label: string; count: number }[];
  ai_labels: boolean; ai_summary: boolean;
};
export type LabelGuess = { name: string; keyword: string | null; probability: number; applied: boolean };
export type LabelPreview = { labels: LabelGuess[]; threshold: number; proposed: { name: string; description: string } | null; model: string | null };

export type Api = <T>(url: string, options?: RequestInit) => Promise<T>;

export class ApiError extends Error {
  constructor(message: string, public status: number) {
    super(message);
  }
}

export const methodLabel: Record<Suggestion['method'], string> = {
  sender: 'where you file mail from this sender',
  knn: 'similar messages you filed',
  llm: 'an AI model',
};

const providerNames: Record<string, string> = {
  openrouter: 'OpenRouter (openrouter.ai)',
  typesafe: 'TypeSafe (typesafe.ai)',
};

export function providerName(id: string): string {
  return providerNames[id] || id;
}

export function listNames(ids: string[]): string {
  const names = ids.map(providerName);
  return names.length > 1 ? `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}` : names[0] || '';
}

export const hasFlag = (flags: string[], flag: string) => flags.some((f) => f.toLowerCase() === flag.toLowerCase());

/** "Jonas Berg <jonas@x>" -> { name: "Jonas Berg", address: "jonas@x" }. */
export function splitAddress(value: string): { name: string; address: string } {
  const match = /^\s*"?([^"<]*?)"?\s*<([^>]+)>\s*$/.exec(value);
  if (match) return { name: match[1].trim() || match[2], address: match[2] };
  return { name: value.trim(), address: value.trim() };
}

export function formatSize(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  if (bytes >= 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${bytes} B`;
}

/** Time today, weekday this week, otherwise a date. */
export function formatListDate(epochSeconds: number): string {
  const date = new Date(epochSeconds * 1000);
  const now = new Date();
  if (date.toDateString() === now.toDateString()) return date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  const days = (now.getTime() - date.getTime()) / 86400000;
  if (days < 6) return date.toLocaleDateString(undefined, { weekday: 'short' });
  return date.toLocaleDateString(undefined, date.getFullYear() === now.getFullYear() ? { day: 'numeric', month: 'short' } : { day: 'numeric', month: 'short', year: 'numeric' });
}

export function formatFullDate(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

const specialOrder: Record<string, number> = { '\\Drafts': 1, '\\Sent': 2, '\\Archive': 3, '\\Junk': 4, '\\Trash': 5 };

/** INBOX first, then special-use folders in a fixed order, then the user's folders alphabetically. */
export function sortFolders(folders: Folder[]): Folder[] {
  const rank = (f: Folder) => (f.owner ? 8 : f.name === 'INBOX' ? 0 : f.special_use ? specialOrder[f.special_use] ?? 6 : 7);
  return [...folders].sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name));
}

export const isUserFolder = (f: Folder) => f.name !== 'INBOX' && !f.special_use && !f.owner;

/** Whether the user holds an RFC 4314 right in a folder; always in their own. */
export const can = (f: Folder | undefined, right: string) => !f?.rights || f.rights.includes(right);

/** A shared folder's name without the `Other Users/<owner>/` prefix. */
export const sharedFolderName = (f: Folder) => (f.owner ? f.name.slice(`Other Users/${f.owner}/`.length) : f.name);
