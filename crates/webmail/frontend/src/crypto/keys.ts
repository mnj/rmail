// Where the user's keys live, and keys unlocked for this tab.
//
// - `browser`: in this browser's IndexedDB, per signed-in address.
// - `server`: on the server (`/api/crypto/keys`), locked the same way.
// Either way a stored key is locked with the user's passphrase (OpenPGP
// S2K, or a PKCS#12 password for S/MIME); unlocked keys stay in memory
// until the tab is closed or reloaded.

import { Api } from '../types';
import * as pgp from './pgp';
import * as smime from './smime';

export type KeyKind = 'pgp' | 'smime';
export type OwnKey = { id: string; kind: KeyKind; label: string; data: string; created: number };
export type PublicKeyEntry = { id: string; kind: KeyKind; address: string; label: string; data: string; created: number };
export type Storage = 'browser' | 'server';
export type CryptoState = { storage: Storage; keys: OwnKey[]; publicKeys: PublicKeyEntry[] };

const DB = 'rmail-crypto';

function idb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB, 1);
    request.onupgradeneeded = () => request.result.createObjectStore('keys', { keyPath: 'key' });
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function tx<T>(mode: IDBTransactionMode, work: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await idb();
  return new Promise((resolve, reject) => {
    const request = work(db.transaction('keys', mode).objectStore('keys'));
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function browserKeys(owner: string): Promise<OwnKey[]> {
  const all = await tx<{ key: string; owner: string; value: OwnKey }[]>('readonly', (store) => store.getAll() as IDBRequest<{ key: string; owner: string; value: OwnKey }[]>);
  return all.filter((row) => row.owner === owner).map((row) => row.value).sort((a, b) => a.created - b.created);
}

export async function load(api: Api, owner: string): Promise<CryptoState> {
  const remote = await api<{ storage: Storage | null; keys: OwnKey[]; public_keys: PublicKeyEntry[] }>('/api/crypto');
  const storage = remote.storage ?? 'browser';
  return {
    storage,
    keys: storage === 'server' ? remote.keys : await browserKeys(owner).catch(() => []),
    publicKeys: remote.public_keys,
  };
}

export async function saveKey(api: Api, owner: string, storage: Storage, key: OwnKey): Promise<void> {
  if (storage === 'server') {
    await api(`/api/crypto/keys/${encodeURIComponent(key.id)}`, { method: 'PUT', body: JSON.stringify(key) });
  } else {
    await tx('readwrite', (store) => store.put({ key: `${owner}\u0000${key.id}`, owner, value: key }));
  }
}

export async function removeKey(api: Api, owner: string, storage: Storage, id: string): Promise<void> {
  unlocked.delete(id);
  if (storage === 'server') await api(`/api/crypto/keys/${encodeURIComponent(id)}`, { method: 'DELETE' });
  else await tx('readwrite', (store) => store.delete(`${owner}\u0000${id}`));
}

/** Move the user's keys to the other place, then forget them where they were. */
export async function moveKeys(api: Api, owner: string, state: CryptoState, to: Storage): Promise<void> {
  if (to === state.storage) return;
  if (to === 'server') {
    await api('/api/crypto', { method: 'PUT', body: JSON.stringify({ storage: 'server' }) });
    for (const key of state.keys) await saveKey(api, owner, 'server', key);
    for (const key of state.keys) await tx('readwrite', (store) => store.delete(`${owner}\u0000${key.id}`));
  } else {
    for (const key of state.keys) await saveKey(api, owner, 'browser', key);
    // The server forgets its copies when storage becomes `browser`.
    await api('/api/crypto', { method: 'PUT', body: JSON.stringify({ storage: 'browser' }) });
  }
}

export async function savePublicKey(api: Api, entry: Omit<PublicKeyEntry, 'created'>): Promise<void> {
  await api(`/api/crypto/public-keys/${encodeURIComponent(entry.id)}`, { method: 'PUT', body: JSON.stringify(entry) });
}

export async function removePublicKey(api: Api, id: string): Promise<void> {
  await api(`/api/crypto/public-keys/${encodeURIComponent(id)}`, { method: 'DELETE' });
}

// ---------------------------------------------------------------------------
// Unlocked keys

type Opened = { kind: 'pgp'; key: pgp.Unlocked } | { kind: 'smime'; key: smime.Unlocked };
const unlocked = new Map<string, Opened>();

export function isUnlocked(id: string): boolean {
  return unlocked.has(id);
}

/** Unlock a key with its passphrase (kept for this tab). */
export async function unlock(key: OwnKey, passphrase: string): Promise<void> {
  if (key.kind === 'pgp') unlocked.set(key.id, { kind: 'pgp', key: await pgp.unlock(key.data, passphrase) });
  else unlocked.set(key.id, { kind: 'smime', key: await smime.unlock(key.data, passphrase) });
}

export function lockAll(): void {
  unlocked.clear();
}

export function openedPgp(id: string): pgp.Unlocked | null {
  const opened = unlocked.get(id);
  return opened?.kind === 'pgp' ? opened.key : null;
}

export function openedSmime(id: string): smime.Unlocked | null {
  const opened = unlocked.get(id);
  return opened?.kind === 'smime' ? opened.key : null;
}

/** Asks the user for a key's passphrase; resolves false when they cancel. */
export type AskPassphrase = (key: OwnKey) => Promise<boolean>;

/** Make sure `key` is unlocked, asking for its passphrase if needed. */
export async function ensureUnlocked(key: OwnKey, ask: AskPassphrase): Promise<boolean> {
  return unlocked.has(key.id) || ask(key);
}
