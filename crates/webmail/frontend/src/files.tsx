// The user's own files (file storage over WebDAV), in webmail: browse,
// upload, make folders, rename, delete and download. The same files are
// reachable from file managers and sync apps at /webdav/.

import { useCallback, useEffect, useRef, useState } from 'react';
import { ChevronRight, Download, File, Folder, FolderPlus, HardDrive, Pencil, Trash2, Upload, X } from 'lucide-react';
import { formatFullDate, formatSize } from './types';

type Entry = { name: string; folder: boolean; size: number; modified: number };
type Listing = { entries: Entry[]; used: number | null; available: number | null };

const HEADERS = { 'X-Rmail-Webmail': '1' };
const enc = (segments: string[]) => '/webdav/' + segments.map(encodeURIComponent).join('/');

async function list(path: string[]): Promise<Listing> {
  const res = await fetch(enc(path) + (path.length ? '/' : ''), { method: 'PROPFIND', credentials: 'same-origin', headers: { ...HEADERS, Depth: '1' } });
  if (!res.ok) throw new Error(res.status === 404 ? 'This folder no longer exists.' : `The files could not be listed (${res.status}).`);
  const doc = new DOMParser().parseFromString(await res.text(), 'application/xml');
  const ns = 'DAV:';
  const text = (node: Element, name: string) => node.getElementsByTagNameNS(ns, name)[0]?.textContent ?? '';
  const responses = Array.from(doc.getElementsByTagNameNS(ns, 'response'));
  const self = responses[0];
  const number = (value: string) => (value === '' ? null : Number(value));
  const entries = responses.slice(1).map((response) => {
    const href = decodeURIComponent(text(response, 'href').replace(/\/$/, ''));
    return {
      name: href.split('/').pop() || '',
      folder: response.getElementsByTagNameNS(ns, 'collection').length > 0,
      size: Number(text(response, 'getcontentlength') || 0),
      modified: Date.parse(text(response, 'getlastmodified')) / 1000 || 0,
    };
  });
  entries.sort((a, b) => Number(b.folder) - Number(a.folder) || a.name.localeCompare(b.name));
  return { entries, used: self ? number(text(self, 'quota-used-bytes')) : null, available: self ? number(text(self, 'quota-available-bytes')) : null };
}

async function dav(method: string, path: string[], headers: Record<string, string> = {}): Promise<void> {
  const res = await fetch(enc(path), { method, credentials: 'same-origin', headers: { ...HEADERS, ...headers } });
  if (!res.ok) {
    const reasons: Record<number, string> = { 405: 'Something with that name already exists.', 409: 'The folder it goes in is missing.', 412: 'Something with that name already exists.', 507: 'There is not enough room left in your storage.' };
    throw new Error(reasons[res.status] ?? `That did not work (${res.status}).`);
  }
}

/** PUT a file with progress (fetch cannot report upload progress). */
function upload(path: string[], file: globalThis.File, progress: (sent: number) => void): Promise<void> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('PUT', enc(path));
    xhr.setRequestHeader('X-Rmail-Webmail', '1');
    xhr.upload.onprogress = (event) => progress(event.loaded);
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) resolve();
      else reject(new Error(xhr.status === 507 ? `${file.name} does not fit in your storage.` : xhr.status === 413 ? `${file.name} is larger than this server allows.` : `${file.name} could not be uploaded (${xhr.status}).`));
    };
    xhr.onerror = () => reject(new Error(`${file.name} could not be uploaded.`));
    xhr.send(file);
  });
}

export function FilesDialog({ address, onClose }: { address: string; onClose: () => void }) {
  const [path, setPath] = useState<string[]>([]);
  const [listing, setListing] = useState<Listing | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [sending, setSending] = useState<{ name: string; sent: number; size: number } | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const load = useCallback(() => list(path).then(setListing).catch((err) => setError((err as Error).message)), [path]);
  useEffect(() => { setListing(null); setError(''); load(); }, [load]);

  const run = async (work: () => Promise<void>) => {
    setBusy(true);
    setError('');
    try { await work(); await load(); } catch (err) { setError((err as Error).message); } finally { setBusy(false); }
  };
  const valid = (name: string) => name && !/[\\/]/.test(name) && name !== '.' && name !== '..';

  async function uploadFiles(files: globalThis.File[]) {
    await run(async () => {
      for (const file of files) {
        setSending({ name: file.name, sent: 0, size: file.size });
        await upload([...path, file.name], file, (sent) => setSending({ name: file.name, sent, size: file.size }));
      }
    });
    setSending(null);
  }
  function newFolder() {
    const name = window.prompt('Name of the new folder')?.trim();
    if (name && valid(name)) run(() => dav('MKCOL', [...path, name]));
  }
  function rename(entry: Entry) {
    const name = window.prompt(`Rename ${entry.name} to`, entry.name)?.trim();
    if (name && valid(name) && name !== entry.name) {
      run(() => dav('MOVE', [...path, entry.name], { Destination: enc([...path, name]), Overwrite: 'F' }));
    }
  }
  function remove(entry: Entry) {
    if (window.confirm(`Delete ${entry.name}${entry.folder ? ' and everything in it' : ''}?`)) run(() => dav('DELETE', [...path, entry.name]));
  }

  const used = listing?.used ?? null;
  const total = used !== null && listing?.available !== null && listing?.available !== undefined ? used + listing.available : null;
  return (
    <div className="dialog-scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()} onKeyDown={(e) => e.key === 'Escape' && onClose()}>
      <section className="dialog wide files-dialog" role="dialog" aria-modal="true" aria-label="Files"
        onDragOver={(e) => e.preventDefault()} onDrop={(e) => { e.preventDefault(); uploadFiles(Array.from(e.dataTransfer.files)); }}>
        <header>
          <h2><HardDrive size={18} />Files</h2>
          <div className="header-actions">
            <button type="button" className="secondary" disabled={busy} onClick={newFolder}><FolderPlus size={14} />New folder</button>
            <button type="button" className="primary" disabled={busy} onClick={() => fileRef.current?.click()}><Upload size={14} />Upload</button>
            <input ref={fileRef} type="file" multiple hidden onChange={(e) => { uploadFiles(Array.from(e.target.files || [])); e.target.value = ''; }} />
            <button type="button" className="icon" aria-label="Close" title="Close" onClick={onClose}><X size={16} /></button>
          </div>
        </header>
        <nav className="files-path" aria-label="Folder">
          <button type="button" className="link" onClick={() => setPath([])}>My files</button>
          {path.map((name, index) => (
            <span key={index}><ChevronRight size={13} /><button type="button" className="link" onClick={() => setPath(path.slice(0, index + 1))}>{name}</button></span>
          ))}
        </nav>
        <div className="files-list">
          {sending && <div className="files-progress" role="status">Uploading {sending.name}… {Math.round((sending.sent / Math.max(1, sending.size)) * 100)}%<progress max={sending.size} value={sending.sent} /></div>}
          {error && <p className="error" role="alert">{error}</p>}
          {listing === null && !error && <p className="muted">Loading…</p>}
          {listing && listing.entries.length === 0 && <p className="muted">Nothing here yet. Upload files or drop them here.</p>}
          {listing && listing.entries.length > 0 && (
            <ul>
              {listing.entries.map((entry) => (
                <li key={entry.name}>
                  {entry.folder
                    ? <button type="button" className="files-name" onClick={() => setPath([...path, entry.name])}><Folder size={16} />{entry.name}</button>
                    : <a className="files-name" href={enc([...path, entry.name])} download={entry.name}><File size={16} />{entry.name}</a>}
                  <small className="muted">{entry.folder ? '' : formatSize(entry.size)}</small>
                  <small className="muted">{entry.modified ? formatFullDate(entry.modified) : ''}</small>
                  <span className="files-actions">
                    {!entry.folder && <a className="icon" href={enc([...path, entry.name])} download={entry.name} aria-label={`Download ${entry.name}`} title="Download"><Download size={15} /></a>}
                    <button type="button" className="icon" aria-label={`Rename ${entry.name}`} title="Rename" disabled={busy} onClick={() => rename(entry)}><Pencil size={15} /></button>
                    <button type="button" className="icon" aria-label={`Delete ${entry.name}`} title="Delete" disabled={busy} onClick={() => remove(entry)}><Trash2 size={15} /></button>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
        <footer className="files-footer">
          <small className="muted">
            {used !== null && total !== null ? `${formatSize(used)} of ${formatSize(total)} used. ` : ''}
            Your file manager or sync app can connect to <code>{window.location.origin}/webdav/</code> as {address}, with an app password from Security.
          </small>
        </footer>
      </section>
    </div>
  );
}
