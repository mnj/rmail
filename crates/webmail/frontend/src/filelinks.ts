// Files too large to attach, uploaded in chunks and sent as download links
// (`/api/files`, served at `/f/<token>`).

import { Api } from './types';

export type FileLinkSettings = { enabled: boolean; max_file_bytes: number; per_user_bytes: number; days: number; chunk_bytes: number; used: number };
export type SharedFile = { id: string; name: string; size: number; url: string; created: number; expires: number; downloads: number };
export type FileListing = FileLinkSettings & { files: SharedFile[] };
export type Linked = { id: string; name: string; size: number; url: string; expires: number };

/** Upload `file` and make its link; `progress` gets the bytes sent so far. */
export async function uploadAsLink(api: Api, file: File, chunk: number, progress: (sent: number) => void): Promise<Linked> {
  const { id } = await api<{ id: string }>('/api/files', { method: 'POST', body: JSON.stringify({ name: file.name, size: file.size }) });
  try {
    for (let offset = 0; offset < file.size; offset += chunk) {
      const body = await file.slice(offset, offset + chunk).arrayBuffer();
      await api(`/api/files/${id}/chunk?offset=${offset}`, { method: 'PUT', body, headers: { 'Content-Type': 'application/octet-stream' } });
      progress(Math.min(file.size, offset + chunk));
    }
    const done = await api<{ url: string; expires: number }>(`/api/files/${id}/finish`, { method: 'POST' });
    return { id, name: file.name, size: file.size, url: `${window.location.origin}${done.url}`, expires: done.expires };
  } catch (err) {
    await api(`/api/files/${id}`, { method: 'DELETE' }).catch(() => undefined);
    throw err;
  }
}
