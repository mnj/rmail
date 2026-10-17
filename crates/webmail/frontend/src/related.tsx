// Messages close in meaning to the open one, from the user's search by
// meaning index (nothing is sent to a model). Hidden when there are none.
import { useEffect, useState } from 'react';
import { Sparkles } from 'lucide-react';
import { Api, formatListDate, splitAddress } from './types';

type Related = { folder: string; uid: number; from: string; subject: string; internal_date: number };

export function RelatedPanel({ api, folder, uid, onOpen }: { api: Api; folder: string; uid: number; onOpen: (folder: string, uid: number) => void }) {
  const [related, setRelated] = useState<Related[]>([]);
  useEffect(() => {
    let live = true;
    setRelated([]);
    api<{ messages: Related[] }>(`/api/folders/${encodeURIComponent(folder)}/messages/${uid}/related`)
      .then((data) => { if (live) setRelated(data.messages); })
      .catch(() => undefined);
    return () => { live = false; };
  }, [api, folder, uid]);
  if (!related.length) return null;
  return (
    <details className="related" open>
      <summary><Sparkles size={14} className="ai-mark" />Related messages</summary>
      <ul>
        {related.map((m) => (
          <li key={`${m.folder}:${m.uid}`}>
            <button type="button" onClick={() => onOpen(m.folder, m.uid)}>
              <span className="related-subject">{m.subject || '(no subject)'}</span>
              <span className="muted small">{splitAddress(m.from).name || splitAddress(m.from).address}{m.folder !== folder && <> · {m.folder === 'INBOX' ? 'Inbox' : m.folder}</>} · {formatListDate(m.internal_date)}</span>
            </button>
          </li>
        ))}
      </ul>
    </details>
  );
}
