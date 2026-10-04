import { useEffect, useState } from 'react';
import { FolderPlus, Plus, Tag, X } from 'lucide-react';
import type { Api, Organize, OrganizeFolder, OrganizeLabel } from './types';
import { listNames } from './types';

/** What a cloud provider would receive for the features this user turned on. */
function cloudUses(data: Organize): string[] {
  const uses: string[] = [];
  if (data.enabled && data.cloud_required) uses.push('Every message you file or receive is sent to learn your folders, including recent mail already in them.');
  else if (data.enabled && data.labels_cloud) uses.push('Messages rMail is unsure where to file are sent.');
  if (data.labels_enabled && data.labels_cloud) uses.push('Every new message in your inbox is sent to label it.');
  if ((data.ai_labels || data.ai_summary) && data.labels_cloud) uses.push('Messages you choose to summarize or label are sent when you ask.');
  return uses;
}

export function OrganizeDialog({ api, onClose, onSaved }: { api: Api; onClose: () => void; onSaved: () => void }) {
  const [data, setData] = useState<Organize | null>(null);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  // Labels the editor showed; ones the AI adds meanwhile are not removed on save.
  const [seen, setSeen] = useState<string[]>([]);
  const [editingLabels, setEditingLabels] = useState(false);
  const [ideaParent, setIdeaParent] = useState('');

  useEffect(() => {
    api<Organize>('/api/organize').then((loaded) => {
      setData(loaded);
      setSeen(loaded.labels.map((l) => l.name));
    }).catch((err) => setError((err as Error).message));
  }, []);

  function updateLabel(index: number, change: Partial<OrganizeLabel>) {
    if (!data) return;
    setData({ ...data, labels: data.labels.map((l, i) => (i === index ? { ...l, ...change } : l)) });
  }

  async function createFolder(label: string) {
    if (!data) return;
    try {
      await api('/api/organize/folders', { method: 'POST', body: JSON.stringify({ label, ...(ideaParent ? { parent: ideaParent } : {}) }) });
      setData({ ...data, folder_ideas: data.folder_ideas.filter((idea) => idea.label !== label) });
      onSaved();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  function update(name: string, change: Partial<OrganizeFolder>) {
    if (!data) return;
    setData({ ...data, folders: data.folders.map((f) => (f.name === name ? { ...f, ...change } : f)) });
  }

  async function save() {
    if (!data) return;
    setSaving(true);
    try {
      await api('/api/organize', {
        method: 'PUT',
        body: JSON.stringify({
          enabled: data.enabled,
          labels_enabled: data.labels_enabled,
          labels: data.labels.filter((l) => l.name.trim()).map((l) => ({ name: l.name, description: l.description })),
          labels_seen: seen,
          ...(data.cloud_providers.length ? { cloud_consent: data.cloud_consent } : {}),
          excluded_folders: data.folders.filter((f) => f.excluded).map((f) => f.name),
          autofile_folders: data.folders.filter((f) => f.autofile && !f.excluded).map((f) => f.name),
        }),
      });
      onSaved();
      onClose();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="dialog-scrim" onClick={onClose}>
      <section className="dialog" role="dialog" aria-label="Organize my mail" onClick={(e) => e.stopPropagation()}>
        <header><h2>Organize my mail</h2><button className="icon" onClick={onClose} title="Close"><X size={18} /></button></header>
        {error && <p className="error">{error}</p>}
        {!data ? <p>Loading…</p> : <>
          <p className="dialog-intro">rMail learns from how you file mail into your folders and suggests a folder for new mail in your inbox.{' '}
            {data.cloud_providers.length === 0
              ? 'It runs entirely on this server; your mail is not sent anywhere.'
              : <>Your administrator uses {listNames(data.cloud_providers)} for this. They only receive your mail if you agree below.</>}
          </p>
          {!data.server_enabled && <p className="notice">Your administrator has not turned this on yet. Your choices are saved and take effect once they do.</p>}
          <label className="switch-row"><input type="checkbox" checked={data.enabled} onChange={(e) => setData({ ...data, enabled: e.target.checked })} /><span>Suggest folders for new mail</span></label>

          {data.enabled && (data.folders.length === 0
            ? <p className="notice">Create a few folders and file some mail into them first; suggestions are based on your own filing.</p>
            : <table className="organize-table">
              <thead><tr><th>Folder</th><th>Learn &amp; suggest</th><th>Move automatically</th><th>Last 30 days</th></tr></thead>
              <tbody>{data.folders.map((f) => (
                <tr key={f.name}>
                  <td><strong>{f.name}</strong><small>{f.learned} messages learned</small></td>
                  <td><input type="checkbox" aria-label={`Suggest ${f.name}`} checked={!f.excluded} onChange={(e) => update(f.name, { excluded: !e.target.checked })} /></td>
                  <td><input type="checkbox" aria-label={`Move to ${f.name} automatically`} disabled={f.excluded} checked={f.autofile && !f.excluded} onChange={(e) => update(f.name, { autofile: e.target.checked })} /></td>
                  <td><small>{f.accepted} accepted · {f.dismissed} dismissed</small></td>
                </tr>
              ))}</tbody>
            </table>)}
          {data.enabled && <p className="dialog-hint">Automatic moves only happen when rMail is very confident and the suggestion is based on mail you filed yourself. Everything else stays in your inbox as a suggestion.</p>}

          <h3 className="dialog-section"><Tag size={16} />Labels</h3>
          <p className="dialog-hint">rMail labels new mail in your inbox automatically. It starts with common labels such as Receipts, Travel and Action needed, and its AI adds a new label when nothing fits. Remove any you don't want and they won't come back; add or reword your own to steer it. Labels show here and, as keywords, in IMAP apps that support them.</p>
          {!data.labels_available && <p className="notice">Your administrator has not set up a model for labels yet. Your labels are saved and used once they do.</p>}
          <label className="switch-row"><input type="checkbox" checked={data.labels_enabled} onChange={(e) => setData({ ...data, labels_enabled: e.target.checked })} /><span>Label new mail</span></label>
          {data.labels_enabled && <>
            {data.labels.length === 0 && <p className="notice">Common labels are added when you save.</p>}
            {!editingLabels ? (
              <div className="label-summary">
                {data.labels.map((label) => (
                  <span className="label-chip" key={label.name} title={label.description || label.name}>
                    <Tag size={11} />{label.name}{label.origin === 'ai' && <span className="ai-badge" title="Created by the AI for mail no other label fit">AI</span>}{label.count > 0 && <small>{label.count}</small>}
                    <button aria-label={`Remove label ${label.name}`} title="Remove label" onClick={() => setData({ ...data, labels: data.labels.filter((l) => l.name !== label.name) })}><X size={11} /></button>
                  </span>
                ))}
                <button className="add-label" onClick={() => setEditingLabels(true)}>Edit labels</button>
              </div>
            ) : (
              <div className="label-editor">
              {data.labels.map((label, index) => (
                <div className="label-row" key={index}>
                  <input aria-label="Label name" value={label.name} maxLength={40} placeholder="Name" onChange={(e) => updateLabel(index, { name: e.target.value })} />
                  <input aria-label={`What ${label.name || 'this label'} means`} value={label.description} maxLength={300} placeholder="What it means (helps the AI)" onChange={(e) => updateLabel(index, { description: e.target.value })} />
                  <small>{label.origin === 'ai' && <span className="ai-badge" title="Created by the AI for mail no other label fit">AI</span>}{label.count ? ` ${label.count} labeled` : ''}</small>
                  <button className="icon" title="Remove label" aria-label={`Remove ${label.name}`} onClick={() => setData({ ...data, labels: data.labels.filter((_, i) => i !== index) })}><X size={15} /></button>
                </div>
              ))}
              {data.labels.length < 30 && <button className="add-label" onClick={() => setData({ ...data, labels: [...data.labels, { name: '', description: '', keyword: '', count: 0, origin: 'user' }] })}><Plus size={14} />Add label</button>}
            </div>
            )}
            {data.folder_ideas.length > 0 && (
              <div className="folder-ideas">
                <p className="dialog-hint">You use these labels a lot. They might deserve a folder:</p>
                <label className="idea-parent">Create in <select value={ideaParent} onChange={(e) => setIdeaParent(e.target.value)}><option value="">Top level</option>{data.folders.map((f) => <option key={f.name} value={f.name}>{f.name}</option>)}</select></label>
                {data.folder_ideas.map((idea) => (
                  <button key={idea.label} onClick={() => createFolder(idea.label)}><FolderPlus size={14} />{idea.label} <small>{idea.count} messages</small></button>
                ))}
              </div>
            )}
          </>}

          {(data.enabled || data.labels_enabled || data.ai_labels || data.ai_summary) && data.cloud_providers.length > 0 && <>
            <h3 className="dialog-section">Privacy</h3>
            <label className="switch-row"><input type="checkbox" checked={data.cloud_consent} onChange={(e) => setData({ ...data, cloud_consent: e.target.checked })} /><span>Send my mail to {listNames(data.cloud_providers)}</span></label>
            <p className="dialog-hint">
              {cloudUses(data).join(' ')} Only the sender, subject and the start of the body are sent.
              {' '}Without this, {data.enabled && !data.cloud_required ? 'folder suggestions still come from mail you filed, on this server' : 'these features are off for you'}. You can withdraw at any time.
            </p>
          </>}
          <footer><button className="secondary" onClick={onClose}>Cancel</button><button className="primary" disabled={saving} onClick={save}>{saving ? 'Saving…' : 'Save'}</button></footer>
        </>}
      </section>
    </div>
  );
}

