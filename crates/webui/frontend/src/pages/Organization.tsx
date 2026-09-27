import React, { useState } from 'react';
import { CheckCircle2, Download, FlaskConical, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { api, CatalogModel, ModelKind, Organization } from '../api';
import { Empty, ErrorBanner, Field, formatBytes, formatRelative, Modal, Panel, Toggle, useFeedback, useResource } from '../ui';

const kindLabel: Record<ModelKind, string> = { embedding: 'Embedding', chat: 'Chat' };

function activeFile(org: Organization, kind: ModelKind): string {
  const value = org.settings[kind === 'embedding' ? 'embed_model' : 'chat_model'];
  return typeof value === 'string' ? value : '';
}

function CustomModelModal({ onClose, onStarted }: { onClose: () => void; onStarted: () => void }) {
  const { run } = useFeedback();
  const [url, setUrl] = useState('');
  const [file, setFile] = useState('');
  const [kind, setKind] = useState<ModelKind>('embedding');
  const [sha256, setSha256] = useState('');
  const [prefix, setPrefix] = useState('');

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    const ok = await run(() => api('/api/organization/download', 'POST', { url: url.trim(), file: file.trim(), kind, sha256: sha256.trim() || null, prefix }), `Downloading ${file}`);
    if (ok) {
      onStarted();
      onClose();
    }
  }

  return (
    <Modal title="Add a model by URL" onClose={onClose} footer={<>
      <button className="button" type="button" onClick={onClose}>Cancel</button>
      <button className="button primary" type="submit" form="customModel" disabled={!url.startsWith('https://') || !file.endsWith('.gguf')}>Download</button>
    </>}>
      <form id="customModel" className="formStack" onSubmit={submit}>
        <Field label="HTTPS URL" hint="A direct link to a GGUF file, such as a Hugging Face resolve/main link.">
          <input value={url} onChange={(event) => { setUrl(event.target.value); if (!file) setFile(event.target.value.split('/').pop() || ''); }} placeholder="https://huggingface.co/…/resolve/main/model.gguf" autoFocus required />
        </Field>
        <Field label="File name"><input value={file} onChange={(event) => setFile(event.target.value)} placeholder="model.gguf" required /></Field>
        <Field label="Kind">
          <select value={kind} onChange={(event) => setKind(event.target.value as ModelKind)}>
            <option value="embedding">Embedding (required)</option>
            <option value="chat">Chat (optional fallback)</option>
          </select>
        </Field>
        <Field label="SHA-256" hint="Optional. When set, a download that does not match is discarded."><input value={sha256} onChange={(event) => setSha256(event.target.value)} placeholder="64 hex characters" /></Field>
        <Field label="Input prefix" hint="Text the model expects before each input, e.g. “classification: ” for Nomic. Usually empty."><input value={prefix} onChange={(event) => setPrefix(event.target.value)} /></Field>
      </form>
    </Modal>
  );
}

function TestPanel({ org }: { org: Organization }) {
  const { notify } = useFeedback();
  const [text, setText] = useState('From: airline@example.com\nSubject: Your boarding pass for AB123\n\nYour flight departs from gate 12 at 09:40.');
  const [folders, setFolders] = useState('Receipts, Travel, Family, Newsletters');
  const [busy, setBusy] = useState<ModelKind | null>(null);
  const [result, setResult] = useState<{ kind: ModelKind; data: Record<string, unknown> } | null>(null);
  const status = org.daemon.running ? org.daemon.status : null;

  async function test(kind: ModelKind) {
    setBusy(kind);
    setResult(null);
    try {
      const data = await api<Record<string, unknown>>('/api/organization/test', 'POST', {
        kind: kind === 'embedding' ? 'embed' : 'chat',
        text,
        folders: folders.split(','),
      });
      setResult({ kind, data });
    } catch (err) {
      notify('error', err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  }

  return (
    <Panel title="Try it" subtitle="Runs on the classifier daemon with the loaded models.">
      <div className="formStack padded">
        <Field label="Sample message"><textarea rows={5} value={text} onChange={(event) => setText(event.target.value)} /></Field>
        <Field label="Folders for the chat test" hint="Comma separated."><input value={folders} onChange={(event) => setFolders(event.target.value)} /></Field>
        <div className="inputRow">
          <button className="button" disabled={!status?.embed_model || busy !== null} onClick={() => test('embedding')}><FlaskConical size={16} />{busy === 'embedding' ? 'Embedding…' : 'Test embedding'}</button>
          <button className="button" disabled={!status?.chat_model || busy !== null} onClick={() => test('chat')}><FlaskConical size={16} />{busy === 'chat' ? 'Thinking…' : 'Test chat'}</button>
        </div>
        {result && result.kind === 'embedding' && (
          <div className="banner info">
            {String(result.data.dimensions)} dimensions in {String(result.data.ms)} ms · first values {(result.data.preview as number[]).map((v) => v.toFixed(3)).join(', ')}
          </div>
        )}
        {result && result.kind === 'chat' && (
          <div className="banner info">
            {result.data.folder ? <>Chose <strong>{String(result.data.folder)}</strong> with confidence {Number(result.data.confidence).toFixed(1)}</> : 'No folder fits'} in {String(result.data.ms)} ms
            <code className="rawAnswer">{String(result.data.raw)}</code>
          </div>
        )}
      </div>
    </Panel>
  );
}

export function OrganizationPage() {
  const { run, confirm } = useFeedback();
  const org = useResource(() => api<Organization>('/api/organization'), [], 3000);
  const [custom, setCustom] = useState(false);
  const data = org.data;

  if (!data) return <><ErrorBanner error={org.error} />{org.loading && <Empty>Loading…</Empty>}</>;

  const installed = new Map(data.installed.map((model) => [model.file, model]));
  const downloads = new Map(data.downloads.map((download) => [download.file, download]));
  const status = data.daemon.running ? data.daemon.status : null;
  const enabled = data.settings.enabled === true;
  const catalogFiles = new Set(data.catalog.map((model) => model.file));
  const extra = data.installed.filter((model) => !catalogFiles.has(model.file));

  async function activate(body: Record<string, unknown>, message: string) {
    await run(async () => {
      const result = await api<{ reloaded: boolean; reload_error: string | null }>('/api/organization/activate', 'POST', body);
      if (!result.reloaded) throw new Error(`Saved, but the classifier daemon did not reload: ${result.reload_error}`);
    }, message);
    org.reload();
  }

  async function remove(file: string) {
    if (await confirm({ title: `Delete ${file}?`, message: 'The model file is removed from the models directory.', confirmLabel: 'Delete model', danger: true })) {
      if (await run(() => api('/api/organization/delete', 'POST', { file }), `Deleted ${file}`)) org.reload();
    }
  }

  function row(model: { file: string; name: string; kind: ModelKind; notes: string; size_mb?: number; ram_mb?: number; license?: string; catalog?: CatalogModel }) {
    const have = installed.get(model.file);
    const download = downloads.get(model.file);
    const active = activeFile(data!, model.kind) === model.file;
    const running = download?.status.state === 'running';
    const percent = running && download!.total ? Math.round((download!.received / download!.total) * 100) : null;
    return (
      <tr key={model.file}>
        <td><strong>{model.name}</strong><small>{model.file}{model.notes ? ` · ${model.notes}` : ''}</small></td>
        <td><span className="pill">{kindLabel[model.kind]}</span></td>
        <td>{have ? formatBytes(have.size) : model.size_mb ? `~${model.size_mb} MB` : '—'}{model.ram_mb ? <small>~{model.ram_mb} MB RAM</small> : null}</td>
        <td>{model.license || '—'}</td>
        <td className="usage">
          {running && <><span>{formatBytes(download!.received)}{download!.total ? ` of ${formatBytes(download!.total)}` : ''}</span>{percent !== null && <div className="usageBar"><i style={{ width: `${percent}%` }} /></div>}</>}
          {download?.status.state === 'failed' && <span className="errorText">{download.status.error}</span>}
          {!running && have && (active ? <span className="pill ok"><CheckCircle2 size={13} /> Active</span> : <span className="pill">Installed</span>)}
          {have?.meta && <small title={have.meta.sha256}>sha256 {have.meta.sha256.slice(0, 12)}…</small>}
        </td>
        <td className="rowActions">
          {!have && !running && model.catalog && <button className="button" onClick={() => run(() => api('/api/organization/download', 'POST', { catalog_id: model.catalog!.id }), `Downloading ${model.name}`).then(() => org.reload())}><Download size={15} />Download</button>}
          {have && !active && <button className="button" onClick={() => activate(model.kind === 'embedding' ? { embed_model: model.file } : { chat_model: model.file }, `${model.name} is now active`)}>Use</button>}
          {have && active && model.kind === 'chat' && <button className="button" onClick={() => activate({ chat_model: '' }, 'Chat fallback turned off')}>Stop using</button>}
          {have && !active && <button className="iconButton danger" title="Delete model" onClick={() => remove(model.file)}><Trash2 size={15} /></button>}
        </td>
      </tr>
    );
  }

  return (
    <div className="organizationPage">
      <ErrorBanner error={org.error} />
      <div className="systemHero">
        <div>
          <span className={`statusDot ${status && enabled && status.embed_model ? 'ok' : 'error'}`} />
          <strong>{!status ? 'Classifier daemon not running' : !enabled ? 'Mail organization is off' : status.embed_model ? 'Suggesting folders for opted-in mailboxes' : activeFile(data, 'embedding') ? 'The embedding model did not load' : 'Choose an embedding model'}</strong>
          <p>
            {status
              ? <>{status.accounts.opted_in || 0} mailbox{status.accounts.opted_in === 1 ? '' : 'es'} opted in from webmail.{status.last_cycle && <> Last check {formatRelative(status.last_cycle.finished_at)}: {status.last_cycle.report.learned} learned, {status.last_cycle.report.suggested} suggested, {status.last_cycle.report.moved} moved.</>}</>
              : <>Start <code>rmail_classifier</code> to classify mail. {data.daemon.running ? '' : data.daemon.error}</>}
          </p>
        </div>
        <div className="heroActions">
          <Toggle checked={enabled} disabled={!data.managed} label="Enabled" onChange={(value) => activate({ enabled: value }, value ? 'Mail organization enabled' : 'Mail organization disabled')} />
          <button className="button" onClick={() => run(() => api('/api/organization/reload', 'POST'), 'Classifier reloaded').then(() => org.reload())} disabled={!status}><RefreshCw size={16} />Reload</button>
        </div>
      </div>
      {status?.errors.map((message) => <ErrorBanner key={message} error={message} />)}
      {status && !status.local_models && <ErrorBanner error="This rmail_classifier build has no local-model support (built without the local-models feature)." />}
      {!data.managed && <ErrorBanner error="Settings are file-only (no db_path), so models cannot be activated here." />}
      <Panel
        title="Models"
        subtitle={<>Stored in <code>{data.models_dir}</code>. An embedding model is required. A chat model is an optional fallback for messages the embedding vote is unsure about.</>}
        actions={<button className="button" onClick={() => setCustom(true)}><Plus size={16} />Add by URL</button>}
      >
        <table>
          <thead><tr><th>Model</th><th>Kind</th><th>Size</th><th>License</th><th>Status</th><th /></tr></thead>
          <tbody>
            {data.catalog.map((model) => row({ ...model, catalog: model }))}
            {extra.map((model) => row({ file: model.file, name: model.file, kind: model.meta?.kind || (activeFile(data, 'chat') === model.file ? 'chat' : 'embedding'), notes: model.meta ? new URL(model.meta.url).host : 'added manually' }))}
          </tbody>
        </table>
        <p className="panelNote">Catalog checksums are not pinned yet. Each download records the SHA-256 it received, and a model added by URL can require a specific checksum.</p>
      </Panel>
      <TestPanel org={data} />
      {custom && <CustomModelModal onClose={() => setCustom(false)} onStarted={org.reload} />}
    </div>
  );
}
