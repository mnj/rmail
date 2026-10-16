// Encryption settings: where the user's keys live, their own OpenPGP keys
// and S/MIME certificates, and other people's public keys.

import { useState } from 'react';
import { Download, KeyRound, Lock, Plus, Trash2, Upload, X } from 'lucide-react';
import { formatFullDate } from '../types';
import { Crypto } from './hook';
import * as keys from './keys';
import * as pgp from './pgp';
import * as smime from './smime';

type Form = null | 'generate' | 'import-pgp' | 'import-p12' | 'public';

function readFile(file: File, binary: boolean): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      if (!binary) return resolve(String(reader.result));
      const bytes = new Uint8Array(reader.result as ArrayBuffer);
      let text = '';
      for (const b of bytes) text += String.fromCharCode(b);
      resolve(btoa(text));
    };
    reader.onerror = () => reject(reader.error);
    if (binary) reader.readAsArrayBuffer(file); else reader.readAsText(file);
  });
}

function download(name: string, text: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const short = (id: string) => id.length > 16 ? `${id.slice(0, 4)} … ${id.slice(-16).replace(/(.{4})/g, '$1 ').trim()}` : id;

export function EncryptionDialog({ crypto, onClose }: { crypto: Crypto; onClose: () => void }) {
  const { api, address, state, reload } = crypto;
  const [form, setForm] = useState<Form>(null);
  const [name, setName] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [again, setAgain] = useState('');
  const [password, setPassword] = useState('');
  const [text, setText] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const reset = () => { setForm(null); setName(''); setPassphrase(''); setAgain(''); setPassword(''); setText(''); setFile(null); setError(''); };
  const run = async (work: () => Promise<void>) => {
    setBusy(true);
    setError('');
    try { await work(); await reload(); reset(); } catch (err) { setError((err as Error).message); } finally { setBusy(false); }
  };
  if (!state) return null;
  const storage = state.storage;
  const passphraseOk = passphrase.length >= 8 && passphrase === again;

  const addOwn = (key: keys.OwnKey) => keys.saveKey(api, address, storage, key);

  async function generate() {
    const made = await pgp.generate(name.trim(), address, passphrase);
    await addOwn({ id: made.info.fingerprint, kind: 'pgp', label: made.info.label, data: made.armored, created: made.info.created });
  }
  async function importPgp() {
    const armored = file ? await readFile(file, false) : text;
    const made = await pgp.importPrivate(armored, passphrase);
    await addOwn({ id: made.info.fingerprint, kind: 'pgp', label: made.info.label, data: made.armored, created: made.info.created });
  }
  async function importP12() {
    if (!file) throw new Error('Choose the .p12 or .pfx file.');
    const made = await smime.importP12(await readFile(file, true), password, passphrase || password);
    await addOwn({ id: made.info.id, kind: 'smime', label: made.info.label, data: made.data, created: Math.floor(Date.now() / 1000) });
  }
  async function addPublic() {
    const data = file ? await readFile(file, false) : text;
    if (data.includes('-----BEGIN PGP')) {
      for (const key of await pgp.readPublicKeys(data)) {
        await keys.savePublicKey(api, { id: key.info.fingerprint, kind: 'pgp', address: key.info.emails[0] ?? '', label: key.info.label, data: key.armored });
      }
    } else if (data.includes('-----BEGIN CERTIFICATE-----')) {
      const info = await smime.describeCertificate(data);
      await keys.savePublicKey(api, { id: info.id, kind: 'smime', address: info.emails[0] ?? '', label: info.label, data: info.pem });
    } else {
      throw new Error('Paste an OpenPGP public key block or a PEM certificate.');
    }
  }
  async function exportPublic(key: keys.OwnKey) {
    if (key.kind === 'pgp') download(`${address}.asc`, await pgp.publicOf(key.data), 'application/pgp-keys');
  }
  async function remove(key: keys.OwnKey) {
    if (!window.confirm(`Delete ${key.label}? Mail encrypted to it can no longer be read here unless you import it again.`)) return;
    await run(() => keys.removeKey(api, address, storage, key.id));
  }
  async function move(to: keys.Storage) {
    await run(() => keys.moveKeys(api, address, state!, to));
  }

  const passphraseFields = (label = 'Passphrase to lock it') => (
    <div className="settings-grid two">
      <label className="field"><span>{label}</span><input type="password" autoComplete="new-password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} /></label>
      <label className="field"><span>Again</span><input type="password" autoComplete="new-password" value={again} onChange={(e) => setAgain(e.target.value)} /></label>
    </div>
  );

  return (
    <div className="dialog-scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()} onKeyDown={(e) => e.key === 'Escape' && onClose()}>
      <section className="dialog crypto-dialog" role="dialog" aria-modal="true" aria-label="Encryption">
        <header><h2><Lock size={18} />Encryption</h2><button type="button" className="icon" aria-label="Close" title="Close" onClick={onClose}><X size={16} /></button></header>
        <p className="dialog-intro">Sign and encrypt mail with OpenPGP or S/MIME. All signing, encrypting and decrypting happens in your browser; your keys are always locked with your passphrase.</p>

        <h3 className="dialog-section">Where your keys are kept</h3>
        <div className="crypto-choice" role="radiogroup" aria-label="Where your keys are kept">
          <label className={storage === 'browser' ? 'selected' : ''}><input type="radio" checked={storage === 'browser'} disabled={busy} onChange={() => move('browser')} />
            <span><strong>In this browser only</strong><small className="muted">The server never has them. Other devices need the key imported too.</small></span></label>
          <label className={storage === 'server' ? 'selected' : ''}><input type="radio" checked={storage === 'server'} disabled={busy} onChange={() => move('server')} />
            <span><strong>On the server, locked</strong><small className="muted">Available wherever you sign in to webmail; the server keeps them locked with your passphrase.</small></span></label>
        </div>

        <h3 className="dialog-section"><KeyRound size={15} />Your keys</h3>
        {state.keys.length === 0 && <p className="muted small">No keys yet.</p>}
        <ul className="crypto-keys">
          {state.keys.map((key) => (
            <li key={key.id}>
              <span className={`crypto-kind ${key.kind}`}>{key.kind === 'pgp' ? 'OpenPGP' : 'S/MIME'}</span>
              <span className="crypto-key-text"><strong>{key.label}</strong><small className="muted">{short(key.id)} · added {formatFullDate(key.created)}</small></span>
              {key.kind === 'pgp' && <button type="button" className="icon" aria-label="Download public key" title="Download public key" onClick={() => exportPublic(key)}><Download size={15} /></button>}
              <button type="button" className="icon" aria-label={`Delete ${key.label}`} title="Delete" onClick={() => remove(key)}><Trash2 size={15} /></button>
            </li>
          ))}
        </ul>
        {form === null && (
          <div className="security-buttons">
            <button type="button" className="secondary" onClick={() => { reset(); setForm('generate'); }}><Plus size={14} />New OpenPGP key</button>
            <button type="button" className="secondary" onClick={() => { reset(); setForm('import-pgp'); }}><Upload size={14} />Import OpenPGP key</button>
            <button type="button" className="secondary" onClick={() => { reset(); setForm('import-p12'); }}><Upload size={14} />Import S/MIME certificate</button>
          </div>
        )}
        {form === 'generate' && (
          <div className="security-step">
            <label className="field"><span>Your name (shown with the key)</span><input value={name} onChange={(e) => setName(e.target.value)} placeholder={address} /></label>
            {passphraseFields()}
            <p className="dialog-hint">At least 8 characters. Without it the key cannot be used, and it cannot be recovered.</p>
            <div className="security-buttons"><button type="button" className="secondary" onClick={reset}>Cancel</button><span className="spacer" />
              <button type="button" className="primary" disabled={busy || !passphraseOk} onClick={() => run(generate)}>{busy ? 'Creating…' : 'Create key'}</button></div>
          </div>
        )}
        {form === 'import-pgp' && (
          <div className="security-step">
            <label className="field"><span>Private key (.asc)</span><input type="file" accept=".asc,.gpg,.key,.txt" onChange={(e) => setFile(e.target.files?.[0] ?? null)} /></label>
            {!file && <label className="field"><span>Or paste it</span><textarea rows={4} value={text} onChange={(e) => setText(e.target.value)} placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----" /></label>}
            <label className="field"><span>Its passphrase (or a new one, if it has none)</span><input type="password" autoComplete="current-password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} /></label>
            <div className="security-buttons"><button type="button" className="secondary" onClick={reset}>Cancel</button><span className="spacer" />
              <button type="button" className="primary" disabled={busy || !passphrase || (!file && !text.trim())} onClick={() => run(importPgp)}>{busy ? 'Importing…' : 'Import'}</button></div>
          </div>
        )}
        {form === 'import-p12' && (
          <div className="security-step">
            <label className="field"><span>Certificate with its private key (.p12, .pfx)</span><input type="file" accept=".p12,.pfx" onChange={(e) => setFile(e.target.files?.[0] ?? null)} /></label>
            <label className="field"><span>The file's password</span><input type="password" autoComplete="off" value={password} onChange={(e) => setPassword(e.target.value)} /></label>
            <label className="field"><span>Passphrase to lock it here (leave empty to use the file's password)</span><input type="password" autoComplete="new-password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} /></label>
            <div className="security-buttons"><button type="button" className="secondary" onClick={reset}>Cancel</button><span className="spacer" />
              <button type="button" className="primary" disabled={busy || !file || !(passphrase || password)} onClick={() => run(importP12)}>{busy ? 'Importing…' : 'Import'}</button></div>
          </div>
        )}

        <h3 className="dialog-section">Other people's keys</h3>
        <p className="dialog-hint">Needed to encrypt to someone. Certificates from S/MIME-signed mail you read are added by themselves.</p>
        {state.publicKeys.length > 0 && (
          <ul className="crypto-keys">
            {state.publicKeys.map((key) => (
              <li key={key.id}>
                <span className={`crypto-kind ${key.kind}`}>{key.kind === 'pgp' ? 'OpenPGP' : 'S/MIME'}</span>
                <span className="crypto-key-text"><strong>{key.address || key.label}</strong><small className="muted">{key.label} · {short(key.id)}</small></span>
                <button type="button" className="icon" aria-label={`Remove the key for ${key.address}`} title="Remove" onClick={() => run(() => keys.removePublicKey(api, key.id))}><Trash2 size={15} /></button>
              </li>
            ))}
          </ul>
        )}
        {form === 'public' ? (
          <div className="security-step">
            <label className="field"><span>Public key or certificate file</span><input type="file" accept=".asc,.gpg,.pem,.crt,.cer" onChange={(e) => setFile(e.target.files?.[0] ?? null)} /></label>
            {!file && <label className="field"><span>Or paste it</span><textarea rows={4} value={text} onChange={(e) => setText(e.target.value)} placeholder="-----BEGIN PGP PUBLIC KEY BLOCK----- or -----BEGIN CERTIFICATE-----" /></label>}
            <div className="security-buttons"><button type="button" className="secondary" onClick={reset}>Cancel</button><span className="spacer" />
              <button type="button" className="primary" disabled={busy || (!file && !text.trim())} onClick={() => run(addPublic)}>Add</button></div>
          </div>
        ) : form === null && <div className="security-buttons"><button type="button" className="secondary" onClick={() => { reset(); setForm('public'); }}><Plus size={14} />Add a public key</button></div>}
        {error && <p className="error small" role="alert">{error}</p>}
      </section>
    </div>
  );
}
