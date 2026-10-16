// The user's keys for the webmail app, and asking for a passphrase when a
// key is needed.

import React, { useCallback, useEffect, useRef, useState } from 'react';
import { KeyRound, X } from 'lucide-react';
import { Api } from '../types';
import * as keys from './keys';

export type Crypto = {
  state: keys.CryptoState | null;
  reload: () => Promise<void>;
  ask: keys.AskPassphrase;
  address: string;
  api: Api;
};

function PassphraseDialog({ ownKey, onDone }: { ownKey: keys.OwnKey; onDone: (ok: boolean) => void }) {
  const [passphrase, setPassphrase] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      await keys.unlock(ownKey, passphrase);
      onDone(true);
    } catch {
      setError('That passphrase does not unlock the key.');
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="dialog-scrim" onKeyDown={(e) => e.key === 'Escape' && onDone(false)}>
      <form className="dialog small" role="dialog" aria-label="Unlock key" onSubmit={submit}>
        <header>
          <h2><KeyRound size={18} />Unlock your key</h2>
          <button type="button" className="icon" aria-label="Cancel" title="Cancel" onClick={() => onDone(false)}><X size={16} /></button>
        </header>
        <p className="muted small">{ownKey.kind === 'pgp' ? 'OpenPGP' : 'S/MIME'} key <strong>{ownKey.label}</strong>. It stays unlocked in this tab until you close or reload it.</p>
        <label className="field"><span>Passphrase</span><input type="password" autoFocus autoComplete="current-password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} /></label>
        {error && <p className="error small" role="alert">{error}</p>}
        <footer>
          <button type="button" className="secondary" onClick={() => onDone(false)}>Cancel</button>
          <button type="submit" className="primary" disabled={busy || !passphrase}>{busy ? 'Unlocking…' : 'Unlock'}</button>
        </footer>
      </form>
    </div>
  );
}

/** The user's keys, and an element to render that asks for passphrases. */
export function useCrypto(api: Api, address: string): [Crypto, React.ReactNode] {
  const [state, setState] = useState<keys.CryptoState | null>(null);
  const [asking, setAsking] = useState<{ key: keys.OwnKey; resolve: (ok: boolean) => void } | null>(null);
  const queue = useRef(Promise.resolve(true));
  const reload = useCallback(async () => {
    try { setState(await keys.load(api, address)); } catch { setState(null); }
  }, [api, address]);
  useEffect(() => { reload(); }, [reload]);
  const ask = useCallback<keys.AskPassphrase>((key) => {
    // One prompt at a time.
    const next = queue.current.then(() => keys.isUnlocked(key.id) || new Promise<boolean>((resolve) => setAsking({ key, resolve })));
    queue.current = next.catch(() => false);
    return next;
  }, []);
  const element = asking && <PassphraseDialog ownKey={asking.key} onDone={(ok) => { asking.resolve(ok); setAsking(null); }} />;
  return [{ state, reload, ask, address, api }, element];
}
