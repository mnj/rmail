// Two-factor sign-in and app passwords. Every change asks for the password
// again; turning 2FA on or off signs out the user's other sessions.

import { useCallback, useEffect, useState } from 'react';
import { Copy, KeyRound, ShieldCheck, Smartphone, Trash2, X } from 'lucide-react';
import { Api, formatFullDate } from './types';

type AppPassword = { id: number; name: string; created_at: number; last_used_at: number | null };
type Overview = { two_factor: { enabled: boolean; since: number | null; recovery_left: number }; app_passwords: AppPassword[] };
type Step =
  | { kind: 'idle' }
  | { kind: 'password'; then: 'start' | 'disable' | 'recovery' | 'app' }
  | { kind: 'scan'; secret: string; qr: string }
  | { kind: 'codes'; codes: string[] }
  | { kind: 'made'; name: string; password: string };

function copy(text: string) {
  navigator.clipboard?.writeText(text).catch(() => undefined);
}

function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const text = codes.join('\n');
  return (
    <div className="security-step">
      <p>Keep these recovery codes somewhere safe, such as a password manager. Each one signs you in once if you lose your phone. They are shown only now.</p>
      <ol className="recovery-codes">{codes.map((code) => <li key={code}><code>{code}</code></li>)}</ol>
      <div className="security-buttons">
        <button type="button" className="secondary" onClick={() => copy(text)}><Copy size={14} />Copy</button>
        <a className="button secondary" href={`data:text/plain;charset=utf-8,${encodeURIComponent(text + '\n')}`} download="rmail-recovery-codes.txt">Download</a>
        <span className="spacer" />
        <button type="button" className="primary" onClick={onDone}>I have saved them</button>
      </div>
    </div>
  );
}

export function SecurityDialog({ api, address, onClose }: { api: Api; address: string; onClose: () => void }) {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [step, setStep] = useState<Step>({ kind: 'idle' });
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [name, setName] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => api<Overview>('/api/security').then(setOverview).catch((err) => setError((err as Error).message)), [api]);
  useEffect(() => { load(); }, [load]);

  const reset = () => { setStep({ kind: 'idle' }); setPassword(''); setCode(''); setName(''); setError(''); };
  const run = async (work: () => Promise<void>) => {
    setBusy(true);
    setError('');
    try { await work(); } catch (err) { setError((err as Error).message); } finally { setBusy(false); }
  };

  async function submitPassword(then: 'start' | 'disable' | 'recovery' | 'app') {
    await run(async () => {
      if (then === 'start') {
        const started = await api<{ secret: string; qr_svg: string }>('/api/security/totp/start', { method: 'POST', body: JSON.stringify({ password }) });
        setPassword('');
        setStep({ kind: 'scan', secret: started.secret, qr: started.qr_svg });
      } else if (then === 'disable') {
        await api('/api/security/totp/disable', { method: 'POST', body: JSON.stringify({ password, code }) });
        reset();
        await load();
      } else if (then === 'recovery') {
        const made = await api<{ recovery_codes: string[] }>('/api/security/recovery-codes', { method: 'POST', body: JSON.stringify({ password, code }) });
        setPassword(''); setCode('');
        setStep({ kind: 'codes', codes: made.recovery_codes });
      } else {
        const made = await api<{ password: string }>('/api/security/app-passwords', { method: 'POST', body: JSON.stringify({ name, password }) });
        setPassword('');
        setStep({ kind: 'made', name, password: made.password });
        await load();
      }
    });
  }

  async function confirm() {
    await run(async () => {
      const done = await api<{ recovery_codes: string[] }>('/api/security/totp/confirm', { method: 'POST', body: JSON.stringify({ code }) });
      setCode('');
      setStep({ kind: 'codes', codes: done.recovery_codes });
      await load();
    });
  }

  async function revoke(item: AppPassword) {
    if (!window.confirm(`Revoke "${item.name}"? Apps using it are signed out.`)) return;
    await run(async () => { await api(`/api/security/app-passwords/${item.id}`, { method: 'DELETE' }); await load(); });
  }

  const tf = overview?.two_factor;
  const passwordStep = step.kind === 'password' ? step : null;
  const needsCode = passwordStep && (passwordStep.then === 'disable' || passwordStep.then === 'recovery');
  return (
    <div className="dialog-scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()} onKeyDown={(e) => e.key === 'Escape' && onClose()}>
      <section className="dialog security-dialog" role="dialog" aria-modal="true" aria-label="Security">
        <header><h2>Security</h2><button type="button" className="icon" aria-label="Close" title="Close" autoFocus onClick={onClose}><X size={16} /></button></header>
        {overview === null && !error && <p className="muted">Loading…</p>}

        {overview && <>
          <h3 className="dialog-section"><ShieldCheck size={15} />Two-factor sign-in</h3>
          {step.kind === 'scan' ? (
            <div className="security-step">
              <p>Scan this code with an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, Aegis…), then type the six-digit code it shows.</p>
              <div className="totp-setup">
                <div className="totp-qr" dangerouslySetInnerHTML={{ __html: step.qr }} />
                <div>
                  <p className="muted small">Can't scan? Enter this key:</p>
                  <code className="totp-secret">{step.secret.replace(/(.{4})/g, '$1 ').trim()}</code>
                  <label className="field"><span>Code</span><input autoFocus inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} placeholder="123456" /></label>
                </div>
              </div>
              <div className="security-buttons"><button type="button" className="secondary" onClick={reset}>Cancel</button><span className="spacer" /><button type="button" className="primary" disabled={busy || !code.trim()} onClick={confirm}>Turn on</button></div>
            </div>
          ) : step.kind === 'codes' ? (
            <RecoveryCodes codes={step.codes} onDone={reset} />
          ) : tf?.enabled ? (
            <>
              <p className="security-status on"><ShieldCheck size={16} />On{tf.since ? ` since ${formatFullDate(tf.since)}` : ''}. {tf.recovery_left} recovery code{tf.recovery_left === 1 ? '' : 's'} left.</p>
              <p className="dialog-hint">Mail apps (phones, Thunderbird, Outlook, calendar and contacts sync) sign in with an app password, not your password.</p>
              {!passwordStep && <div className="security-buttons">
                <button type="button" className="secondary" onClick={() => setStep({ kind: 'password', then: 'recovery' })}>New recovery codes</button>
                <button type="button" className="secondary danger-quiet" onClick={() => setStep({ kind: 'password', then: 'disable' })}>Turn off</button>
              </div>}
            </>
          ) : (
            <>
              <p className="security-status">Off. Turn it on to require a code from your phone when you sign in to webmail.</p>
              <p className="dialog-hint">Once it is on, mail apps sign in with app passwords only, so make one for each device first (below), or right after.</p>
              {!passwordStep && <div className="security-buttons"><button type="button" className="primary" onClick={() => setStep({ kind: 'password', then: 'start' })}>Turn on…</button></div>}
            </>
          )}

          {passwordStep && passwordStep.then !== 'app' && (
            <form className="security-step" onSubmit={(e) => { e.preventDefault(); submitPassword(passwordStep.then); }}>
              <label className="field"><span>Your password</span><input type="password" autoFocus autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} /></label>
              {needsCode && <label className="field"><span>Code from your app, or a recovery code</span><input inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} /></label>}
              <div className="security-buttons"><button type="button" className="secondary" onClick={reset}>Cancel</button><span className="spacer" />
                <button className={passwordStep.then === 'disable' ? 'danger' : 'primary'} disabled={busy || !password || (needsCode ? !code.trim() : false)}>
                  {passwordStep.then === 'start' ? 'Continue' : passwordStep.then === 'disable' ? 'Turn off' : 'Make new codes'}
                </button>
              </div>
            </form>
          )}

          <h3 className="dialog-section"><Smartphone size={15} />App passwords</h3>
          <p className="dialog-hint">A separate password for each mail app or device ({address} as the user name), so you can revoke one without changing your password. {tf?.enabled ? 'With two-factor sign-in on, mail apps need one.' : ''}</p>
          {step.kind === 'made' ? (
            <div className="security-step">
              <p>Type this password into <strong>{step.name}</strong> instead of your own. It is shown only now; spaces and dashes don't matter.</p>
              <div className="app-password"><code>{step.password}</code><button type="button" className="secondary small-button" onClick={() => copy(step.password)}><Copy size={13} />Copy</button></div>
              <div className="security-buttons"><span className="spacer" /><button type="button" className="primary" onClick={reset}>Done</button></div>
            </div>
          ) : passwordStep?.then === 'app' ? (
            <form className="security-step" onSubmit={(e) => { e.preventDefault(); submitPassword('app'); }}>
              <div className="settings-grid two">
                <label className="field"><span>Name</span><input autoFocus maxLength={100} placeholder="e.g. iPhone mail" value={name} onChange={(e) => setName(e.target.value)} /></label>
                <label className="field"><span>Your password</span><input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} /></label>
              </div>
              <div className="security-buttons"><button type="button" className="secondary" onClick={reset}>Cancel</button><span className="spacer" /><button className="primary" disabled={busy || !name.trim() || !password}>Create</button></div>
            </form>
          ) : (
            <div><button type="button" className="secondary small-button" onClick={() => setStep({ kind: 'password', then: 'app' })}><KeyRound size={13} />New app password</button></div>
          )}
          {overview.app_passwords.length > 0 && (
            <ul className="app-password-list">
              {overview.app_passwords.map((item) => (
                <li key={item.id}>
                  <span><strong>{item.name}</strong><small>Created {formatFullDate(item.created_at)} · {item.last_used_at ? `last used ${formatFullDate(item.last_used_at)}` : 'not used yet'}</small></span>
                  <button type="button" className="icon" aria-label={`Revoke ${item.name}`} title="Revoke" onClick={() => revoke(item)}><Trash2 size={14} /></button>
                </li>
              ))}
            </ul>
          )}
        </>}
        {error && <p className="error" role="alert">{error}</p>}
      </section>
    </div>
  );
}
