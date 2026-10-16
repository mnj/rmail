// The reading pane's part for signed and encrypted mail: checks signatures
// and decrypts in the browser, then shows what was inside.

import { useEffect, useMemo, useState } from 'react';
import DOMPurify from 'dompurify';
import { Download, Lock, ShieldAlert, ShieldCheck, ShieldQuestion, Unlock } from 'lucide-react';
import { Crypto } from './hook';
import * as keys from './keys';
import { Shown, binaryToBytes, bytesToBinary, crlf, decodedBody, encryptedPayload, parseEntity, protectionOf, readEntity, splitSigned } from './mime';
import * as pgp from './pgp';
import * as smime from './smime';

type Verdict = { kind: 'pgp' | 'smime'; status: 'valid' | 'invalid' | 'unknown_key'; signer: string | null; note?: string };
type Opened = { shown: Shown | null; verdicts: Verdict[] };

export const ENCRYPTED = new Set(['pgp-encrypted', 'smime-encrypted', 'smime-opaque', 'pgp-inline']);

const purifier = DOMPurify(window);
purifier.addHook('uponSanitizeAttribute', (_node, data) => {
  // Nothing decrypted loads from elsewhere (no tracking, nothing leaks).
  if ((data.attrName === 'src' || data.attrName === 'background') && !/^(data:|blob:)/i.test(data.attrValue)) data.keepAttr = false;
  if (data.attrName === 'style' && /url\s*\(/i.test(data.attrValue)) data.keepAttr = false;
});

function htmlDocument(html: string, shown: Shown): string {
  let body = html;
  for (const attachment of shown.attachments) {
    if (!attachment.contentId) continue;
    const url = `data:${attachment.mimeType};base64,${btoa(bytesToBinary(attachment.content))}`;
    body = body.split(`cid:${attachment.contentId}`).join(url);
  }
  const clean = purifier.sanitize(body, {
    WHOLE_DOCUMENT: false,
    FORBID_TAGS: ['form', 'input', 'button', 'textarea', 'select', 'iframe', 'object', 'embed', 'meta', 'link', 'base', 'script'],
  });
  return `<!doctype html><html><head><meta charset="utf-8"><base target="_blank"><style>body{font-family:system-ui,sans-serif;margin:0;padding:0 2px;overflow-wrap:anywhere}img{max-width:100%;height:auto}</style></head><body>${clean}</body></html>`;
}

async function fetchRaw(folder: string, uid: number): Promise<string> {
  const res = await fetch(`/api/folders/${encodeURIComponent(folder)}/messages/${uid}/raw`, { credentials: 'same-origin', headers: { 'X-Rmail-Webmail': '1' } });
  if (!res.ok) throw new Error('The message could not be loaded.');
  return bytesToBinary(new Uint8Array(await res.arrayBuffer()));
}

function senderAddress(from: string): string {
  return (/<([^>]+)>/.exec(from)?.[1] ?? from).trim().toLowerCase();
}

/** Open an entity: decrypt and check signatures, layer by layer. */
async function open(entity: string, crypto: Crypto, from: string, depth = 0): Promise<Opened> {
  const state = crypto.state!;
  const kind = depth > 4 ? null : protectionOf(entity);
  const pgpPublic = [...state.publicKeys.filter((k) => k.kind === 'pgp').map((k) => k.data)];
  for (const own of state.keys.filter((k) => k.kind === 'pgp')) pgpPublic.push(await pgp.publicOf(own.data));
  if (kind === 'pgp-signed') {
    const parts = splitSigned(entity);
    if (!parts) return { shown: await readEntity(entity), verdicts: [{ kind: 'pgp', status: 'invalid', signer: null, note: 'The signature could not be found.' }] };
    const verdict = await pgp.verifyDetached(parts.signed, parts.signature, pgpPublic);
    const inner = await open(parts.signed, crypto, from, depth + 1);
    return { shown: inner.shown, verdicts: [{ kind: 'pgp', ...verdict }, ...inner.verdicts] };
  }
  if (kind === 'smime-signed' || kind === 'smime-opaque') {
    let signatureDer: string;
    let content: string | null = null;
    if (kind === 'smime-signed') {
      const parts = splitSigned(entity);
      if (!parts) return { shown: await readEntity(entity), verdicts: [{ kind: 'smime', status: 'invalid', signer: null, note: 'The signature could not be found.' }] };
      signatureDer = parts.signature;
      content = parts.signed;
    } else {
      signatureDer = decodedBody(parseEntity(entity));
    }
    const result = await smime.verify(signatureDer, content);
    const sender = senderAddress(from);
    let note = result.reason;
    if (result.status === 'valid') {
      if (sender && result.emails.length && !result.emails.includes(sender)) note = `The certificate is for ${result.emails.join(', ')}, not the sender.`;
      else if (result.certificate && !state.publicKeys.some((k) => k.data.trim() === result.certificate!.trim())) {
        // Remember the sender's certificate, to encrypt to them later.
        const info = await smime.describeCertificate(result.certificate);
        await keys.savePublicKey(crypto.api, { id: info.id, kind: 'smime', address: info.emails[0] ?? sender, label: info.label, data: info.pem }).then(() => crypto.reload()).catch(() => undefined);
      }
      if (result.issuer) note = [note, `Certificate issued by ${result.issuer}; not checked against trusted authorities.`].filter(Boolean).join(' ');
    }
    const inner = await open(result.content, crypto, from, depth + 1);
    return { shown: inner.shown, verdicts: [{ kind: 'smime', status: result.status, signer: result.signer, note }, ...inner.verdicts] };
  }
  if (kind === 'pgp-encrypted') {
    const armored = encryptedPayload(entity);
    if (!armored) throw new Error('The encrypted part is missing.');
    const ids = await pgp.recipientsOf(armored);
    const candidates = await pgp.matchingKeys(state.keys.filter((k) => k.kind === 'pgp'), ids);
    const own = state.keys.find((k) => candidates.includes(k.id));
    if (!own) throw new Error(`This message was not encrypted to any of your OpenPGP keys (it is for ${ids.join(', ') || 'unknown keys'}).`);
    if (!(await keys.ensureUnlocked(own, crypto.ask))) throw new Error('cancelled');
    const result = await pgp.decrypt(armored, [keys.openedPgp(own.id)!], pgpPublic);
    const inner = await open(crlf(result.data), crypto, from, depth + 1);
    return { shown: inner.shown, verdicts: [...(result.verdict ? [{ kind: 'pgp' as const, ...result.verdict }] : []), ...inner.verdicts] };
  }
  if (kind === 'smime-encrypted') {
    const der = encryptedPayload(entity);
    if (!der) throw new Error('The encrypted part is missing.');
    const own = state.keys.filter((k) => k.kind === 'smime');
    if (!own.length) throw new Error('You have no S/MIME certificate to decrypt this with.');
    for (const key of own) if (!(await keys.ensureUnlocked(key, crypto.ask))) throw new Error('cancelled');
    const inner = await smime.decrypt(der, own.map((k) => keys.openedSmime(k.id)!).filter(Boolean));
    return open(crlf(inner), crypto, from, depth + 1);
  }
  return { shown: await readEntity(entity), verdicts: [] };
}

/** An inline OpenPGP block in a plain-text body. */
async function openInline(text: string, crypto: Crypto): Promise<Opened> {
  const state = crypto.state!;
  const pgpPublic = state.publicKeys.filter((k) => k.kind === 'pgp').map((k) => k.data);
  const signedBlock = /-----BEGIN PGP SIGNED MESSAGE-----[\s\S]*?-----END PGP SIGNATURE-----/.exec(text);
  if (signedBlock) {
    const result = await pgp.verifyCleartext(signedBlock[0], pgpPublic);
    return { shown: { text: result.text, html: null, attachments: [] }, verdicts: [{ kind: 'pgp', ...result.verdict }] };
  }
  const block = /-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----/.exec(text);
  if (!block) throw new Error('The encrypted block is missing.');
  const ids = await pgp.recipientsOf(block[0]);
  const candidates = await pgp.matchingKeys(state.keys.filter((k) => k.kind === 'pgp'), ids);
  const own = state.keys.find((k) => candidates.includes(k.id));
  if (!own) throw new Error('This message was not encrypted to any of your OpenPGP keys.');
  if (!(await keys.ensureUnlocked(own, crypto.ask))) throw new Error('cancelled');
  const result = await pgp.decrypt(block[0], [keys.openedPgp(own.id)!], pgpPublic);
  const decoded = new TextDecoder().decode(binaryToBytes(result.data));
  return { shown: { text: decoded, html: null, attachments: [] }, verdicts: result.verdict ? [{ kind: 'pgp', ...result.verdict }] : [] };
}

function Badge({ verdict }: { verdict: Verdict }) {
  const tech = verdict.kind === 'pgp' ? 'OpenPGP' : 'S/MIME';
  const Icon = verdict.status === 'valid' ? ShieldCheck : verdict.status === 'unknown_key' ? ShieldQuestion : ShieldAlert;
  const text = verdict.status === 'valid'
    ? `Signed by ${verdict.signer ?? 'an unknown signer'} (${tech}); the signature is valid.`
    : verdict.status === 'unknown_key'
      ? `Signed (${tech}) with ${verdict.signer ?? 'a key'} you do not have. Add the sender's public key to check it.`
      : `The ${tech} signature${verdict.signer ? ` from ${verdict.signer}` : ''} is not valid: the message may have been changed.`;
  return (
    <div className={`crypto-badge ${verdict.status}`} role="status">
      <Icon size={16} /><span>{text}{verdict.note && <small className="muted"> {verdict.note}</small>}</span>
    </div>
  );
}

function AttachmentLinks({ shown }: { shown: Shown }) {
  const urls = useMemo(() => shown.attachments.filter((a) => !(a.inline && a.contentId)).map((a) => ({ ...a, url: URL.createObjectURL(new Blob([a.content as BlobPart], { type: a.mimeType })) })), [shown]);
  useEffect(() => () => urls.forEach((a) => URL.revokeObjectURL(a.url)), [urls]);
  if (!urls.length) return null;
  return (
    <ul className="crypto-attachments">
      {urls.map((a) => <li key={a.url}><a href={a.url} download={a.filename}><Download size={14} />{a.filename}</a> <small className="muted">{Math.max(1, Math.round(a.content.length / 1024))} KB</small></li>)}
    </ul>
  );
}

/** What a protected message shows: signature verdicts and, once decrypted, its content. */
export function ProtectedMessage({ crypto, folder, uid, protection, from, textBody }: {
  crypto: Crypto; folder: string; uid: number; protection: string; from: string; textBody: string;
}) {
  const encrypted = ENCRYPTED.has(protection);
  const [opened, setOpened] = useState<Opened | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function run() {
    if (!crypto.state) return;
    setBusy(true);
    setError('');
    try {
      setOpened(protection === 'pgp-inline' || protection === 'pgp-inline-signed'
        ? await openInline(textBody, crypto)
        : await open(await fetchRaw(folder, uid), crypto, from));
    } catch (err) {
      const message = (err as Error).message;
      if (message !== 'cancelled') setError(message || 'The message could not be opened.');
    } finally {
      setBusy(false);
    }
  }

  // Signatures are checked at once; decrypting waits for the user.
  useEffect(() => {
    setOpened(null);
    setError('');
    if (!encrypted && crypto.state) run();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [folder, uid, protection, crypto.state === null]);

  const shown = opened?.shown;
  return (
    <div className="crypto-panel">
      {encrypted && !opened && (
        <div className="crypto-locked">
          <Lock size={20} />
          <div><strong>This message is encrypted.</strong><p className="muted small">It is decrypted in your browser with your {protection.startsWith('smime') ? 'S/MIME certificate' : 'OpenPGP key'}; nothing decrypted is sent to the server.</p></div>
          <button type="button" className="primary" disabled={busy || !crypto.state} onClick={run}><Unlock size={14} />{busy ? 'Decrypting…' : 'Decrypt'}</button>
        </div>
      )}
      {!encrypted && busy && <p className="muted small">Checking the signature…</p>}
      {opened?.verdicts.map((verdict, index) => <Badge key={index} verdict={verdict} />)}
      {error && <div className="crypto-badge invalid" role="alert"><ShieldAlert size={16} /><span>{error}</span></div>}
      {encrypted && shown && (
        <>
          {opened && opened.verdicts.length === 0 && <div className="crypto-badge plain"><Lock size={16} /><span>Decrypted. The message was not signed.</span></div>}
          {shown.html
            ? <iframe className="html-message" title="Decrypted message" sandbox="allow-popups allow-popups-to-escape-sandbox" srcDoc={htmlDocument(shown.html, shown)} />
            : <pre className="text-message">{shown.text}</pre>}
          <AttachmentLinks shown={shown} />
        </>
      )}
    </div>
  );
}
