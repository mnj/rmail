// Signing and encrypting a message being sent: the server builds the body
// (`/api/compose/entity`), the browser protects it, and `/api/send` sends
// the result as it is.

import { Crypto } from './hook';
import * as keys from './keys';
import { pgpEncryptedEntity, signedBytes, signedEntity, smimeEncryptedEntity } from './mime';
import * as pgp from './pgp';
import * as smime from './smime';

export type Security = 'none' | 'sign' | 'encrypt' | 'sign-encrypt';
export type Technology = 'pgp' | 'smime';

/** The technologies the user has a key for. */
export function technologies(crypto: Crypto): Technology[] {
  const kinds = new Set(crypto.state?.keys.map((k) => k.kind) ?? []);
  return (['pgp', 'smime'] as Technology[]).filter((kind) => kinds.has(kind));
}

async function ownKey(crypto: Crypto, kind: Technology, from: string): Promise<keys.OwnKey> {
  const mine = crypto.state?.keys.filter((k) => k.kind === kind) ?? [];
  if (!mine.length) throw new Error(`You have no ${kind === 'pgp' ? 'OpenPGP key' : 'S/MIME certificate'}. Add one under Encryption.`);
  const address = from.toLowerCase();
  if (kind === 'pgp') {
    for (const key of mine) if ((await pgp.describe(key.data)).emails.includes(address)) return key;
    // An OpenPGP key often serves several addresses; the first one does.
    return mine[0];
  }
  // A certificate names its address, and receivers check it against From:
  // only a matching one will do. Reading it needs the certificate unlocked.
  for (const key of mine) {
    if (!(await keys.ensureUnlocked(key, crypto.ask))) throw new Error('cancelled');
    if ((await smime.ownCertificate(keys.openedSmime(key.id)!)).emails.includes(address)) return key;
  }
  throw new Error(`None of your S/MIME certificates is for ${from}.`);
}

/** The body to send for `payload`, signed and/or encrypted. */
export async function protect(crypto: Crypto, payload: { bcc?: string[] }, security: Security, kind: Technology): Promise<string> {
  const encryptingAtAll = security === 'encrypt' || security === 'sign-encrypt';
  // Every recipient's key is named in an encrypted message, so Bcc would not stay hidden.
  if (encryptingAtAll && payload.bcc?.length) throw new Error('Encrypted mail cannot have Bcc recipients: the others could see whose keys it is encrypted to. Send them a separate copy.');
  const made = await crypto.api<{ entity: string; from: string; recipients: string[] }>('/api/compose/entity', { method: 'POST', body: JSON.stringify(payload) });
  const own = await ownKey(crypto, kind, made.from);
  const signing = security === 'sign' || security === 'sign-encrypt';
  const encrypting = security === 'encrypt' || security === 'sign-encrypt';
  // S/MIME needs the user's own certificate to encrypt to themselves.
  if ((signing || (encrypting && kind === 'smime')) && !(await keys.ensureUnlocked(own, crypto.ask))) throw new Error('cancelled');
  let recipientKeys: string[] = [];
  if (encrypting) {
    // The user's own addresses are covered by their own key.
    const ownEmails = kind === 'pgp' ? (await pgp.describe(own.data)).emails : (await smime.ownCertificate(keys.openedSmime(own.id)!)).emails;
    const missing: string[] = [];
    for (const address of made.recipients) {
      if (ownEmails.includes(address.toLowerCase()) || address.toLowerCase() === made.from.toLowerCase()) continue;
      const found = crypto.state!.publicKeys.filter((k) => k.kind === kind && k.address === address.toLowerCase());
      if (!found.length) missing.push(address);
      recipientKeys.push(...found.map((k) => k.data));
    }
    if (missing.length) throw new Error(`No ${kind === 'pgp' ? 'OpenPGP key' : 'S/MIME certificate'} for ${missing.join(', ')}. Add theirs under Encryption, or send without encryption.`);
  }
  if (kind === 'pgp') {
    const signer = signing ? keys.openedPgp(own.id) : null;
    if (!encrypting) return signedEntity(made.entity, await pgp.sign(signedBytes(made.entity), signer!), 'pgp');
    // Encrypted to the user too, so the Sent copy can be read.
    recipientKeys = [...recipientKeys, await pgp.publicOf(own.data)];
    return pgpEncryptedEntity(await pgp.encrypt(made.entity, recipientKeys, signer));
  }
  const unlocked = keys.openedSmime(own.id)!;
  let inner = made.entity;
  if (signing) inner = signedEntity(inner, await smime.sign(signedBytes(inner), unlocked), 'smime');
  if (!encrypting) return inner;
  const self = (await smime.ownCertificate(unlocked)).pem;
  return smimeEncryptedEntity(await smime.encrypt(inner, [...recipientKeys, self]));
}
