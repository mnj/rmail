// OpenPGP (RFC 9580) with OpenPGP.js, loaded only when needed. Private
// keys are always stored locked with the user's passphrase.

import { binaryToBytes, bytesToBinary } from './mime';

type OpenPGP = typeof import('openpgp');
let loaded: Promise<OpenPGP> | null = null;
const openpgp = () => (loaded ??= import('openpgp'));

export type PgpInfo = { fingerprint: string; label: string; emails: string[]; expires: number | null; created: number };

async function info(key: import('openpgp').Key): Promise<PgpInfo> {
  const ids = key.getUserIDs();
  const emails = ids.map((id) => /<([^>]+)>/.exec(id)?.[1] ?? (id.includes('@') ? id.trim() : '')).filter(Boolean).map((e) => e.toLowerCase());
  let expires: number | null = null;
  try {
    const time = await key.getExpirationTime();
    if (time instanceof Date) expires = Math.floor(time.getTime() / 1000);
  } catch { /* no valid self-signature: treated as not expiring here */ }
  return {
    fingerprint: key.getFingerprint().toUpperCase(),
    label: ids[0] ?? key.getKeyID().toHex(),
    emails,
    expires,
    created: Math.floor(key.getCreationTime().getTime() / 1000),
  };
}

export async function describe(armored: string): Promise<PgpInfo> {
  const { readKey } = await openpgp();
  return info(await readKey({ armoredKey: armored }));
}

/** A new key pair for the user, locked with `passphrase`. */
export async function generate(name: string, email: string, passphrase: string) {
  const { generateKey } = await openpgp();
  const { privateKey } = await generateKey({ userIDs: [{ name, email }], passphrase, format: 'armored' });
  return { armored: privateKey, info: await describe(privateKey) };
}

/** A private key the user brought, checked against its passphrase (and locked with it if it was not). */
export async function importPrivate(armored: string, passphrase: string) {
  const { readPrivateKey, decryptKey, encryptKey } = await openpgp();
  const key = await readPrivateKey({ armoredKey: armored });
  const locked = key.isDecrypted()
    ? (await encryptKey({ privateKey: key, passphrase })).armor()
    : (await decryptKey({ privateKey: key, passphrase }), key.armor());
  return { armored: locked, info: await info(key) };
}

/** The public half of a private key, armored. */
export async function publicOf(armored: string): Promise<string> {
  const { readPrivateKey } = await openpgp();
  return (await readPrivateKey({ armoredKey: armored })).toPublic().armor();
}

/** Public keys in an armored block (a key file can hold several). */
export async function readPublicKeys(armored: string): Promise<{ armored: string; info: PgpInfo }[]> {
  const { readKeys } = await openpgp();
  const keys = await readKeys({ armoredKeys: armored });
  return Promise.all(keys.map(async (key) => {
    const pub = key.isPrivate() ? key.toPublic() : key;
    return { armored: pub.armor(), info: await info(pub) };
  }));
}

export async function unlock(armored: string, passphrase: string) {
  const { readPrivateKey, decryptKey } = await openpgp();
  return decryptKey({ privateKey: await readPrivateKey({ armoredKey: armored }), passphrase });
}

export type Unlocked = Awaited<ReturnType<typeof unlock>>;

async function publicKeys(armored: string[]) {
  const { readKey } = await openpgp();
  const out = [];
  for (const text of armored) {
    try { out.push(await readKey({ armoredKey: text })); } catch { /* skip a key that does not read */ }
  }
  return out;
}

export type Verdict = { status: 'valid' | 'invalid' | 'unknown_key'; signer: string | null };

async function verdict(signatures: { keyID: { toHex(): string }; verified: Promise<unknown> }[], keys: import('openpgp').Key[]): Promise<Verdict> {
  if (!signatures.length) return { status: 'invalid', signer: null };
  const signature = signatures[0];
  const signerKey = keys.find((key) => key.getKeys().some((sub) => sub.getKeyID().equals(signature.keyID as never)));
  try {
    await signature.verified;
    const label = signerKey ? (await info(signerKey)).label : null;
    return { status: 'valid', signer: label };
  } catch (err) {
    const message = (err as Error).message || '';
    if (!signerKey || /could not find signing key|missing key/i.test(message)) {
      return { status: 'unknown_key', signer: `key ${signature.keyID.toHex().toUpperCase()}` };
    }
    return { status: 'invalid', signer: (await info(signerKey)).label };
  }
}

/** Check a detached signature over the exact signed part. */
export async function verifyDetached(signed: string, armoredSignature: string, keys: string[]): Promise<Verdict> {
  const { createMessage, readSignature, verify } = await openpgp();
  const verificationKeys = await publicKeys(keys);
  const result = await verify({
    message: await createMessage({ binary: binaryToBytes(signed) }),
    signature: await readSignature({ armoredSignature }),
    verificationKeys,
  });
  return verdict(result.signatures, verificationKeys);
}

/** A detached signature over `inner` (CRLF lines, as sent). */
export async function sign(inner: string, key: Unlocked): Promise<string> {
  const { createMessage, sign: signWith } = await openpgp();
  return signWith({ message: await createMessage({ binary: binaryToBytes(inner) }), signingKeys: key, detached: true, format: 'armored' }) as Promise<string>;
}

/** `inner` encrypted to `recipients` (armored public keys), signed by `signer` when given. */
export async function encrypt(inner: string, recipients: string[], signer: Unlocked | null): Promise<string> {
  const { createMessage, encrypt: encryptWith } = await openpgp();
  return encryptWith({
    message: await createMessage({ binary: binaryToBytes(inner) }),
    encryptionKeys: await publicKeys(recipients),
    ...(signer ? { signingKeys: signer } : {}),
    format: 'armored',
  }) as Promise<string>;
}

/** Decrypt an armored message; returns its content (a binary string) and any signature. */
export async function decrypt(armored: string, keys: Unlocked[], verifyWith: string[]): Promise<{ data: string; verdict: Verdict | null }> {
  const { readMessage, decrypt: decryptWith } = await openpgp();
  const verificationKeys = await publicKeys(verifyWith);
  const result = await decryptWith({
    message: await readMessage({ armoredMessage: armored }),
    decryptionKeys: keys,
    verificationKeys,
    format: 'binary',
  });
  const data = bytesToBinary(result.data as Uint8Array);
  const signatures = result.signatures as { keyID: { toHex(): string }; verified: Promise<unknown> }[];
  return { data, verdict: signatures.length ? await verdict(signatures, verificationKeys) : null };
}

/** The key ids a message is encrypted to (to say which key is missing). */
export async function recipientsOf(armored: string): Promise<string[]> {
  const { readMessage } = await openpgp();
  const message = await readMessage({ armoredMessage: armored });
  return message.getEncryptionKeyIDs().map((id) => id.toHex().toUpperCase());
}

/** Whether one of `keys` (armored private) can decrypt for these key ids. */
export async function matchingKeys(armoredKeys: { id: string; data: string }[], wanted: string[]): Promise<string[]> {
  const { readPrivateKey } = await openpgp();
  const out: string[] = [];
  for (const stored of armoredKeys) {
    try {
      const key = await readPrivateKey({ armoredKey: stored.data });
      if (key.getKeys().some((sub) => wanted.includes(sub.getKeyID().toHex().toUpperCase()))) out.push(stored.id);
    } catch { /* not readable */ }
  }
  return out;
}

/** Verify a cleartext-signed (inline) message. */
export async function verifyCleartext(text: string, keys: string[]): Promise<{ text: string; verdict: Verdict }> {
  const { readCleartextMessage, verify } = await openpgp();
  const verificationKeys = await publicKeys(keys);
  const message = await readCleartextMessage({ cleartextMessage: text });
  const result = await verify({ message, verificationKeys });
  return { text: message.getText(), verdict: await verdict(result.signatures, verificationKeys) };
}
