// S/MIME (RFC 8551) with node-forge, loaded only when needed: PKCS#12
// import, detached signatures, and enveloped data (RSA key transport,
// AES-256-CBC content). Certificates are not checked against trusted roots
// here; the reader shows who a certificate names and who issued it.

type Forge = typeof import('node-forge');
let loaded: Promise<Forge> | null = null;
const load = () => (loaded ??= import('node-forge').then((m) => (m as unknown as { default: Forge }).default ?? (m as unknown as Forge)));

export type CertInfo = { id: string; label: string; emails: string[]; issuer: string; expires: number; pem: string };

function attribute(entity: import('node-forge').pki.Certificate['subject'], short: string): string {
  const field = entity.getField(short);
  return field ? String(field.value) : '';
}

async function certInfo(cert: import('node-forge').pki.Certificate): Promise<CertInfo> {
  const forge = await load();
  const der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  const md = forge.md.sha256.create();
  md.update(der);
  const emails = new Set<string>();
  const san = cert.getExtension('subjectAltName') as { altNames?: { type: number; value: string }[] } | null;
  for (const name of san?.altNames ?? []) if (name.type === 1) emails.add(name.value.toLowerCase());
  const subjectEmail = attribute(cert.subject, 'E') || (cert.subject.getField({ name: 'emailAddress' })?.value as string | undefined) || '';
  if (subjectEmail) emails.add(subjectEmail.toLowerCase());
  const cn = attribute(cert.subject, 'CN');
  return {
    id: md.digest().toHex().toUpperCase(),
    label: cn || [...emails][0] || 'Certificate',
    emails: [...emails],
    issuer: attribute(cert.issuer, 'CN') || attribute(cert.issuer, 'O'),
    expires: Math.floor(cert.validity.notAfter.getTime() / 1000),
    pem: forge.pki.certificateToPem(cert),
  };
}

export async function describeCertificate(pem: string): Promise<CertInfo> {
  const forge = await load();
  return certInfo(forge.pki.certificateFromPem(pem));
}

export type Unlocked = { key: import('node-forge').pki.rsa.PrivateKey; cert: import('node-forge').pki.Certificate; chain: import('node-forge').pki.Certificate[] };

/** Open a PKCS#12 file (base64) with its password. */
export async function unlock(base64: string, password: string): Promise<Unlocked> {
  const forge = await load();
  const p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(atob(base64)), password);
  const keyBag = (p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag] ?? [])[0]
    ?? (p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag] ?? [])[0];
  const certs = (p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] ?? [])
    .map((bag) => bag.cert)
    .filter((cert): cert is import('node-forge').pki.Certificate => Boolean(cert));
  const key = keyBag?.key as import('node-forge').pki.rsa.PrivateKey | undefined;
  if (!key) throw new Error('The file has no private key (or an unsupported, non-RSA one).');
  // The user's own certificate is the one for this key.
  const cert = certs.find((c) => (c.publicKey as import('node-forge').pki.rsa.PublicKey).n?.equals(key.n)) ?? certs[0];
  if (!cert) throw new Error('The file has no certificate.');
  return { key, cert, chain: certs.filter((c) => c !== cert) };
}

/** A PKCS#12 file checked against its password, and locked with `passphrase` for keeping. */
export async function importP12(base64: string, password: string, passphrase: string) {
  const forge = await load();
  const unlocked = await unlock(base64, password);
  const asn1 = forge.pkcs12.toPkcs12Asn1(unlocked.key, [unlocked.cert, ...unlocked.chain], passphrase, { algorithm: 'aes256' });
  return { data: btoa(forge.asn1.toDer(asn1).getBytes()), info: await certInfo(unlocked.cert) };
}

export async function ownCertificate(unlocked: Unlocked): Promise<CertInfo> {
  return certInfo(unlocked.cert);
}

/** A detached CMS signature (DER, binary string) over `inner`. */
export async function sign(inner: string, signer: Unlocked): Promise<string> {
  const forge = await load();
  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer(inner);
  p7.addCertificate(signer.cert);
  for (const cert of signer.chain) p7.addCertificate(cert);
  p7.addSigner({
    key: signer.key,
    certificate: signer.cert,
    digestAlgorithm: forge.pki.oids.sha256,
    authenticatedAttributes: [
      { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
      { type: forge.pki.oids.messageDigest },
      { type: forge.pki.oids.signingTime, value: new Date() as unknown as string },
    ],
  });
  p7.sign({ detached: true });
  return forge.asn1.toDer(p7.toAsn1()).getBytes();
}

export type Verdict = { status: 'valid' | 'invalid'; signer: string | null; emails: string[]; issuer: string; certificate: string | null; reason?: string };

const DIGESTS: Record<string, 'sha1' | 'sha256' | 'sha384' | 'sha512'> = {
  '1.3.14.3.2.26': 'sha1',
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
};

/** Check a CMS signature over `content` (detached), or over the content it carries. */
export async function verify(signatureDer: string, content: string | null): Promise<Verdict & { content: string }> {
  const forge = await load();
  const asn1 = forge.asn1;
  const p7 = forge.pkcs7.messageFromAsn1(asn1.fromDer(signatureDer)) as unknown as {
    certificates: import('node-forge').pki.Certificate[];
    content?: { bytes(): string };
    rawCapture: { signerInfos: import('node-forge').asn1.Asn1[] };
  };
  const signed = content ?? p7.content?.bytes() ?? '';
  const fail = (reason: string, cert: import('node-forge').pki.Certificate | null = null) => ({
    status: 'invalid' as const, signer: cert ? attribute(cert.subject, 'CN') : null, emails: [], issuer: '', certificate: null, reason, content: signed,
  });
  const info = p7.rawCapture.signerInfos?.[0];
  if (!info) return fail('no signer');
  const fields = info.value as import('node-forge').asn1.Asn1[];
  const sid = fields[1].value as import('node-forge').asn1.Asn1[];
  const serial = forge.util.bytesToHex(sid[1]?.value as string ?? '').replace(/^0+/, '');
  const cert = p7.certificates.find((c) => c.serialNumber.replace(/^0+/, '') === serial) ?? (p7.certificates.length === 1 ? p7.certificates[0] : null);
  if (!cert) return fail('the signer’s certificate is not in the message');
  const digestOid = asn1.derToOid((fields[2].value as import('node-forge').asn1.Asn1[])[0].value as string);
  const name = DIGESTS[digestOid];
  if (!name) return fail('unsupported digest', cert);
  const hash = (data: string) => { const md = forge.md[name].create(); md.update(data); return md; };
  let index = 3;
  let toVerify = hash(signed);
  const attrs = fields[3];
  if (attrs && attrs.tagClass === asn1.Class.CONTEXT_SPECIFIC && attrs.type === 0) {
    index = 4;
    const digest = hash(signed).digest().getBytes();
    const messageDigest = (attrs.value as import('node-forge').asn1.Asn1[]).find((attr) => {
      const parts = attr.value as import('node-forge').asn1.Asn1[];
      return asn1.derToOid(parts[0].value as string) === forge.pki.oids.messageDigest;
    });
    const value = messageDigest && ((messageDigest.value as import('node-forge').asn1.Asn1[])[1].value as import('node-forge').asn1.Asn1[])[0].value;
    if (value !== digest) return fail('the message was changed after it was signed', cert);
    // The signature covers the attributes, DER-encoded as a SET.
    const set = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, attrs.value as import('node-forge').asn1.Asn1[]);
    toVerify = hash(asn1.toDer(set).getBytes());
  }
  const signature = fields[index + 1]?.value as string;
  let ok = false;
  try {
    ok = (cert.publicKey as import('node-forge').pki.rsa.PublicKey).verify(toVerify.digest().getBytes(), signature);
  } catch { ok = false; }
  const described = await certInfo(cert);
  if (!ok) return { ...fail('the signature does not match', cert), signer: described.label };
  const now = Date.now() / 1000;
  return {
    status: 'valid', signer: described.label, emails: described.emails, issuer: described.issuer, certificate: described.pem, content: signed,
    reason: now > described.expires ? 'the certificate has expired' : undefined,
  };
}

/** Decrypt CMS EnvelopedData (DER) with whichever of `keys` it was sent to. */
export async function decrypt(der: string, keys: Unlocked[]): Promise<string> {
  const forge = await load();
  const p7 = forge.pkcs7.messageFromAsn1(forge.asn1.fromDer(der)) as unknown as {
    findRecipient(cert: import('node-forge').pki.Certificate): unknown;
    decrypt(recipient: unknown, key: import('node-forge').pki.rsa.PrivateKey): void;
    content: { bytes(): string };
  };
  for (const unlocked of keys) {
    const recipient = p7.findRecipient(unlocked.cert);
    if (recipient) {
      p7.decrypt(recipient, unlocked.key);
      return p7.content.bytes();
    }
  }
  throw new Error('This message was not encrypted to any of your certificates.');
}

/** `inner` encrypted to the certificates (PEM): CMS EnvelopedData, DER. */
export async function encrypt(inner: string, certificates: string[]): Promise<string> {
  const forge = await load();
  const p7 = forge.pkcs7.createEnvelopedData();
  for (const pem of certificates) p7.addRecipient(forge.pki.certificateFromPem(pem));
  p7.content = forge.util.createBuffer(inner);
  p7.encrypt(undefined, forge.pki.oids['aes256-CBC']);
  return forge.asn1.toDer(p7.toAsn1()).getBytes();
}
