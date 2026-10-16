// MIME pieces for signed and encrypted mail (RFC 1847, RFC 3156 for
// OpenPGP, RFC 8551 for S/MIME): finding the exact signed bytes, and
// wrapping a body the server built into a signed or encrypted one.
//
// Messages are handled as "binary strings" (one char per byte), so the
// bytes a signature covers stay exactly as received.

export function bytesToBinary(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 0x8000) out += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return out;
}

export function binaryToBytes(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
  return out;
}

/** Text with every line ending CRLF. */
export function crlf(text: string): string {
  return text.replace(/\r?\n/g, '\r\n');
}

type Entity = { headers: Map<string, string>; body: string };

/** Split an entity into its (unfolded, lower-cased) headers and body. */
export function parseEntity(text: string): Entity {
  const match = /\r?\n\r?\n/.exec(text);
  const head = match ? text.slice(0, match.index) : text;
  const body = match ? text.slice(match.index + match[0].length) : '';
  const headers = new Map<string, string>();
  let last = '';
  for (const line of head.split(/\r?\n/)) {
    if (/^[ \t]/.test(line) && last) {
      headers.set(last, `${headers.get(last)} ${line.trim()}`);
      continue;
    }
    const colon = line.indexOf(':');
    if (colon <= 0) continue;
    last = line.slice(0, colon).trim().toLowerCase();
    headers.set(last, line.slice(colon + 1).trim());
  }
  return { headers, body };
}

/** A parameter of a header value (`boundary`, `protocol`...). */
export function param(value: string | undefined, name: string): string | undefined {
  if (!value) return undefined;
  const re = new RegExp(`;\\s*${name}\\s*=\\s*("([^"]*)"|[^;\\s]+)`, 'i');
  const match = re.exec(value);
  return match ? (match[2] ?? match[1]) : undefined;
}

/** The parts of a multipart body, each exactly as it stands between the delimiters. */
export function multipartParts(entity: Entity): string[] {
  const boundary = param(entity.headers.get('content-type'), 'boundary');
  if (!boundary) return [];
  const delimiter = `--${boundary}`;
  const body = entity.body;
  const parts: string[] = [];
  let at = body.startsWith(delimiter) ? 0 : body.indexOf(`\n${delimiter}`);
  if (at < 0) return [];
  if (at > 0) at += 1;
  for (;;) {
    const lineEnd = body.indexOf('\n', at);
    if (lineEnd < 0) break;
    if (body.slice(at + delimiter.length, at + delimiter.length + 2) === '--') break;
    const next = body.indexOf(`\n${delimiter}`, lineEnd);
    if (next < 0) break;
    // The line break before a delimiter belongs to the delimiter.
    const end = body[next - 1] === '\r' ? next - 1 : next;
    parts.push(body.slice(lineEnd + 1, end));
    at = next + 1;
  }
  return parts;
}

/** The decoded body of an entity (base64 or as it is), as a binary string. */
export function decodedBody(entity: Entity): string {
  const encoding = (entity.headers.get('content-transfer-encoding') || '').toLowerCase();
  if (encoding === 'base64') return atob(entity.body.replace(/[^A-Za-z0-9+/=]/g, ''));
  return entity.body;
}

/** A detached signature's two halves: the signed part and the signature. */
export function splitSigned(raw: string): { signed: string; signature: string } | null {
  const message = parseEntity(raw);
  const parts = multipartParts(message);
  if (parts.length < 2) return null;
  return { signed: parts[0], signature: decodedBody(parseEntity(parts[1])) };
}

/** The encrypted payload of a message: the armored PGP/MIME part, or S/MIME's DER. */
export function encryptedPayload(raw: string): string | null {
  const message = parseEntity(raw);
  const type = (message.headers.get('content-type') || '').toLowerCase();
  if (type.startsWith('multipart/encrypted')) {
    const parts = multipartParts(message);
    return parts.length >= 2 ? decodedBody(parseEntity(parts[1])) : null;
  }
  return decodedBody(message);
}

function boundary(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  return `=_rmail_${Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')}`;
}

function base64Lines(binary: string): string {
  return (btoa(binary).match(/.{1,76}/g) || []).join('\r\n') + '\r\n';
}

/**
 * The bytes a detached signature covers for `inner`: the part as it will
 * stand in the multipart/signed body, without the line break before the
 * next boundary (RFC 1847 2.1).
 */
export function signedBytes(inner: string): string {
  return inner.endsWith('\r\n') ? inner.slice(0, -2) : inner;
}

/** `inner` with a detached signature (made over `signedBytes(inner)`) around it. */
export function signedEntity(inner: string, signature: string, kind: 'pgp' | 'smime'): string {
  const b = boundary();
  const head = kind === 'pgp'
    ? `Content-Type: multipart/signed; micalg=pgp-sha256;\r\n protocol="application/pgp-signature"; boundary="${b}"`
    : `Content-Type: multipart/signed; micalg=sha-256;\r\n protocol="application/pkcs7-signature"; boundary="${b}"`;
  const signaturePart = kind === 'pgp'
    ? `Content-Type: application/pgp-signature; name="signature.asc"\r\nContent-Description: OpenPGP digital signature\r\nContent-Disposition: attachment; filename="signature.asc"\r\n\r\n${crlf(signature).replace(/(\r\n)?$/, '\r\n')}`
    : `Content-Type: application/pkcs7-signature; name="smime.p7s"\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename="smime.p7s"\r\n\r\n${base64Lines(signature)}`;
  const body = signedBytes(inner);
  return `${head}\r\n\r\nThis is an OpenPGP/MIME or S/MIME signed message.\r\n--${b}\r\n${body}\r\n--${b}\r\n${signaturePart}--${b}--\r\n`;
}

/** An OpenPGP/MIME encrypted entity (RFC 3156 4). */
export function pgpEncryptedEntity(armored: string): string {
  const b = boundary();
  return `Content-Type: multipart/encrypted;\r\n protocol="application/pgp-encrypted"; boundary="${b}"\r\n\r\n`
    + `This is an OpenPGP/MIME encrypted message.\r\n--${b}\r\nContent-Type: application/pgp-encrypted\r\nContent-Description: PGP/MIME version identification\r\n\r\nVersion: 1\r\n\r\n`
    + `--${b}\r\nContent-Type: application/octet-stream; name="encrypted.asc"\r\nContent-Description: OpenPGP encrypted message\r\nContent-Disposition: inline; filename="encrypted.asc"\r\n\r\n${crlf(armored).replace(/(\r\n)?$/, '\r\n')}--${b}--\r\n`;
}

/** An S/MIME enveloped entity from the CMS EnvelopedData (DER, binary string). */
export function smimeEncryptedEntity(der: string): string {
  return `Content-Type: application/pkcs7-mime; smime-type=enveloped-data;\r\n name="smime.p7m"\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename="smime.p7m"\r\n\r\n${base64Lines(der)}`;
}

export type Shown = {
  text: string;
  html: string | null;
  attachments: { filename: string; mimeType: string; contentId: string | null; inline: boolean; content: Uint8Array }[];
};

/** A decrypted entity as the reader shows it. */
export async function readEntity(entity: string): Promise<Shown> {
  const PostalMime = (await import('postal-mime')).default;
  const parsed = await PostalMime.parse(binaryToBytes(entity));
  return {
    text: parsed.text ?? '',
    html: parsed.html ?? null,
    attachments: parsed.attachments.map((attachment, index) => ({
      filename: attachment.filename || `attachment-${index + 1}`,
      mimeType: attachment.mimeType,
      contentId: attachment.contentId ? attachment.contentId.replace(/^<|>$/g, '') : null,
      inline: attachment.disposition === 'inline' || Boolean(attachment.related),
      content: typeof attachment.content === 'string'
        ? new TextEncoder().encode(attachment.content)
        : new Uint8Array(attachment.content as ArrayBuffer),
    })),
  };
}

/** How an entity is protected (the same judgement as the server's). */
export function protectionOf(entity: string): string | null {
  const parsed = parseEntity(entity);
  const value = parsed.headers.get('content-type') || 'text/plain';
  const type = value.split(';')[0].trim().toLowerCase();
  const protocol = (param(value, 'protocol') || '').toLowerCase();
  if (type === 'multipart/encrypted' && protocol === 'application/pgp-encrypted') return 'pgp-encrypted';
  if (type === 'multipart/signed' && protocol === 'application/pgp-signature') return 'pgp-signed';
  if (type === 'multipart/signed' && /^application\/(x-)?pkcs7-signature$/.test(protocol)) return 'smime-signed';
  if (/^application\/(x-)?pkcs7-mime$/.test(type)) {
    return (param(value, 'smime-type') || '').toLowerCase() === 'signed-data' ? 'smime-opaque' : 'smime-encrypted';
  }
  return null;
}
