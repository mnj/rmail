"""Check the mail webmail signed and encrypted in the browser with the
standard tools: GnuPG verifies the OpenPGP signature and lists who the
encrypted message is for, OpenSSL verifies and decrypts the S/MIME ones.

Usage: crypto_check.py DEMO_DIR (with crypto/*.eml and alice.asc left by
capture.mjs, and alice-smime.key/pem from capture.sh).
"""

import email
import email.policy
import os
import subprocess
import sys
import tempfile

demo = sys.argv[1]
crypto = os.path.join(demo, "crypto")


def run(*args, **kwargs):
    result = subprocess.run(args, capture_output=True, **kwargs)
    if result.returncode != 0:
        sys.exit(f"FAILED: {' '.join(args)}\n{result.stdout.decode(errors='replace')}\n{result.stderr.decode(errors='replace')}")
    return result


def raw(name):
    with open(os.path.join(crypto, name), "rb") as f:
        return f.read()


def signed_parts(data):
    """The exact bytes of the first part of a multipart/signed body, and the signature part's payload."""
    message = email.message_from_bytes(data, policy=email.policy.compat32)
    boundary = message.get_boundary().encode()
    body = data.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in data else data.split(b"\n\n", 1)[1]
    delimiter = b"--" + boundary
    pieces = body.split(delimiter)
    first = pieces[1]
    first = first[first.index(b"\n") + 1:]
    first = first[:-2] if first.endswith(b"\r\n") else first[:-1]
    signature = message.get_payload()[1].get_payload(decode=True)
    return first, signature


with tempfile.TemporaryDirectory() as home:
    env = dict(os.environ, GNUPGHOME=home)
    run("gpg", "--batch", "--import", os.path.join(crypto, "alice.asc"), env=env)
    signed, signature = signed_parts(raw("pgp-signed.eml"))
    with open(os.path.join(home, "part"), "wb") as f:
        f.write(signed)
    with open(os.path.join(home, "part.asc"), "wb") as f:
        f.write(signature)
    out = run("gpg", "--batch", "--status-fd", "1", "--verify", os.path.join(home, "part.asc"), os.path.join(home, "part"), env=env)
    assert b"GOODSIG" in out.stdout, out.stdout
    print("OpenPGP/MIME signature: good (GnuPG)")

    encrypted = email.message_from_bytes(raw("pgp-encrypted.eml"), policy=email.policy.compat32)
    assert encrypted.get_content_type() == "multipart/encrypted"
    armored = encrypted.get_payload()[1].get_payload(decode=True)
    packets = subprocess.run(["gpg", "--batch", "--list-packets"], input=armored, capture_output=True, env=env)
    assert b"pubkey enc packet" in packets.stdout + packets.stderr, packets
    print("OpenPGP/MIME encrypted: well-formed, encrypted to a public key (GnuPG)")

key = os.path.join(demo, "alice-smime.key")
cert = os.path.join(demo, "alice-smime.pem")
out = run("openssl", "smime", "-verify", "-noverify", "-in", os.path.join(crypto, "smime-signed.eml"))
assert b"Signed with a certificate." in out.stdout.replace(b"=\r\n", b"").replace(b"=\n", b""), out.stdout
print("S/MIME signature: good (OpenSSL)")
decrypted = run("openssl", "smime", "-decrypt", "-recip", cert, "-inkey", key, "-in", os.path.join(crypto, "smime-encrypted.eml")).stdout
verified = run("openssl", "smime", "-verify", "-noverify", input=decrypted).stdout
assert b"Sealed with S/MIME." in verified, verified
print("S/MIME encrypted and signed: decrypted and verified (OpenSSL)")
