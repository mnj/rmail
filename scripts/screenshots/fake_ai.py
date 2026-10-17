#!/usr/bin/env python3
"""A stand-in OpenAI-compatible Chat Completions endpoint for the screenshot demo.

Webmail's writing suggestions (compose_ai.* settings) point here, so the ghost
text and rewrite shots need no real AI service. Canned answers; standard
library only. It is also a single sign-on provider (OpenID Connect) that
signs anyone in as Alice. Usage: fake_ai.py PORT
"""

import base64
import datetime
import json
import time
import urllib.parse
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONTINUATION = " the DMARC report numbers, so we can decide on p=reject before the cut-over?"
REWRITE = "Thank you for the agenda. I have a few notes to share before Thursday's review."


SUMMARY = "Priya shares the draft agenda for Thursday's infrastructure review and asks for additions before she sends the invite."


def extraction(system):
    """Thursday's review from the agenda mail, dated from when it was sent."""
    sent = re.search(r"sent on \w+ (\d{4}-\d{2}-\d{2})", system)
    day = datetime.date.fromisoformat(sent.group(1)) if sent else datetime.date.today()
    thursday = day + datetime.timedelta(days=(3 - day.weekday()) % 7 or 7)
    return json.dumps({
        "events": [{"title": "Q4 infrastructure review", "date": thursday.isoformat(), "start": "14:00",
                    "end": "15:00", "location": "Video call"}],
        "contact": {"name": "Priya Raman", "email": "priya@northwind.test", "phone": "+45 3312 4455",
                    "organization": "Northwind Traders", "title": "Infrastructure Lead"},
    })


# Embeddings: words that mean much the same land on one dimension, the rest
# are hashed, so "boat trip" is close to the sailing club's mail.
CONCEPTS = [
    {"boat", "boats", "sailing", "sail", "regatta", "harbour", "harbor", "marina", "yacht", "club"},
    {"invoice", "invoices", "payment", "bill", "billing", "paid", "amount", "receipt"},
    {"trip", "travel", "flight", "hotel", "booking", "journey"},
    {"meeting", "agenda", "review", "call", "invite", "invitation"},
]
DIMENSIONS = 64


def embed(text):
    vector = [0.0] * DIMENSIONS
    for word in re.findall(r"[a-z]+", text.lower()):
        concept = next((i for i, words in enumerate(CONCEPTS) if word in words), None)
        if concept is not None:
            vector[concept] += 1.0
        else:
            vector[len(CONCEPTS) + sum(map(ord, word)) % (DIMENSIONS - len(CONCEPTS))] += 0.2
    norm = sum(v * v for v in vector) ** 0.5 or 1.0
    return [v / norm for v in vector]


ISSUER = f"http://127.0.0.1:{sys.argv[1]}"


def id_token(nonce):
    def part(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
    claims = {"iss": ISSUER, "aud": "rmail-demo", "exp": int(time.time()) + 300, "nonce": nonce,
              "email": "alice@example.com", "email_verified": True}
    return f"{part({'alg': 'none'})}.{part(claims)}.x"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        if url.path == "/.well-known/openid-configuration":
            return self.reply({"issuer": ISSUER, "authorization_endpoint": f"{ISSUER}/auth",
                               "token_endpoint": f"{ISSUER}/token"})
        if url.path == "/auth":
            # Signed in at once; the nonce rides along as the code.
            query = dict(urllib.parse.parse_qsl(url.query))
            back = query["redirect_uri"] + "?" + urllib.parse.urlencode({"code": query["nonce"], "state": query["state"]})
            self.send_response(302)
            self.send_header("Location", back)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        if self.path == "/token":
            form = dict(urllib.parse.parse_qsl(raw.decode()))
            return self.reply({"id_token": id_token(form["code"]), "access_token": "demo"})
        request = json.loads(raw or b"{}")
        if self.path.endswith("/embeddings"):
            texts = request.get("input", [])
            texts = [texts] if isinstance(texts, str) else texts
            return self.reply({"data": [{"index": i, "embedding": embed(t)} for i, t in enumerate(texts)]})
        system = request.get("messages", [{}])[0].get("content", "")
        if "find (1) events" in system:
            text = extraction(system)
        elif system.startswith("Summarize"):
            text = SUMMARY
        else:
            text = REWRITE if "rewrite" in system else CONTINUATION
        self.reply({"choices": [{"message": {"role": "assistant", "content": text}}]})

    def reply(self, value):
        body = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
