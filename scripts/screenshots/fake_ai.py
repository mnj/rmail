#!/usr/bin/env python3
"""A stand-in OpenAI-compatible Chat Completions endpoint for the screenshot demo.

Webmail's writing suggestions (compose_ai.* settings) point here, so the ghost
text and rewrite shots need no real AI service. Canned answers; standard
library only. Usage: fake_ai.py PORT
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONTINUATION = " the DMARC report numbers, so we can decide on p=reject before the cut-over?"
REWRITE = "Thank you for the agenda. I have a few notes to share before Thursday's review."


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length) or b"{}")
        system = request.get("messages", [{}])[0].get("content", "")
        text = REWRITE if "rewrite" in system else CONTINUATION
        body = json.dumps({"choices": [{"message": {"role": "assistant", "content": text}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
