#!/usr/bin/env python3
"""Fill a demo rMail instance with sample mail, routing and queued outbound messages.

Used by capture.sh; expects the services started there (SMTP 2525, submission 2587,
admin console 18080) and the demo password below. Standard library only.
"""

import http.cookiejar
import json
import smtplib
import ssl
import time
import urllib.request
from email.message import EmailMessage
from email.utils import formatdate

PASSWORD = "Demo-pass-123"
ADMIN = "https://127.0.0.1:18080"
TLS = ssl._create_unverified_context()  # the demo uses a throwaway self-signed certificate


def message(frm, to, subject, body, html=None, ago=0):
    m = EmailMessage()
    m["From"] = frm
    m["To"] = to
    m["Subject"] = subject
    m["Date"] = formatdate(time.time() - ago, localtime=True)
    m.set_content(body)
    if html:
        m.add_alternative(html, subtype="html")
    return m


def deliver(m):
    with smtplib.SMTP("127.0.0.1", 2525) as s:
        s.ehlo()
        s.send_message(m, mail_options=["BODY=8BITMIME"])


def submit(m):
    with smtplib.SMTP("127.0.0.1", 2587) as s:
        s.starttls(context=TLS)
        s.login("alice@example.com", PASSWORD)
        s.send_message(m, mail_options=["BODY=8BITMIME"])


NEWSLETTER = """<div style="font-family:system-ui,sans-serif;max-width:560px;margin:auto">
<img src="https://tracker.northwind.test/pixel.gif" width="1" height="1">
<h1 style="color:#b45309">Northwind Weekly</h1>
<img src="https://cdn.northwind.test/banner.png" width="560" height="160" alt="Banner">
<h2>Rust 2024 edition in production</h2>
<p>How three teams moved their services to the 2024 edition, and what they learned about async closures along the way.</p>
<p><a href="https://northwind.test/read">Read the full story &rarr;</a></p>
</div>"""

INBOX = [
    ('"Priya Raman" <priya@northwind.test>', "Q4 infrastructure review — agenda",
     "Hi Alice,\n\nAttached is the draft agenda for Thursday's infrastructure review:\n\n"
     "  1. Mail server migration status\n  2. TLS certificate automation (ACME)\n"
     "  3. Outbound deliverability: SPF, DKIM and DMARC reports\n  4. Capacity planning for 2027\n\n"
     "Let me know if you want to add anything before I send the invite.\n\nThanks,\nPriya", None, 60 * 14),
    ('"Marcus Lee" <marcus@contoso.test>', "Re: IMAP IDLE on mobile clients",
     "Confirmed — push works on both iOS Mail and K-9 now. IDLE keepalives come through every few "
     "minutes and the battery hit is negligible.\n\nMarcus", None, 60 * 55),
    ('"Northwind Weekly" <news@northwind.test>', "This week: Rust 2024 edition in production",
     "View this newsletter in an HTML-capable client.", NEWSLETTER, 60 * 60 * 3),
    ('"Bob Hansen" <bob@example.com>', "Lunch Friday?",
     "The new ramen place on 5th opened. 12:30?\n\n— Bob", None, 60 * 60 * 5),
    ('"GitHub" <noreply@github.test>', "[rmail] CI passed on main",
     "All checks have passed.\n\n  rust (fmt, clippy, test)   ✓\n  frontends (webui)          ✓\n"
     "  frontends (webmail)        ✓\n", None, 60 * 60 * 8),
    ('"Sofia Martins" <sofia@fabrikam.test>', "Contract renewal for 2027",
     "Hi Alice,\n\nOur current hosting contract ends on 31 December. I've attached the renewal terms — "
     "the main change is the move to a per-mailbox quota model.\n\nBest regards,\nSofia", None, 60 * 60 * 26),
    ('"DMARC Reports" <dmarc@reports.test>', "Report domain: example.com Submitter: reports.test",
     "Aggregate DMARC report attached.\n\n  pass: 1,284\n  fail: 3\n", None, 60 * 60 * 30),
    ('"Jonas Berg" <jonas@contoso.test>', "Photos from the offsite",
     "Uploaded everything to the shared album. The one of the server rack cake is my favourite.\n\nJonas",
     None, 60 * 60 * 50),
]

for frm, subject, body, html, ago in INBOX:
    deliver(message(frm, "alice@example.com", subject, body, html, ago))
deliver(message('"Alice Chen" <alice@example.com>', "support@example.com",
                "Customer escalation: delayed invoices", "Can someone look at ticket 4411?"))
deliver(message('"Monitoring" <alerts@example.org>', "ops@example.org",
                "Disk usage 71% on mx1", "Warning threshold reached."))

# Aliases and a catchall through the admin API.
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
    urllib.request.HTTPSHandler(context=TLS),
)


def admin(path, method, body):
    request = urllib.request.Request(
        ADMIN + path, method=method, data=json.dumps(body).encode(),
        headers={"X-Rmail-Admin": "1", "Content-Type": "application/json"},
    )
    opener.open(request).read()


admin("/api/login", "POST", {"username": "admin", "password": PASSWORD})
admin("/api/routing/alias", "POST", {"address": "hello@example.com", "targets": ["alice@example.com", "bob@example.com"]})
admin("/api/routing/alias", "POST", {"address": "postmaster@example.com", "targets": ["ops@example.org"]})
admin("/api/routing/alias", "POST", {"address": "billing@example.com", "targets": ["support@example.com"]})
admin("/api/routing/catchall", "POST", {"domain": "example.org", "target": "ops@example.org"})

# Authenticated submission to .test domains: they never resolve, so the messages stay queued.
for to, subject in [
    ("priya@northwind.test", "Re: Q4 infrastructure review — agenda"),
    ("sofia@fabrikam.test", "Re: Contract renewal for 2027"),
    ("marcus@contoso.test", "IMAP rollout checklist"),
]:
    submit(message("alice@example.com", to, subject, "Thanks — see my notes inline.\n\nAlice"))

print("seeded demo data")
