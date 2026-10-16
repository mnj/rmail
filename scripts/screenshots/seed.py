#!/usr/bin/env python3
"""Fill a demo rMail instance with sample mail, routing and queued outbound messages.

Used by capture.sh; expects the services started there (SMTP 2525, submission 2587,
admin console 18080) and the demo password below. Standard library only.
"""

import http.cookiejar
import imaplib
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


def invitation():
    """An iMIP invitation from Priya for next Thursday, 14:00-15:00 UTC."""
    now = time.gmtime()
    days = (3 - now.tm_wday) % 7 or 7
    day = time.gmtime(time.time() + days * 86400)
    date = time.strftime("%Y%m%d", day)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", now)
    lines = [
        "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Northwind//Calendar//EN", "METHOD:REQUEST",
        "BEGIN:VEVENT", "UID:q4-infra-review@northwind.test", f"DTSTAMP:{stamp}", "SEQUENCE:0",
        f"DTSTART:{date}T140000Z", f"DTEND:{date}T150000Z",
        "SUMMARY:Q4 infrastructure review", "LOCATION:Video call (link in description)",
        "DESCRIPTION:Mail migration status\\, ACME\\, deliverability and 2027 capacity.",
        "ORGANIZER;CN=Priya Raman:mailto:priya@northwind.test",
        "ATTENDEE;CN=Priya Raman;PARTSTAT=ACCEPTED:mailto:priya@northwind.test",
        "ATTENDEE;CN=Alice Chen;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:alice@example.com",
        "ATTENDEE;CN=Marcus Lee;PARTSTAT=TENTATIVE:mailto:marcus@contoso.test",
        "ATTENDEE;CN=Bob Hansen;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:bob@example.com",
        "END:VEVENT", "END:VCALENDAR", "",
    ]
    m = message('"Priya Raman" <priya@northwind.test>', "alice@example.com",
                "Invitation: Q4 infrastructure review",
                "Priya Raman invites you to \"Q4 infrastructure review\".", ago=60 * 10)
    m.add_alternative("\r\n".join(lines), subtype="calendar", params={"method": "REQUEST"})
    return m


deliver(invitation())
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

# Bob shares a folder with Alice over IMAP (RFC 4314 SETACL); it shows under
# "Shared with me" in her webmail.
imap = imaplib.IMAP4("127.0.0.1", 1143)
imap.starttls(ssl_context=TLS)
imap.login("bob@example.com", PASSWORD)
imap.create('"Team Projects"')
for subject, body in [
    ("Migration runbook v3", "Steps for the cut-over weekend, with rollback points marked."),
    ("Vendor shortlist", "Three vendors made the shortlist; notes on each are below."),
]:
    m = message('"Bob Hansen" <bob@example.com>', "bob@example.com", subject, body)
    imap.append('"Team Projects"', None, None, m.as_bytes())
imap._simple_command("SETACL", '"Team Projects"', "alice@example.com", "lrs")
imap.logout()

# Alice's address book (CardDAV), for address suggestions while composing.
auth = "Basic " + __import__("base64").b64encode(f"alice@example.com:{PASSWORD}".encode()).decode()
for uid, name, email in [
    ("priya", "Priya Raman", "priya@northwind.test"),
    ("sofia", "Sofia Lind", "sofia@fabrikam.test"),
    ("marcus", "Marcus Okafor", "marcus@contoso.test"),
    ("bob", "Bob Hansen", "bob@example.com"),
]:
    card = f"BEGIN:VCARD\r\nVERSION:4.0\r\nUID:{uid}\r\nFN:{name}\r\nEMAIL:{email}\r\nEND:VCARD\r\n"
    request = urllib.request.Request(
        f"https://127.0.0.1:18081/dav/addressbooks/alice%40example.com/default/{uid}.vcf",
        method="PUT", data=card.encode(),
        headers={"Authorization": auth, "Content-Type": "text/vcard; charset=utf-8"},
    )
    urllib.request.urlopen(request, context=TLS).read()

# A meeting Alice organizes, and Sofia proposing another time for it.
def counter_day(days, hour):
    day = time.gmtime(time.time() + days * 86400)
    return time.strftime(f"%Y%m%dT{hour:02d}0000Z", day)


sync_event = [
    "BEGIN:VEVENT", "UID:fabrikam-sync@example.com", f"DTSTAMP:{counter_day(0, 8)}", "SEQUENCE:0",
    f"DTSTART:{counter_day(2, 10)}", f"DTEND:{counter_day(2, 11)}", "SUMMARY:Fabrikam onboarding sync",
    "ORGANIZER;CN=Alice Chen:mailto:alice@example.com",
    "ATTENDEE;CN=Alice Chen;PARTSTAT=ACCEPTED:mailto:alice@example.com",
    "ATTENDEE;CN=Sofia Lind;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:sofia@fabrikam.test",
    "END:VEVENT",
]
calendar = "\r\n".join(["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//rMail demo//EN", *sync_event, "END:VCALENDAR", ""])
urllib.request.urlopen(urllib.request.Request(
    "https://127.0.0.1:18081/dav/calendars/alice%40example.com/default/fabrikam-sync.ics",
    method="PUT", data=calendar.encode(),
    headers={"Authorization": auth, "Content-Type": "text/calendar; charset=utf-8"},
), context=TLS).read()
proposed = [line.replace(counter_day(2, 10), counter_day(3, 13)).replace(counter_day(2, 11), counter_day(3, 14))
            .replace("PARTSTAT=NEEDS-ACTION", "PARTSTAT=ACCEPTED") for line in sync_event]
proposed.insert(-1, "COMMENT:Could we push it a day? Afternoons work better for our team.")
counter = message('"Sofia Lind" <sofia@fabrikam.test>', "alice@example.com",
                  "New time proposed: Fabrikam onboarding sync",
                  "Sofia Lind proposes a new time for \"Fabrikam onboarding sync\".", ago=60 * 5)
counter.add_alternative("\r\n".join(["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Fabrikam//EN", "METHOD:COUNTER",
                                     *proposed, "END:VCALENDAR", ""]), subtype="calendar", params={"method": "COUNTER"})
deliver(counter)

# Alice opts in to writing suggestions (the demo points them at fake_ai.py).
webmail = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
    urllib.request.HTTPSHandler(context=TLS),
)
for path, method, body in [
    ("/api/login", "POST", {"address": "alice@example.com", "password": PASSWORD}),
    ("/api/compose/settings", "PUT", {"format": "html", "language": "", "undo_seconds": 0, "ai_suggestions": True}),
]:
    webmail.open(urllib.request.Request(
        "https://127.0.0.1:18081" + path, method=method, data=json.dumps(body).encode(),
        headers={"X-Rmail-Webmail": "1", "Content-Type": "application/json"},
    )).read()

print("seeded demo data")
