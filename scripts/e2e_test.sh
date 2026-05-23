#!/usr/bin/env bash
set -euo pipefail

export RMAIL_CONFIG=config/test.toml
export RUST_BACKTRACE=1

cleanup() {
  echo "Stopping services..."
  pkill -f rmail_smtpd || true
  pkill -f rmail_imapd || true
  pkill -f rmail_web || true
  rm -f /tmp/rmail_smtpd.pid /tmp/rmail_imapd.pid /tmp/rmail_web.pid || true
}
trap cleanup EXIT

# ensure a clean maildir
rm -rf mail_test

# start services
cargo run -p rmail_smtpd > /tmp/rmail_smtpd.log 2>&1 & echo $! > /tmp/rmail_smtpd.pid
sleep 0.5
cargo run -p rmail_imapd > /tmp/rmail_imapd.log 2>&1 & echo $! > /tmp/rmail_imapd.pid
sleep 0.5
cargo run -p rmail_web > /tmp/rmail_web.log 2>&1 & echo $! > /tmp/rmail_web.pid
sleep 1

# send a test message
printf 'EHLO localhost\r\nMAIL FROM:<sender@local>\r\nRCPT TO:<user@example.local>\r\nDATA\r\nSubject: E2E test\r\n\r\nHello e2e\r\n.\r\nQUIT\r\n' | nc 127.0.0.1 2525 -w 5 || true
sleep 0.5

# check maildir
if [ ! -d mail_test/example.local/user/Maildir/new ]; then
  echo "Maildir not created"; exit 2
fi
if [ -z "$(ls mail_test/example.local/user/Maildir/new 2>/dev/null)" ]; then
  echo "No message in Maildir"; exit 3
fi

# imap check
printf 'A001 LOGIN "user@example.local" "password"\r\nA002 SELECT INBOX\r\nA003 LOGOUT\r\n' | nc 127.0.0.1 1143 -w 5 > /tmp/e2e_imap.out || true
if ! grep -q "A002 OK" /tmp/e2e_imap.out; then
  echo "IMAP select failed"; cat /tmp/e2e_imap.out; exit 4
fi

# web UI check
curl -sS http://127.0.0.1:18080/health | grep -q ok

echo "E2E test succeeded"
