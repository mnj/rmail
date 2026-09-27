#!/usr/bin/env bash
# Regenerate the screenshots used by the project site (site/assets/screenshots).
#
# Builds the daemons and both frontends, starts a throwaway demo instance on
# loopback ports in a temporary directory, fills it with sample data (seed.py)
# and captures the admin console and webmail with Playwright (capture.mjs).
#
# Requires: cargo, bun, python3, openssl. Chromium is downloaded by Playwright
# unless CHROMIUM_PATH points at an existing binary.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "${here}/../.." && pwd)"
out="${1:-${root}/site/assets/screenshots}"
mkdir -p "${out}"
out="$(cd "${out}" && pwd)"

cd "${root}"
cargo build --bins
for app in webui webmail; do
  (cd "crates/${app}/frontend" && bun install --frozen-lockfile && bun run build)
done
(cd "${here}" && bun install --frozen-lockfile)
if [[ -z "${CHROMIUM_PATH:-}" ]]; then
  (cd "${here}" && bunx playwright install chromium)
fi

demo="$(mktemp -d)"
pids=()
cleanup() {
  for pid in "${pids[@]}"; do kill "${pid}" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf -- "${demo}"
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 7 -subj /CN=mail.example.com \
  -keyout "${demo}/key.pem" -out "${demo}/cert.pem" 2>/dev/null
# Relative paths: the services run from ${demo}, and the console shows the
# config path, so this keeps the temporary directory name out of the shots.
cat > "${demo}/config.toml" <<TOML
[global]
mail_root = "mail"
db_path = "rmail.db"
log_level = "info"
tls_cert = "cert.pem"
tls_key = "key.pem"

[global.listeners]
smtp = ["127.0.0.1:2525"]
submission = ["127.0.0.1:2587"]
imap = ["127.0.0.1:1143"]
admin = ["127.0.0.1:18080"]
webmail = ["127.0.0.1:18081"]
TOML

bin="${root}/target/debug"
ctl="${bin}/rmail_ctl"
cd "${demo}"
"${ctl}" init-db --config config.toml >/dev/null
for mailbox in alice@example.com bob@example.com support@example.com ops@example.org; do
  "${ctl}" add-mailbox "${mailbox}" --password Demo-pass-123 --config config.toml >/dev/null
done
"${ctl}" admin-password --password Demo-pass-123 --config config.toml >/dev/null

export RMAIL_CONFIG=config.toml RMAIL_MAIL_ROOT=mail
export RMAIL_WEB_STATIC_DIR="${root}/crates/webui/frontend/dist"
export RMAIL_WEBMAIL_STATIC_DIR="${root}/crates/webmail/frontend/dist"
for service in smtpd imapd web webmail outbound; do
  "${bin}/rmail_${service}" > "${service}.log" 2>&1 &
  pids+=("$!")
done

for _ in $(seq 1 50); do
  curl -skf https://127.0.0.1:18080/health >/dev/null && curl -skf https://127.0.0.1:18081/ >/dev/null && break
  sleep 0.2
done

python3 "${here}/seed.py"
(cd "${here}" && node capture.mjs "${out}")
echo "Screenshots written to ${out}"
