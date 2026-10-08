#!/usr/bin/env bash
# Store the settings of the local test instance (config/test.toml): loopback
# listeners on non-privileged ports, the development certificate and debug
# logging. Run after `rmail_ctl init-db`; safe to run again.
set -euo pipefail
config="${1:-config/test.toml}"
ctl="${RMAIL_CTL:-./target/debug/rmail_ctl}"
set_setting() { "${ctl}" settings set "$1" "$2" --config "${config}" >/dev/null; }

set_setting global.log_level debug
set_setting global.tls_cert config/certs/localhost.crt
set_setting global.tls_key config/certs/localhost.key
set_setting global.tcp_listener.reuse_port false
set_setting global.tcp_listener.backlog 128
set_setting global.tcp_listener.ipv6_only true
set_setting global.listeners.smtp '["127.0.0.1:2525", "[::1]:2525"]'
set_setting global.listeners.smtps '["127.0.0.1:2465", "[::1]:2465"]'
set_setting global.listeners.submission '["127.0.0.1:2587", "[::1]:2587"]'
set_setting global.listeners.imap '["127.0.0.1:1143", "[::1]:1143"]'
set_setting global.listeners.imaps '["127.0.0.1:1993", "[::1]:1993"]'
set_setting global.listeners.admin '["127.0.0.1:18080"]'
set_setting global.listeners.webmail '["127.0.0.1:18081"]'
echo "Stored test settings in the database named by ${config}"
