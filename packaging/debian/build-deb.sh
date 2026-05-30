#!/usr/bin/env bash
set -euo pipefail

if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "dpkg-deb is required to build the package" >&2
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required to build the Rust binaries" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="${1:-0.1.0}"
ARCH="${2:-amd64}"
TARGET_TRIPLE="${3:-}"
PKG_ROOT="${ROOT_DIR}/target/debian/rmail_${VERSION}_${ARCH}"
RELEASE_DIR="${ROOT_DIR}/target/release"

cd "${ROOT_DIR}"

if [[ -n "${TARGET_TRIPLE}" ]]; then
  cargo build --release --target "${TARGET_TRIPLE}"
  RELEASE_DIR="${ROOT_DIR}/target/${TARGET_TRIPLE}/release"
else
  cargo build --release
fi

rm -rf "${PKG_ROOT}"
mkdir -p \
  "${PKG_ROOT}/DEBIAN" \
  "${PKG_ROOT}/usr/bin" \
  "${PKG_ROOT}/usr/lib/systemd/system" \
  "${PKG_ROOT}/etc/rmail" \
  "${PKG_ROOT}/etc/default" \
  "${PKG_ROOT}/var/lib/rmail" \
  "${PKG_ROOT}/var/log/rmail"

install -m 0755 "${RELEASE_DIR}/rmail_smtpd" "${PKG_ROOT}/usr/bin/rmail_smtpd"
install -m 0755 "${RELEASE_DIR}/rmail_imapd" "${PKG_ROOT}/usr/bin/rmail_imapd"
install -m 0755 "${RELEASE_DIR}/rmail_web" "${PKG_ROOT}/usr/bin/rmail_web"
install -m 0755 "${RELEASE_DIR}/rmail_outbound" "${PKG_ROOT}/usr/bin/rmail_outbound"
install -m 0644 "${ROOT_DIR}/packaging/systemd/rmail_smtpd.service" "${PKG_ROOT}/usr/lib/systemd/system/rmail_smtpd.service"
install -m 0644 "${ROOT_DIR}/packaging/systemd/rmail_imapd.service" "${PKG_ROOT}/usr/lib/systemd/system/rmail_imapd.service"
install -m 0644 "${ROOT_DIR}/packaging/systemd/rmail_web.service" "${PKG_ROOT}/usr/lib/systemd/system/rmail_web.service"
install -m 0644 "${ROOT_DIR}/packaging/systemd/rmail_outbound.service" "${PKG_ROOT}/usr/lib/systemd/system/rmail_outbound.service"
install -m 0644 "${ROOT_DIR}/packaging/systemd/rmail.env" "${PKG_ROOT}/etc/default/rmail"
install -m 0644 "${ROOT_DIR}/config/example.toml" "${PKG_ROOT}/etc/rmail/config.toml"

cat > "${PKG_ROOT}/DEBIAN/control" <<EOF
Package: rmail
Version: ${VERSION}
Section: mail
Priority: optional
Architecture: ${ARCH}
Maintainer: rMail Maintainers <noreply@example.invalid>
Depends: systemd
Description: rMail SMTP, IMAP, web, and outbound daemons
 Minimal Rust mail stack packaged for systemd-based Linux distributions.
EOF

cat > "${PKG_ROOT}/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if ! getent group rmail >/dev/null 2>&1; then
  addgroup --system rmail
fi
if ! id -u rmail >/dev/null 2>&1; then
  adduser --system --ingroup rmail --home /var/lib/rmail --no-create-home --disabled-login rmail
fi
mkdir -p /var/lib/rmail /var/log/rmail /etc/rmail
chown -R rmail:rmail /var/lib/rmail /var/log/rmail
systemctl daemon-reload || true
EOF
chmod 0755 "${PKG_ROOT}/DEBIAN/postinst"

cat > "${PKG_ROOT}/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
systemctl stop rmail_outbound.service rmail_web.service rmail_imapd.service rmail_smtpd.service >/dev/null 2>&1 || true
EOF
chmod 0755 "${PKG_ROOT}/DEBIAN/prerm"

cat > "${PKG_ROOT}/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
systemctl daemon-reload || true
EOF
chmod 0755 "${PKG_ROOT}/DEBIAN/postrm"

OUT_DEB="${ROOT_DIR}/target/debian/rmail_${VERSION}_${ARCH}.deb"
dpkg-deb --build "${PKG_ROOT}" "${OUT_DEB}"
echo "Built ${OUT_DEB}"
