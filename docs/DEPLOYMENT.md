# Deployment Guide

This document covers:

- installing `rmail_*` daemons as systemd services on Ubuntu 24.04 or newer
- building a `.deb` package from this repository, even if your development host is not Debian-based

## Overview

The daemons are:

- `rmail_smtpd`: inbound SMTP
- `rmail_imapd`: IMAP
- `rmail_web`: admin/status web UI
- `rmail_outbound`: outbound queue worker

Administrative tools:

- `rmail_ctl`: mailbox/password/cert management CLI
- `rmail_queuectl`: queue and alias management CLI

The runtime model is:

- configuration lives in `/etc/rmail/config.toml`
- service environment lives in `/etc/default/rmail`
- mail and queue state live under `/var/lib/rmail`
- logs can be read from `journalctl`; the units also allow `/var/log/rmail` if you later add file logging

## Manual Install On Ubuntu 24.04+

### 1. Build the binaries

From the repository root:

```bash
cargo build --release
```

### 2. Create the service user and directories

```bash
sudo addgroup --system rmail
sudo adduser --system --ingroup rmail --home /var/lib/rmail --no-create-home --disabled-login rmail
sudo install -d -o rmail -g rmail /var/lib/rmail /var/log/rmail /etc/rmail
```

### 3. Install binaries

```bash
sudo install -m 0755 target/release/rmail_smtpd /usr/bin/rmail_smtpd
sudo install -m 0755 target/release/rmail_imapd /usr/bin/rmail_imapd
sudo install -m 0755 target/release/rmail_web /usr/bin/rmail_web
sudo install -m 0755 target/release/rmail_outbound /usr/bin/rmail_outbound
sudo install -m 0755 target/release/rmail_ctl /usr/bin/rmail_ctl
sudo install -m 0755 target/release/rmail_queuectl /usr/bin/rmail_queuectl
```

### 4. Install config and environment files

```bash
sudo install -m 0644 config/example.toml /etc/rmail/config.toml
sudo install -m 0644 packaging/systemd/rmail.env /etc/default/rmail
```

Then edit both files:

- set real domains, passwords, cert paths, and ports in `/etc/rmail/config.toml`
- set `RMAIL_CONFIG=/etc/rmail/config.toml` in `/etc/default/rmail`
- set `RMAIL_MAIL_ROOT=/var/lib/rmail` in `/etc/default/rmail`

Important:

- `rmail_outbound` reads `RMAIL_MAIL_ROOT`; it does not read the TOML file directly
- `rmail_web` currently binds to `127.0.0.1` by default, which is a safer default for admin access

### 5. Install systemd units

```bash
sudo install -m 0644 packaging/systemd/rmail_smtpd.service /usr/lib/systemd/system/rmail_smtpd.service
sudo install -m 0644 packaging/systemd/rmail_imapd.service /usr/lib/systemd/system/rmail_imapd.service
sudo install -m 0644 packaging/systemd/rmail_web.service /usr/lib/systemd/system/rmail_web.service
sudo install -m 0644 packaging/systemd/rmail_outbound.service /usr/lib/systemd/system/rmail_outbound.service
sudo systemctl daemon-reload
```

### 6. Enable and start services

```bash
sudo systemctl enable --now rmail_smtpd.service
sudo systemctl enable --now rmail_imapd.service
sudo systemctl enable --now rmail_web.service
sudo systemctl enable --now rmail_outbound.service
```

### 7. Verify

```bash
sudo systemctl status rmail_smtpd.service rmail_imapd.service rmail_web.service rmail_outbound.service
journalctl -u rmail_smtpd.service -u rmail_imapd.service -u rmail_web.service -u rmail_outbound.service -n 200 --no-pager
```

## Notes On Privileged Ports

The service units use:

```ini
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

That allows binding privileged ports like `25`, `143`, `465`, and `993` without running the daemons as root.

## Why There Are No `.socket` Units

Older packaging in this repository included systemd socket units, but the daemons do not currently implement socket activation. Shipping `.socket` units would be misleading and would not work correctly. If socket activation is wanted later, the daemons need explicit support for inherited listeners.

## Building A Debian Package

This repository includes:

```text
packaging/debian/build-deb.sh
```

### 1. Ensure `dpkg-deb` is available

On Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y dpkg-dev
```

On Arch, install the Debian packaging toolchain:

```bash
sudo pacman -S dpkg
```

You also need a working Rust toolchain with `cargo`.

### 2. Build the package

```bash
./packaging/debian/build-deb.sh 0.1.0 amd64
```

That script now:

- runs `cargo build --release`
- assembles the package payload
- emits the final `.deb`

Optional third argument:

```bash
./packaging/debian/build-deb.sh 0.1.0 amd64 x86_64-unknown-linux-gnu
```

Use that if you want to package from a specific Cargo target directory.

That emits:

```text
target/debian/rmail_0.1.0_amd64.deb
```

### 3. Install on Ubuntu

```bash
sudo apt install ./target/debian/rmail_0.1.0_amd64.deb
```

Avoid installing a local `.deb` from `/root/...` with `apt install` if possible. Put it in a world-readable path like your normal home directory or `/tmp`, otherwise `apt` may warn that download/acquire ran unsandboxed because the `_apt` user cannot read the file.

Then edit:

- `/etc/rmail/config.toml`
- `/etc/default/rmail`

On first package install, the maintainer script will also try to:

- create the `rmail` system user/group if missing
- `enable` the four systemd services

After editing the config, start them:

```bash
sudo systemctl start rmail_smtpd.service
sudo systemctl start rmail_imapd.service
sudo systemctl start rmail_web.service
sudo systemctl start rmail_outbound.service
```

## Upgrading The Debian Package

If you installed `0.1.0` and build `0.2.0`, upgrade with:

```bash
sudo apt install ./target/debian/rmail_0.2.0_amd64.deb
```

or:

```bash
sudo dpkg -i ./target/debian/rmail_0.2.0_amd64.deb
```

`apt install ./...deb` is preferred on Ubuntu.

If you see:

```text
Download is performed unsandboxed as root as file '/root/...' couldn't be accessed by user '_apt'
```

that is not a package bug. It means the `.deb` file is stored somewhere `_apt` cannot read, typically `/root`. Move it to a readable path before installing, for example:

```bash
cp target/debian/rmail_0.2.0_amd64.deb /tmp/
sudo apt install /tmp/rmail_0.2.0_amd64.deb
```

The package now marks these as Debian conffiles:

- `/etc/rmail/config.toml`
- `/etc/default/rmail`

That means your local edits are preserved across upgrades unless you explicitly replace them.

On upgrades, the package does not auto-enable services again; it only does `enable` on the initial install path.

## Current Limits

- The generated `.deb` is simple and does not yet declare library/runtime dependencies beyond `systemd`.
- The package installs a sample config; you still need to provision real TLS certs, mailbox config, and any DNS/MX records yourself.
