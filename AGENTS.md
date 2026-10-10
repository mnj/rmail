# Working on rMail

Guidance for coding agents and contributors. The README covers what rMail does, the
repository layout and standards support; this file covers how to work on it.

## Repository and branches

- The only git remote is `upstream` (`git@github.com:mnj/rmail.git`); there is no `origin`.
  Run `git fetch upstream`, branch from `upstream/main` and push with
  `git push -u upstream <branch>`. A branch created from `upstream/main` tracks it, so set the
  push target explicitly so you never push to `main` by accident.
- Several agents often work on the repository at once. Do feature work in a git worktree under
  `.claude/worktrees/<name>` (`git worktree add -b <branch> .claude/worktrees/<name> upstream/main`).
  Never switch branches in, or edit, the shared main checkout.
- Never use a bare `git stash`: the stash is shared by every worktree. Set work aside with a
  temporary commit instead.
- Remove a worktree once its PR is merged (`cargo clean --manifest-path <worktree>/Cargo.toml`,
  then `git worktree remove`). Each worktree's `target/` can grow past 15 GB.

## Checks (what CI runs)

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
```

For the frontends (`crates/webui/frontend`, `crates/webmail/frontend`), use bun:

```sh
bun install --frozen-lockfile
bun run typecheck
bun run build
```

Run all of these before pushing. Clippy must be warning-free.

## Pull requests

- Push and open a PR when the work is ready (`gh pr create --base main`).
- Wait for the checks (`gh pr checks <n> --watch`). These are CI, CodeQL and CodeRabbit;
  CodeRabbit can take ten minutes or more.
- Fix every applicable review finding, with tests. Reply on each thread with the fixing commit,
  or with a short reason when a finding doesn't apply. Dismiss CodeQL false positives with a
  comment.
- Merge only when the maintainer asks. Use merge commits (`gh pr merge <n> --merge`).
  Rebase onto `upstream/main` first and run the checks locally after resolving conflicts.
- When several PRs touch the same files, merge them one by one and rebase the next onto the
  result. Rebuild conflicted test files from `main` plus the PR's own diff rather than
  concatenating both sides.

## Code conventions

- Match the surrounding code: comment density, naming, and doc comments that explain why rather
  than what.
- **Configuration lives in SQLite** (settings specs in `crates/common/src/settings.rs`, edited in
  the admin console or with `rmail_ctl settings`). `config.toml` only names the mail root and the
  database. Do not add new configuration files, and do not write importers for old text
  configuration.
- **Schema changes need migrations.** Databases from earlier versions must keep working: use
  `CREATE TABLE IF NOT EXISTS` for new tables, and an idempotent `pragma_table_info` check plus
  `ALTER TABLE ... ADD COLUMN` for new columns. Add a test that starts from the old schema.
- Treat protocol input as hostile: cap sizes, never panic on malformed data, and test the
  refusal paths, not only the happy path.
- Checks and writes that must agree belong in one transaction (see
  `rmail_common::dav::store::put_with`); a check made before the write lock can be raced.
- Update the README (feature list and the standards tables), `docs/DEPLOYMENT.md` and
  `site/index.html` when user-visible behaviour changes.

## Shell safety

- Never write secrets (private keys, API keys, passwords) to temporary files. Pipe them between
  tools instead.
- Do not `rm` with globs. Use `cargo clean --manifest-path` for build output, and fixed,
  explicit paths for scratch files.

## Screenshots and UI checks

`scripts/screenshots/capture.sh [out-dir]` builds everything, starts a seeded demo instance on
loopback ports and captures both web apps with Playwright (into `site/assets/screenshots` by
default). Set `CHROMIUM_PATH` to use an installed Chromium. Capture into a scratch directory
first and look at the results at desktop and phone width before committing them. The demo must
keep the host name `mail.example.com` so no machine names end up in published images.

## Notes

Markdown files in the repository root other than `README.md` and this file are ignored by git,
so dated planning notes (for example `11oct26.md`) can live there without being committed.
