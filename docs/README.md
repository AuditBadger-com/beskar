# Beskar documentation

Start with the current guides and operational contracts below. The original
review and archived overview describe earlier code; they are not current setup
instructions. [Repair status](audits/repair-status.md) distinguishes verified
changes from open findings and production validation still required.

## Start here

- **Installing or integrating:** follow the [project README](../README.md#installation),
  then read [configuration](guides/configuration.md),
  [authentication](guides/authentication.md), and [state storage](operations/state-storage.md).
- **Upgrading an existing installation:** use the
  [security hardening and rollout checklist](operations/security-hardening.md#rollout).
- **Working on repairs:** consult [repair status](audits/repair-status.md) and the
  [original findings](audits/project-review.md) before selecting work.

## Guides

- [Configuration](guides/configuration.md) — validation, supported capabilities,
  defaults, and audited runtime changes.
- [Authentication](guides/authentication.md) — Devise/Warden admission, native
  session integration, account locks, and revocation boundaries.
- [Risk scoring](guides/risk-scoring.md) — factors, geographic evidence, and
  heuristic limitations.
- [Audit data and WAF](guides/audit-and-waf.md) — filtering, exports, scanner
  matching, and privacy boundaries.
- [Audit lifecycle](guides/audit-lifecycle.md) — unchanged event retention,
  administrative permissions, actor/reason history, and migrations.
- [Dashboard and search](guides/dashboard-and-search.md) — reporting, search,
  routes, forms, timezones, and browser/CSP behavior.
- [Notifications and recovery](guides/notifications-and-recovery.md) — opt-in
  delivery jobs and host-owned recovery flows.

## Operations

- [State storage](operations/state-storage.md) — database authority, cache
  independence, concurrency, rate limits, cleanup, and rollout.
- [Monitor-only mode](operations/monitor-only-mode.md) — observation behavior and
  the transition to enforcement.
- [Security hardening](operations/security-hardening.md) — authentication
  coverage, deployment requirements, availability tradeoffs, and validation gates.

## Audits and repair tracking

- [Repair status](audits/repair-status.md) — completed batches, test evidence,
  unresolved findings, and next verification gates.
- [Original project review](audits/project-review.md) — the September 2026
  diagnostic baseline and F01–F26 findings; preserved as historical evidence.

## Research and historical reference

- [Rust performance assessment](research/rust-performance-assessment.md) — a
  measured investigation and proposal, not an implemented feature or performance
  guarantee.
- [Archived project overview](archive/project-documentation.md) — the
  pre-remediation architecture and examples; do not use it as current guidance.
- [Changelog](../CHANGELOG.md) — historical release notes.

## Maintaining these docs

Keep `README.md` and `CHANGELOG.md` at the repository root. Put current feature
guides in `guides/`, deployment/runtime contracts in `operations/`, findings and
progress in `audits/`, proposals in `research/`, and superseded references in
`archive/`. Use lowercase, hyphenated filenames and relative Markdown links.
Source paths mentioned in prose are relative to the repository root.

Add new documents to this index. The gem includes `docs/**/*.md`; link/index and
packaging regressions run with:

```sh
mise exec -- env PARALLEL_WORKERS=1 bin/rails test test/documentation_test.rb
```
