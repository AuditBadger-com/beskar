# Review remediation

Tracks [Original project review](project-review.md), which remains the historical baseline.
Ten implementation batches are complete; this is not a claim that all findings are fixed.
The runtime is the project's mise default Ruby **4.0.6**.

Batch ten addresses the renewed audit findings 2–6. See
[Security hardening and rollout](../operations/security-hardening.md) for the entry-point coverage matrix,
revocation semantics, separate administrative permissions, required export/config
history, changed availability defaults, and the host/database validation gates
that remain open. Account deletion still retains events unchanged.

## Implemented and locally verified

| Finding | Change and evidence |
| --- | --- |
| F01 | Devise database-password/HTTP Basic admission now reserves and enforces IP/account and opt-in global limits before password verification. Failed known targets count against their account; unknown identities use normalized hashed keys. Native controllers have explicit admission/session guards. Outcome callbacks do not double-count, and credential-free page visits create no attempts. Standard custom Warden strategies now have IP pre-verification admission and account binding after identity resolution; set_user is guarded even when callbacks are disabled. API/Cable adapters and remaining host integration boundaries are documented in docs/operations/security-hardening.md. |
| F02 | Warden sign-out uses the current request's actual lock result, not recent audit rows, and affects only the current scope. Confirmed locks now always reject admission, rotate a durable account generation, and invalidate all prior Devise sessions/remember cookies. Unlock never restores them; unrelated accounts remain signed in. |
| F03 | Beskar automatic account locks, sign-outs, and emergency resets honor monitor/whitelist policy. Whitelisted authentication observations cannot consume enforced global capacity. Risk-enabled audits now record would-lock eligibility and adapter availability without claiming an actual lock. Host Devise/Rails policies remain independent. |
| F04 | Implemented persistent native locks, expiry/manual unlock, all-session revocation, and a transactional session-creation guard. Existing-session readers honor lock state. Separate-connection races and failed/aborted destruction callbacks are covered; failed cleanup requires successful cleanup before manual unlock. Host integration and same-writer-pool requirements are explicit in docs/guides/authentication.md. |
| F05 | Geographic history pairs normalized JSON locations with their own timestamps/IDs, uses actual elapsed seconds and explicit chronology, and rejects unusable coordinates/times. Real Devise/native requests exercise persisted travel evidence through actual locks. Mock locations never create travel/country risk. Bounded history and geolocation limitations are explicit in docs/guides/risk-scoring.md; production accuracy remains unverified. |
| F06 | Middleware, authentication audit, rate limiting, and WAF attribution use the Rails-resolved `remote_ip`. Trusted-proxy regression coverage added. Hosts must configure trusted proxies correctly. |
| F07 | Ban enforcement reads the database, never cached booleans. Regressions cover rollback, IP edits, expiry edits, stale positives, and stale negatives. |
| F08 | Permanent flag is authoritative; permanent bans are excluded from expiry cleanup and normalize expiry to nil on save. Temporary bans require expiry. Legacy-data review remains an upgrade prerequisite. |
| F09 | Database-backed state, unique keys, transactional updates, optimistic conflict detection, and bounded retries replace cache read/modify/write. Separate-connection SQLite regressions exercise counters, admissions, WAF history, and repeated bans. Other database concurrency/load runs remain unverified. |
| F13 | Minitest 5 pinned for Rails 8.0; lint dependencies updated for Ruby 4. CI now includes Ruby 4.0.6 and 3.4; duplicate automatic workflow made manual. Local verification below; hosted CI has not been run here. |
| F14 | Removed the disconnected `ip_auth_failures` cache representation. Request-wide IP-quota blocking and its fixed-window denial/auto-ban counter are now opt-in; unrelated shared-NAT traffic remains accessible by default. |
| F15 | Read-only previews, configured counting windows, bounded attempt storage, enforced backoff deadlines, longest retry selection, global backoff separation, and explicit global/IP-denial reset coverage. Global capacity is now opt-in, removing the default shared lock hot spot and distributed-denial budget. |
| F16 | Added bounded path canonicalization, root/segment-aware signatures, exact-format query matching, and method/path/category exclusions. Ordinary Rails exceptions no longer score without independent scanner evidence by default; broad scoring requires opt-in. Middleware records at most one charge for path plus exception. Benign/attack corpora cover boundary false positives, encoded traversal, query poisoning, malformed input, and exclusions. Production route coverage and false-positive rates remain unverified; this remains a cumulative scanner heuristic, not first-request exploit prevention. |
| F19 | Monitor WAF/rate observations use separate state and never create automatic active IP bans. WAF audit `would_be_blocked` respects whitelist and auto-block policy. Automatic account actions now honor the same monitor/whitelist policy. |

## Partially addressed

| Finding | Completed so far | Still open |
| --- | --- | --- |
| F10 | Dashboard callbacks that render/redirect are not rendered twice; missing-config logging no longer interpolates secrets; credential recipes reject blank/missing values and use secure comparison; recursive installer example removed. | Broader host-adapter authorization coverage and review of custom callbacks. |
| F11 | Authentication context drops session IDs/forwarded headers and cleans referrers. WAF sinks retain bounded rule evidence, not raw URLs/headers/exception messages. Audit models bound/filter metadata and text using built-in plus host parameter filters, including on legacy model reads. Rescued-exception logs use classes rather than messages. CSV exporters quote cells and visibly prefix formula-like text; JSON projects known fields. Associated Devise/native email presentation now shares filtering across views and exports. Export authorization and no-store behavior are tested. | Arbitrary secrets in allowed free text/paths, historical rows/logs/backups, raw SQL/bulk API bypasses, retention/access policy, and actual spreadsheet-client import/save/reopen QA. Stored-value search can reveal legacy record membership despite read-time redaction. Audit filtering does not anonymize enforcement fields such as ban IPs. |
| F12 | Logger fallback no longer recurses. Cache availability is not required for authoritative state. Required authentication-state, lock-persistence, and enforced risk-assessment failures reject with 503; optional authentication and WAF audit writes are isolated with savepoints. A failed optional WAF audit does not prevent state updates or bans. Optional host analysis queues only after enclosing commits; rollback cancels it and queue failures do not undo admission/committed work or log raw exception messages. | Unified dependency-failure policy for the other middleware/WAF paths and database-specific fault tests. The optional analysis hook has no outbox/durable-delivery guarantee. |
| F17 | One assessment provides explicit factors whose points/caps sum to the score and flow into lock evidence. Corrected bot/reason flags, browser captures, and midnight scoring. Removed implicit IP/unlock trust discounts and geographic bypasses; only explicitly admitted, unlocked-success history supplies travel observations. The geographic pattern helper is implemented. Observation history does not raise enforced risk. | Production calibration/false-positive evaluation and any future verified-device/recovery trust mechanism. User-Agent and IP geography remain spoofable/approximate heuristics, not identity proof. |
| F18 | Native unlock deadlines/manual locks work; Devise's own unlock policy is explicitly separate. Emergency thresholds count confirmed locks with true flags, not duplicated successes or false-flag strings. Password invalidation, session revocation, and mandatory recovery audit are transactional. Opt-in Action Mailer lock/reset/team notices now use independent post-commit jobs with five-attempt retries, validated sender/recipients/recovery page, and isolated failures. Native recovery is exercised through the host reset email/token redemption and authorized manual unlock; resetting the native password alone cannot bypass the lock. A real Devise reset-email/token handoff now verifies its own email-unlock policy, replay rejection and continued revocation of old sessions. | Real SMTP/production worker and broader host recovery verification; durable outbox/reconciliation, duplicate/bounce handling, delivery-status history, and broader host recovery/identity-verification policies. |
| F20 | Correct migration source/destination paths, destination-aware mount detection, migration numbering, idempotence with engine-copied migrations, monitor-first initializer, truthful immediate installation instructions. Copied migrations run successfully against a fresh SQLite database. | Full fresh host-app boot/authentication exercise and remaining older documentation claims. |
| F21 | README and gem metadata describe scanner-path and User-Agent heuristics without promising SQLi/XSS filtering, JavaScript challenges, or honeypots. Removed versioned API routes that pointed to missing controllers; authenticated resource exports remain. Devise's invalid callback-registration path was removed. Automatic background analysis now defaults off and requires an explicit host Active Job with a documented post-commit contract. Both authentication paths invoke it only after admission. Removed custom-lock/IP2Location no-op placeholders; unsupported settings fail explicitly. Notification defaults now opt out and their enabled paths perform real Action Mailer delivery, not log-only intent. Current operational-contract documents ship in the gem. | Remaining historical capability/configuration claims. No built-in analyzer, production worker validation, custom lock adapter API, IP2Location integration, or standalone recovery/token endpoint is supplied. |
| F22 | Added a composite user/event/time index; risk-history projections are ordered/bounded and one device/geographic snapshot supplies scoring/evidence. Exports are capped at 1,000 rows with cursors. Centralized PostgreSQL/SQLite/MySQL JSON search expressions, exact legacy email fallback, bound text values, and literal LIKE escaping. Overview counts reuse grouped queries; related-event tables preload users. Query-count regressions pass. | Live PostgreSQL/MySQL execution, adapter/collation/query-plan/load testing, further query reduction, and retention. JSON-text substring search remains expensive; paging and grouped counts are not transactional snapshots. |
| F23 | Account deletion retains linked security events unchanged, including original polymorphic IDs, as explicitly chosen. Raw-row comparisons and dashboard/export regressions cover both adapters. Dashboard ban changes require a trusted actor and reason, with bounded before/after snapshots, server operation UUID, and request correlation in a separate journal that survives target/actor deletion. Changes and history share a transaction and ban coordination; bulk selections are bounded, deduplicated, and all-or-nothing. Required-history failures and aborted destruction never report success. SecurityEvent and administrative history reject normal instance CRUD rewrites. Exports require separate permission, actor/reason and a mandatory preparation journal; runtime configuration has its own grant and before/after journal; manual extensions no longer fabricate violations. | No automatic retention period/purge, historical backfill, universal auditing of direct model/automatic changes, failed-attempt journal, database tamper resistance, or production adapter/load verification. Low-level SQL/bulk/counter APIs and privileged host code can bypass model protections. Boot/deployment changes need host source-control/deployment auditing. |
| F24 | Whitelist parsing follows replaced/mutated configuration; default getters and Devise scope mappings are corrected. Geolocation caches are isolated by provider/database identity, and readers follow database generations. Startup/configure validation checks section schemas, booleans, numeric bounds, whitelist/exclusions, supported providers/strategies, readable MaxMind paths, and enabled host jobs. Partial section assignments merge library defaults; invalid configure blocks do not publish partial changes. Boot/job-autoload and direct unsupported-strategy authentication regressions pass. | Host model/adapter readiness checks, real MaxMind hot-reload/load testing and distributed configuration. Configuration is sealed at boot; authorized runtime changes serialize local publication with required history. This is process-local, not a distributed or crash-atomic publication protocol. |
| F25 | Lowercase Rack 3 response headers and actual retry deadlines; verified using Rack::Lint. | Content negotiation for API clients. |
| F26 | Reporting bands, full-history statistics, native-user identity/filtering, and stable event ordering are unified. Ban expiry fields now explicitly use UTC with strict server parsing, browser-compatible milliseconds, and unchanged-value microsecond preservation. Presets use server time; invalid inputs are rejected, custom reasons survive edits, and validation retries preserve duration selections. One nonce-bearing script replaces inline handlers and handwritten method-link submission. Native navigation opts out of host Turbo; real forms retain CSRF and work without JavaScript. Page-size changes preserve filters without duplicate/stale fields; validation feedback stays visible. Chromium regressions cover timezone/DST, skewed clocks, precision, toggles, bulk confirmations, Turbo/back navigation, and no-script forms. | Full strict-style CSP (inline style attributes remain), other browsers, mobile/accessibility and broader host-layout/auth QA, Turbo Frames/Streams, stale-form protection, and remaining dashboard semantics. |

## Next implementation batch

First run the new PostgreSQL/MySQL CI jobs and host multi-worker load/failure
tests; Docker daemon access was denied locally, including outside the sandbox.
Verify host API/Cable/native adapters and deployment configuration audit coverage.
Then address F25 content negotiation and the remaining F26 strict-style CSP/host UI work.
Continue the remaining privacy and
real-client validation work in F11.
Complete the remaining portions of F10/F12/F18/F20/F21/F22/F24/F25 alongside those changes.

## Verification

- Batch ten regular suite: **839 tests, 4,369 assertions, 0 failures/errors,
  3 existing MaxMind-data skips**, Ruby 4.0.6, seeds `20260915` and `20260916`.
- Batch ten Chromium suite: **10 tests, 97 assertions, 0 failures/errors/skips**,
  Chromium/ChromeDriver **153.0.8010.36**, seeds `20260915` and `20260916`. Includes the new
  reason-bearing export form, required history, and existing form regressions.
- Batch ten lint: **180 files, no offenses**. Zeitwerk and CI YAML parsing pass.
  The existing dummy mailer-preview eager-load warning remains. New test-only
  adapters are pg 1.6.3 and mysql2 0.5.7; their servers/CI jobs were not run locally.
- New authentication regressions cover custom Warden failure admission, disabled
  callbacks, same-scope identity substitution, whitelist isolation, multiple
  browser/remember-cookie revocation, lock rollback, revocation during verification,
  generic token issuance, stale native sessions, deleted cached Cable users,
  inbound/outbound Cable denial, and Devise recovery-token replay rejection.
- New administration/availability regressions cover separate permissions,
  required export actor/reason/history, append-only events, sealed/runtime config
  publication, failed journal/transaction rejection, distributed login capacity,
  shared-NAT page access, eliminated default quota queries and database failures.

- Before implementation, restored baseline: **595 tests, 2,342 assertions,
  0 failures, 0 errors, 4 skips**.
- First batch: **626 tests, 2,465 assertions, 0 failures, 0 errors, 4 skips**.
- Second batch: **655 tests, 2,606 assertions, 0 failures, 0 errors, 4 skips**.
- Third batch: **679 tests, 2,753 assertions, 0 failures, 0 errors, 4 skips**.
- Fourth batch: **700 tests, 2,951 assertions, 0 failures, 0 errors, 4 skips**.
- Fifth batch: **718 tests, 3,177 assertions, 0 failures, 0 errors, 4 skips**.
- Sixth batch: **747 tests, 3,388 assertions, 0 failures, 0 errors, 3 skips**.
- Seventh batch: **768 tests, 3,623 assertions, 0 failures, 0 errors, 3 skips**.
- Eighth batch: **791 tests, 3,932 assertions, 0 failures, 0 errors, 3 skips**.
- Ninth-batch regular suite: **798 tests, 4,073 assertions, 0 failures, 0 errors,
  3 existing MaxMind database skips**, Ruby 4.0.6, seeds `20260923` and `20260924`.
- Ninth-batch Chromium system suite: **9 tests, 91 assertions, 0 failures, 0 errors,
  0 skips**, Chromium/ChromeDriver 152.0.7977.82, seeds `20260923` and `20260924`.
  The formerly assertion-free ban-deletion test now verifies a 404 response.
- Standard Ruby lint passes (164 files). Zeitwerk eager-load verification passes;
  the dummy application's mailer-preview directory is outside eager-load paths.
- New regressions include separate database connections (not transactional fixture
  connection-sharing), null/unavailable caches, retry/rollback, counter isolation,
  long windows, ban permanence, monitor isolation, trusted proxies, Rack responses,
  dashboard challenges, and fresh migration execution.
- Authentication regressions additionally exercise real Devise/Warden requests,
  pre-password denial, HTTP Basic, independent scopes, disabled/unavailable audits,
  state/risk failures, native lock/session races, cleanup callbacks, and transactional
  password-reset rollback.
- Risk regressions cover persisted travel through both adapters, matching score/
  lock evidence, history order and bounds, removal of implicit trust, observation
  isolation, malformed geography/times, midnight and browser scoring, cache/provider
  generation isolation, and unavailable optional caches. Old discount assertions
  were replaced with regressions that reject unsupported trust assumptions.
- Audit/WAF regressions cover nested/host redaction, metadata bounds, legacy model
  reads and state projection, partial model queries, CSV formulas/column boundaries,
  filtered-email admission accounting, both export cursors/authorization, canonical
  matching/exclusions, benign exception policy, single charges, and optional audit
  failures. Existing tests that required raw emails or exception messages now assert
  redaction; attack-accounting checks use user associations and hashed counters.
- Dashboard/search regressions cover reporting boundaries across model/UI/export,
  invalid/fractional scores, selected-time statistics, full-history ban totals,
  native/Devise display privacy, stable equal-time ordering, absent phantom API
  routes, literal search text, legacy JSON email fallback, adapter-specific SQL
  generation, composition across pages/exports, and aggregate/preload query counts.
- Configuration/analysis regressions cover real application startup and host job
  autoloading, host configuration callbacks, invalid-block publication, nested
  default merging, unsupported providers/strategies, both authentication paths,
  native final-session denial, real enclosing commits/savepoint rollbacks, and
  queue exceptions/aborted enqueues. The formerly skipped background-analysis
  test now exercises the supported opt-in contract.
- Notification regressions exercise actual Devise/native lock requests, real
  commits/savepoint rollbacks, reset-token invalidation, independent user/team
  hooks, enqueue aborts/failures, bounded delivery retries and failed retry enqueue,
  malformed recipients, deleted users, recipient-list changes, delivery switches,
  sanitized transport/job logging, and the full dummy native recovery handoff.
  Only the Rails test delivery backend was used; no real emails were sent.
- Lifecycle/admin regressions compare every stored event field after native/Devise
  account deletion, including legacy evidence, and exercise missing-user pages and
  exports without rewriting retained rows. Administrative tests cover trusted actor
  resolution, real CSRF rejection, required-history rollback, later-item bulk
  failure, deletion callbacks, strict selections/durations, no-ops and subsecond
  changes, ordinary history CRUD rejection, legacy read filtering, bounded history
  paging, escaped HTML, and confirmation-form verbs. Separate SQLite connections
  exercise concurrent manual extensions and mixed manual/automatic updates.
- Form/browser regressions additionally cover non-UTC application-zone parsing,
  UTC and offset instants, invalid calendar dates/types/overflow/precision, strict
  creation presets/defaults, permanent/temporary validation, nonce-bearing markup,
  native navigation, and filter-preserving page sizes. Actual Chromium tests use
  multiple browser zones, DST-boundary dates, a skewed browser clock, real CSRF,
  host Turbo loaded from its package, JavaScript disabled, and browser console
  assertions. They verify persistent validation feedback, precise expiry retention,
  and no duplicate administrative operations. A separate browser CI job is added.
- PostgreSQL/MySQL concurrency, production throughput, hosted CI, and broader
  cross-browser/host UI testing remain unverified. The tested CSP forbids inline
  script handlers but explicitly allows the existing inline style attributes.

## Rollout contract

See [State storage](../operations/state-storage.md): apply the migration before starting new
workers, drain old cache-based workers, share one authoritative writer database,
review legacy bans, and schedule `beskar:cleanup_security_state`. Cache counters
are not imported. The test database has been migrated locally; no host production
database was changed.

Rails-native hosts must also adopt the login and existing-session guards in
[Authentication](../guides/authentication.md). No additional migration beyond the
shared-state table is required for batches two through seven. Custom lock strategies
and cross-database authentication models remain unsupported. Batch ten's
API/Cable/Warden adapters are documented in docs/operations/security-hardening.md.

Risk weights were not calibrated against production traffic. Review the corrected
factors and removal of implicit trust discounts in [Risk scoring](../guides/risk-scoring.md)
before enabling enforcement or emergency resets. Legacy records without explicit
admission evidence are not automatically promoted into travel history.

Review [Audit data and WAF](../guides/audit-and-waf.md) for changed capture/export fields,
host email-filter behavior, the 1,000-row export cursor contract, visible CSV text
prefixes, and the narrower default exception policy. No historical personal data
or existing bans were bulk-rewritten or deleted by this batch.

Review [Dashboard and search](../guides/dashboard-and-search.md) for the corrected reporting
bands, search behavior/privacy limits, native-user display, and removal of unused
versioned API routes/helpers. Authentication risk weights and lock thresholds were
not changed by the dashboard repair.

Review [Configuration](../guides/configuration.md) before deploying the sixth batch:
invalid/obsolete settings now stop startup, partial section assignments overlay
library defaults, and `:custom`/IP2Location placeholders are rejected. Automatic
analysis defaults off; opt in with a host job and the new keyword contract. The
analysis hook supplies neither a built-in analyzer nor recovery delivery.

Review [Notifications and recovery](../guides/notifications-and-recovery.md) for batch seven.
The three notification flags now default to false; enabling them requires explicit
sender/recovery/team settings and a worker consuming `beskar_notifications`.
Notifications use their own post-commit delivery jobs. They do not issue recovery
tokens, unlock accounts, guarantee delivery, or supply an outbox. Production
transports and host recovery/support procedures must be configured and verified.

Review [Audit lifecycle](../guides/audit-lifecycle.md) for batch eight. Apply the new
administrative-action migration and configure a trusted `audit_actor` before
dashboard writes; forms/scripted callers must supply `audit_reason`. Drain old
workers, whose code can still delete events with accounts or make unaudited ban
changes. Events now survive account deletion unchanged, not anonymized. No audit
retention period, purge, historical reconstruction, or production data rewrite
was performed. Journal protections are not a database tamper-resistance guarantee.

Review the form/browser sections of [Dashboard and search](../guides/dashboard-and-search.md)
for batch nine. No additional migration is needed. Expiry inputs are now UTC;
scripted callers must use valid UTC/offset timestamps and valid bounded duration
seconds. The host must allow its nonce for the behavior script; the engine does
not loosen CSP. Inline style attributes still require separate cleanup for hosts
with strict style policies. Native navigation is deliberate, including with host
Turbo loaded; it is not support for arbitrary Turbo Frames/Streams integrations.

For batch ten, apply `ExpandAdministrativeActionTargets`, configure explicit
dashboard grants and actor resolution, and update exports to supply a reason.
Adopt the API/Cable/native adapters, bind credential generations, and plan the
one-time Devise session invalidation. Configuration is now sealed after boot.
Global login capacity and request-wide quota blocking are explicit opt-ins.
Read [Security hardening and rollout](../operations/security-hardening.md) before rolling out; host
integration, deployment auditing and PostgreSQL/MySQL/load gates remain open.
