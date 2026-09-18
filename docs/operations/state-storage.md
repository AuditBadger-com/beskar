# Coordinated security state

Beskar supports any `Rails.cache` backend, including a process-local MemoryStore,
FileStore, RedisCacheStore, MemCacheStore, Solid Cache, or NullStore. Enforcement
does not depend on cache increment, compare-and-swap, distributed locks, or cache
persistence. A custom store does not need any Beskar-specific operations.

## Authority and trade-offs

`beskar_security_states` is the shared authority for rate-limit windows, backoff
deadlines, middleware denial counts, and WAF violation history. Transactions lock
rows in deterministic order. Unique keys prevent duplicate state; optimistic
locking and bounded retries handle concurrent-update conflicts, including SQLite
write-lock contention. Retryable blocks must contain only database work.

`beskar_banned_ips` is authoritative for ban decisions. Each decision uses an
indexed database query. Stale positive/negative cache entries, cache eviction,
process restarts, and rolled-back ban writes do not change the result.
`BannedIp.preload_cache!` remains a compatibility no-op.

All application workers must use the same authoritative database. Separate SQLite
files in different containers are not shared coordination. Run security reads and
writes against the writer, not an asynchronously replicated read-only database.
Cache independence is **not** database-outage independence: database failures may
fail the request, rather than silently discard enforcement state.
Windows and deadlines use application time, so worker clocks must be synchronized.

This design adds database work: normal requests read bans; authentication attempts
update IP and optional account state; detected WAF violations update per-IP state.
The shared global counter is disabled by default, avoiding an application-wide
login-denial budget and lock hot spot. Explicitly enabling
`rate_limiting[:global_attempts][:enabled]` restores it and its availability risk.
Session resumption/generation checks add uncached database reads; locks revoke
generations transactionally. Benchmark with the host application's traffic and pool
size. No fixed throughput or latency guarantee is asserted.

Concurrency regressions currently exercise separate connections to SQLite. The
implementation uses Active Record transactions and portable queries, but equivalent
PostgreSQL/MySQL concurrency and production-load runs remain to be performed.
CI jobs now run the full suite against PostgreSQL 17 and MySQL 8.4, but those jobs
have not been executed here. Local Docker access was denied, including outside
the sandbox. `BESKAR_TEST_DATABASE_URL` selects an isolated test database; never
point it at a production database (Rails test tasks can rebuild it).

## Rate-limit semantics

All recorded authentication attempts count, whether credentials succeed or fail.
Each tier retains at most its configured limit of admitted timestamps; denied
attempts do not grow that tier's sliding window. Other tiers still count the
attempt while they have capacity. Results combine tiers using the latest retry
deadline. Exponential backoff is an enforced deadline, not just a response hint.

`:check`, `is_rate_limited?`, and `time_until_allowed` are read-only and do not
escalate backoff. Backoff grows on denied calls that record attempts. Middleware
previews do not grow authentication backoff. By default an authentication quota
does not block unrelated page/API traffic from the same shared IP. Opting into
`rate_limiting[:ip_attempts][:block_requests] = true` enables request-wide blocking
and the five-denials/hour automatic ban. IP login quotas still affect shared-NAT
users: size them for actual shared egress, and retain account limits. No default
can distinguish every legitimate user from an attacker sharing an IP.

`reset_rate_limit(ip_address:, user:, global: false)` clears the selected IP,
account, and IP denial/backoff state in the current mode. Pass `global: true` to
also reset the global counter. It does not remove bans. Monitor and enforcement
state are separate; see [monitor mode](monitor-only-mode.md).

The Devise database-password adapter now reserves and enforces all applicable
limits before verifying credentials. Rails-native controllers must adopt the
[explicit admission/session guards](../guides/authentication.md). Outcomes reuse the same
request-local attempt, independently of optional audit persistence. Whitelisted
requests record observation-only counters without consuming enforced capacity.

Native account locks also use this table, with an internal automatic-unlock
deadline or manual-only state. Their rows are retained for the account lifetime;
expired-counter cleanup does not delete native lock authority.

## Upgrade

1. Copy the new migration with `bin/rails beskar:install:migrations`, then run
   `bin/rails db:migrate` before starting the new application workers. Fresh installs
   can use `bin/rails generate beskar:install`.
2. Drain old workers during rollout. Old cache-based workers and new database-based
   workers do not coordinate. Existing cache counters are not imported, so counting
   windows restart; existing database bans remain in force.
3. Review legacy bans. A temporary ban must have an expiry; a permanent ban is
   active regardless of a legacy expiry timestamp. Permanent rows are never removed
   by expired-ban cleanup. New saves normalize permanent expiry to nil. Inspect
   malformed/CIDR IPs, alternate IPv6 spellings, and duplicate canonical addresses
   in older data before rollout; new writes require canonical individual IPs.
4. Review bans created by older monitor-mode versions before enabling enforcement.
   Those rows are not automatically deleted or reclassified.
5. Schedule `bin/rails beskar:cleanup_security_state` periodically (for example,
   hourly). Expired rows are ignored immediately; cleanup only reclaims storage.
   Audit events and active bans are not deleted by this task. Security-event
   retention is separate: account deletion now retains events unchanged, with
   no automatic expiry/purge. See [Audit lifecycle](../guides/audit-lifecycle.md).
6. Upgrade Rails-native login controllers and existing-session readers using
   [Authentication](../guides/authentication.md). The former logging-only calls cannot
   prevent session creation. No additional migration beyond the shared-state
   migration is needed for these native locks.
7. For batch eight, also apply the administrative-action migration and configure
   a trusted `audit_actor` for dashboard writes. See [Audit lifecycle](../guides/audit-lifecycle.md)
   for required reasons, transactional history, and the old-worker drain requirement.

## Verification

Run with the project's mise default Ruby (4.0.6 locally):

```sh
mise exec -- env PARALLEL_WORKERS=1 bin/rails test
mise exec -- bundle exec standardrb
```

Regression coverage includes null/unavailable caches, distinct IP/account keys,
global coordination, atomic concurrent updates, long windows, backoff expiry,
read-only checks, rollback, stale ban caches, canonical IPv6, permanent bans,
monitor isolation, trusted proxy attribution, Rack headers, and migration copying.
