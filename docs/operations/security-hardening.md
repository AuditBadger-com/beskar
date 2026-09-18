# Audit findings 2–6: hardening and deployment contract

This batch extends the previous repairs. It does not claim that arbitrary host
authentication code is automatically secured, or that production capacity has
been validated. Use the coverage checklist below as a deployment gate.

## Authentication and revocation coverage

| Entry point | Beskar enforcement | Host requirement / boundary |
| --- | --- | --- |
| Devise database password, including HTTP Basic | IP/account admission before password verification; risk/lock decision before session establishment | Include SecurityTrackable on every protected model; preserve the standard strategy/serialization pipeline |
| Standard custom Warden strategies | IP admission before `_run!`; account admission when identity becomes known; failed strategy outcomes audited | Scope must resolve to a protected model. An opaque token's target cannot be counted before its verifier identifies it |
| OAuth/manual Warden sign-in | `set_user` guarded, even with `run_callbacks: false` | External provider verification happens before Beskar sees the identity. Use the generic gateway if pre-verification admission is needed |
| Devise cookie and remember-me resumption | Durable generation in both credential salts; locks rotate generations; fetch checks locks | New salt format invalidates old cookies once. Custom serializers/remember verifiers require review |
| Rails-native session creation and resumption | Transactional session guard; locks delete sessions; resumption validates the persisted session and lock | Adopt both controller and resumption hooks in docs/guides/authentication.md; arbitrary host `Current`/cookie readers are not discoverable automatically |
| Custom API/token issuance | Framework-neutral admission gateway and issued generation | Host verifies/cryptographically binds identity and generation and honors the result before issuing anything |
| API token use | Shared base-controller guard checks account and signed generation per request | Include `Controllers::SessionSecurity` after host identity resolution; implement both readers below |
| Action Cable | Base-channel guard checks subscribe, inbound actions, and normal outbound channel transmissions | Prepend `Channels::SessionSecurity`; connection implements the same readers. Direct connection writes/custom dispatchers bypass this adapter |

Risk-based locking remains opt-in and requires a supported lock strategy. A
confirmed lock always rejects the attempt; legacy `immediate_signout: false` no
longer provides an exception. Ordinary Devise `locked_at` writes rotate the
account generation in the user transaction. Explicit `user.revoke_beskar_sessions!`
rotates it without needing a lock; native accounts also destroy database sessions.
Unlock never restores old generations. Persistent generation rows must not be
purged; they deliberately have no TTL. Bulk SQL updates bypass model callbacks.

All users, sessions and security state must share the writer connection pool.
Generation/native-lock reads bypass the query cache, not just Rails.cache. A
database failure denies access; it does not use an old allow decision. In-flight
work cannot be retroactively canceled; idle sockets close on their next guarded
action or transmission, not via a background disconnect broadcast.

### Framework-neutral credential issuance

```ruby
attempt = Beskar::Services::Authentication.authenticate(
  request, model: User, scope: :api,
  credentials: {email_address: params[:email_address]} # Identity only; never passwords/tokens
) do
  User.authenticate_by(params.permit(:email_address, :password))
end
# On denial, return attempt.response; on Unavailable, return the standard 503.
# Only when attempt.allowed? is true may the host issue a credential containing:
#   subject: attempt.user.id, beskar_generation: attempt.session_token
# Sign/store these values using the host's existing authenticated token mechanism.
```

`scope` is a stable host-selected name, never a client-selected partition. The
gateway does not create tokens, sessions, endpoints, or verify OAuth assertions.
Credential verifiers must return the authenticated persisted model or nil.
If the subject is unknown before verification, use an empty identity hash; IP
admission still precedes the verifier and account admission follows it.

For protected API controllers:

```ruby
class Api::BaseController < ActionController::API
  before_action :verify_host_token! # Existing host verifier; never trust unverified claims
  include Beskar::Controllers::SessionSecurity

  private

  def beskar_authenticated_user = @verified_user
  def beskar_authenticated_generation = @verified_claims["beskar_generation"]
end
```

For Action Cable, prepend `Beskar::Channels::SessionSecurity` to the shared
`ApplicationCable::Channel` base. The connection must expose public
`beskar_authenticated_user` and `beskar_authenticated_generation` methods from a
verified credential, plus its normal `request`. Missing readers, missing/old
generations, locks and unavailable state fail closed. **Never fill a missing token
generation with `user.beskar_session_token` on resumption**: doing so would give
an old credential a new generation and bypass revocation. Native DB-session
connections can use the persisted-session guard instead, through a host adapter.

Inventory every login, impersonation, recovery auto-login, API base, native
session reader and Cable base before enabling enforcement. Verify each with a
lock/revoke/unlock replay test. Beskar cannot guarantee coverage for omitted
hooks, unprotected model classes, direct `connection.transmit`, or host overrides
that intentionally bypass the supported pipeline.

## Administrative history and permissions

Security events survive account deletion unchanged and now reject ordinary
instance rewrites/deletes. Administrative history is also append-only at the
model layer; raw SQL/bulk APIs and privileged Ruby code remain outside this
guarantee. No historical rows were rewritten or backfilled.

Dashboard authentication grants no capabilities by itself. Configure
`authorize_admin(request, permission)` in controller context to return exactly
true for separately assigned `:read`, `:manage_bans`, `:export`, or `:read_audit`
grants. Missing callbacks/grants deny access. Do not infer permissions from the
request; consult the host's trusted role/permission store.

Exports require a trusted `audit_actor`, a reason, and a committed journal record
before sending a body. The record includes resource, format, filtered query,
result count/ID bounds and truncation. A log of preparation does not prove client
receipt. Every cursor page needs a reason. See docs/guides/audit-lifecycle.md for ban history
and atomic all-or-nothing mutations.

Configuration is sealed after startup. For exceptional process-local runtime
changes, configure a separate `authorize_configuration(actor)` callback at boot,
then call `Beskar.configure(actor:, reason:, request_id:) { |candidate| ... }`.
It serializes local publication, validates a copy and requires a filtered
before/after journal before publishing. Open database transactions are rejected.
The record includes changed top-level settings; callbacks are represented as
`[CALLBACK]`, never serialized code. Per-entry filtering/bounds still apply.

This is not distributed configuration: restart all workers from reviewed
initializers for normal deployments. A crash between journal commit/publication
can leave an intent record without publication. Source-controlled boot edits,
environment changes, and trusted callback code changes require host deployment
auditing; they cannot safely require a migrated database during initial boot.

## Advertised features

The nonexistent versioned API routes remain removed. No built-in automatic
pattern analyzer is advertised: enabling it requires a real host Active Job and
startup validates that dependency. Notifications have opt-in Action Mailer jobs,
bounded retries, and explicit sender/recipient/recovery-page configuration.
Recovery itself uses host/Devise token and unlock workflows, not a Beskar token
issuer. Production delivery, an outbox, replay/idempotence policy and support
identity verification remain host/operational work; see docs/guides/notifications-and-recovery.md.

## Availability and validation gate

The global login budget now defaults off, removing its shared lock hot spot and
distributed-attacker kill switch. `global_attempts[:enabled] = true` explicitly
restores both. IP/account admission and backoff remain enabled. Authentication
quotas no longer deny unrelated traffic or auto-ban shared egress by default;
`ip_attempts[:block_requests] = true` restores that opt-in policy.

Shared-NAT users can still share a login quota, and attackers can target one
account's quota. Tune thresholds with observed traffic. There is no unconditional
DoS resistance: password hashing, audit growth, writer availability, pool/lock
timeouts, WAF storage and ingress bandwidth remain finite resources. Required
pre-request state failures return a no-store 503/Retry-After response; arbitrary
host database exceptions retain their host handling.

The SQLite suite includes independently leased connections, lost-update/admission
races, rollback/retry, null/unavailable caches, distributed-budget isolation, NAT
page access and dependency failures. PostgreSQL 17/MySQL 8.4 CI jobs run the full
suite using `BESKAR_TEST_DATABASE_URL`; **not yet executed here**. Docker daemon
access was denied, including outside the sandbox. Installed pg/mysql2 adapters
alone are not evidence of tested servers. No production throughput claim is made.

Before production, run those jobs and host load/soak tests across multiple app
workers: successful/failed/distributed logins, concentrated account/NAT traffic,
WAF bursts, exports, concurrent locks/session creation, database loss/recovery,
pool exhaustion and bounded-retry exhaustion. Measure p50/p95/p99 latency, error
rate, password CPU, query/lock waits, pool utilization and table growth. Set host
ingress limits, database statement/lock timeouts and operational alerts from the
measured capacity. Never use a production database URL with Rails test tasks.

## Rollout

1. Install/apply all engine migrations, including `ExpandAdministrativeActionTargets`.
2. Configure separate dashboard permissions and actor resolution; update exports
   to send a reason. Runtime settings now require the audited path.
3. Deploy the host authentication adapters and signed generation claims; reject
   or reissue legacy tokens without them. Plan the one-time Devise sign-out.
4. Drain old workers and restart from the same reviewed configuration. Mixed
   versions can otherwise issue stale credentials or mutate/delete old audit rows.
5. Keep the adapter/load gate open until actually run. Only the local test
   database was migrated; no production database, remote CI or mail service was changed.
