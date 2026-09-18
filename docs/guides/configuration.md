# Configuration and supported capabilities

Beskar validates configuration during Rails startup, after main autoloader setup
and host `after_initialize` callbacks registered by configuration files. Invalid settings raise
`Beskar::Configuration::Error` and stop boot. Errors identify known setting paths
without interpolating supplied values or unknown keys.

## Changes and defaults

Prefer `Beskar.configure` in `config/initializers/beskar.rb`:

```ruby
Beskar.configure do |config|
  config.monitor_only = true
  config.rate_limiting = {ip_attempts: {limit: 20}}
end
```

Whole-section assignment overlays **library defaults**, including nested defaults.
The example keeps the default IP period and account/global limits. It also resets
any previous customizations in that section. To retain existing customizations,
edit individual entries inside the configure block:

```ruby
Beskar.configure do |config|
  config.rate_limiting[:ip_attempts][:limit] = 20
end
```

`configure` copies the current settings, yields the copy, validates it, and
publishes another copy. A raised exception or validation failure leaves the
active configuration unchanged. Retaining the block's nested hashes/arrays does
not provide a reference to the published values. Proc callbacks and classes
remain trusted host objects; their behavior is not sandboxed or deep-copied.

Configuration is sealed after startup validation. Direct/nested mutation and
wholesale replacement are then rejected. Prefer initializer changes plus a
coordinated restart. Runtime `Beskar.configure(actor:, reason:, request_id:)`
requires an explicit `authorize_configuration` grant, validates a detached copy,
and records a mandatory filtered before/after journal before publishing it.
Missing authorization, invalid settings, open database transactions, or failed
journaling cannot publish. Publication is serialized within the Ruby process.
This is not a distributed configuration store or a per-request snapshot; runtime
changes affect only this process. The journal records authorized publication
intent, not proof every worker adopted it. A process crash after journaling can
prevent publication. Boot/deployment edits and changes inside trusted callback
implementations must be audited by the host deployment/source-control workflow.
See [Security hardening and rollout](../operations/security-hardening.md) for the complete contract.

During initialization, `configure` defers resolution of named host jobs until the
final startup check, when `app/jobs` can be autoloaded. Runtime `configure` and an
explicit `validate!` resolve enabled jobs immediately.

## What is validated

- Known symbol-keyed section schemas; unknown, misspelled, string, and removed
  keys are rejected. Partial section assignments fill missing defaults; deleting
  required entries in place is invalid.
- Actual booleans, not strings such as `"false"`; dashboard authorization and
  `audit_actor` callbacks must each be a Proc or nil. Nil authorization denies all
  dashboard access; nil `audit_actor` permits authenticated reads but rejects writes.
  Validation does not execute callbacks, grant access, or verify their decisions.
- Finite positive windows, cache lifetimes, decay half-lives, block durations,
  and thresholds; integer attempt/history/emergency counts. Authentication risk
  thresholds must be between 0 and 100. Native `auto_unlock_time` and WAF
  `permanent_block_after` accept nil for manual-only unlock/no permanent escalation.
- Valid IP/CIDR whitelist strings; WAF exception policies, nonempty block-duration
  arrays, regexp exclusions, and method/category names.
- Supported lock strategies and geolocation providers; configured authentication
  scope-name syntax. MaxMind requires an existing readable database path.
- An explicit Active Job subclass when automatic analysis is active.
- Sender/recipient mailbox syntax and an explicit HTTPS recovery entry page when
  user notifications are enabled; a nonempty recipient list for enabled team alerts.

Validation does not query application tables or `Rails.cache`. Any Rails.cache
backend remains supported; coordinated enforcement still uses the database
contract in [State storage](../operations/state-storage.md). Validation does not prove host
model/adapter readiness, MaxMind file integrity, queue availability, or production
database correctness. Runtime enrichment failure handling remains separate.

## Supported capabilities

| Area | Contract |
| --- | --- |
| Account locks | `:devise_lockable`, `:rails_auth`, or explicit `:none`. The placeholder `:custom` and unknown values are rejected. Host adapter requirements remain in [Authentication](authentication.md). |
| Geolocation | `:mock` or `:maxmind`. IP2Location and unknown providers are rejected, including by direct service construction. Mock results do not supply geographic risk evidence. |
| Background analysis | Off by default. A host-owned Active Job can opt into the post-commit hook below; no built-in analyzer is supplied. |
| Administration API | No versioned API; authenticated dashboard resource exports remain available. |
| Administrative history | Dashboard ban changes require a trusted `audit_actor` and per-request `audit_reason`, with mandatory transactional history. See [Audit lifecycle](audit-lifecycle.md) for configuration and the new migration. |
| Notifications/recovery delivery | Opt-in Action Mailer notices for account locks and native emergency resets, with post-commit jobs and bounded retries. Explicit sender/recovery/team configuration is required. The host still owns password-reset/unlock flows; see [Notifications and recovery](notifications-and-recovery.md). |

Unsupported lock strategies also raise when read at runtime. With risk enforcement
enabled, authentication rejects this misconfiguration with 503 rather than
silently skipping the lock; both supported authentication paths are regression
tested. `:none` deliberately disables locking and is not a custom adapter hook.

## Optional host background analysis

Provide a host job and explicitly enable it. Prefer a class-name string so each
invocation resolves the current Rails-autoloaded class:

```ruby
# app/jobs/security_review_job.rb
class SecurityReviewJob < ApplicationJob
  def perform(user_type:, user_id:, event_type:)
    # Restrict supported identities explicitly; adapt for your host models.
    return unless user_type == "User" && event_type == "login_success"
    user = User.find_by(id: user_id)
    return unless user

    suspicious = user.suspicious_login_pattern?
    Rails.logger.info("Security review user_id=#{user.id} suspicious=#{suspicious}")
  end
end

# config/initializers/beskar.rb
Beskar.configure do |config|
  config.security_tracking[:analysis_job] = "SecurityReviewJob"
  config.security_tracking[:auto_analyze_patterns] = true
end
```

Automatic invocation occurs on the successful-login tracking path after an
admitted attempt, with successful-login tracking enabled. It is optional analysis,
not asynchronous authentication enforcement. A failed optional audit write does
not by itself prevent invocation. The arguments contain only the model's base
class name, user ID, and `"login_success"`; no email, credential, session, raw
request context, or audit-event ID is passed. IDs still identify users and require
appropriate queue access/retention policy.

Monitor-only and whitelisted observations can invoke the hook too. Arguments do
not contain the policy mode; host jobs must not infer permission to lock, revoke,
or reset an account from receiving a job. Keep this hook read-only enrichment;
final admission and applicable policy remain synchronous.

Enqueueing waits for all enclosing Active Record transactions to commit. An outer
rollback or rolled-back savepoint cancels its callback. With no open transaction,
enqueueing runs immediately. Preparation errors, queue exceptions, and aborted
enqueue attempts are logged without raw exception messages and do not undo a
committed login/update or change admission.

This is **not a transactional outbox**: a process crash between commit and enqueue
can lose analysis. Backends/retries may duplicate work. Hosts own queue selection,
workers, retry/idempotence policy, and any eventual delivery. The local tests use
real database commits/rollbacks and the Active Job test adapter, not a production
worker or durable delivery service. The public `analyze_suspicious_patterns_async`
helper is also callable directly, but is not an admission/authorization check.

## Upgrade notes

- Configure `authorize_admin(request, permission)` separately from authentication;
  missing permissions deny dashboard access. Grants are `:read`, `:manage_bans`,
  `:export`, and `:read_audit`. Exports now require actor/reason/history as well.
- Global login limits and request-wide authentication-quota blocking default off.
  Explicitly opting in restores their distributed-denial/shared-NAT tradeoffs.
- A real lock always rejects the login and invalidates prior Devise credentials;
  `immediate_signout: false` is a deprecated compatibility value, not a bypass.

- Dashboard mutations now require a server-derived `audit_actor` callback and
  `audit_reason`. Deploy the administrative-action migration before new workers;
  see [Audit lifecycle](audit-lifecycle.md). Missing actor configuration returns
  503 for writes, without disabling authenticated reads.
- Lock/user-reset/team notification flags now default to false. Their old true
  defaults were log-only placeholders. Explicitly configure delivery before
  enabling them; see [Notifications and recovery](notifications-and-recovery.md).
- Automatic analysis now defaults to false. Enabling it requires `analysis_job`;
  the former silent discovery of a nonexistent `Beskar::SecurityAnalysisJob` is
  removed. Adapt any existing custom job to the explicit keyword contract above.
- Replace `:custom`/IP2Location configuration with a supported capability; these
  placeholders no longer silently do nothing.
- Remove obsolete `waf[:block_threshold]` and `waf[:monitor_only]`. Use cumulative
  `waf[:score_threshold]` and top-level `monitor_only`, respectively. A violation
  count is not interchangeable with a cumulative score.
- MaxMind configuration with a missing/unreadable path now stops startup. Supply
  a readable database or explicitly choose `:mock` without geographic risk evidence.
- Review partial section assignments for the default-overlay behavior above.
  The sixth batch required no new migration; the eighth batch adds the history table.

The Ruby 4.0.6 regressions exercise invalid/valid application boots, host job
autoloading, rejected configure-block publication, real commit/rollback behavior,
and optional queue failures. Production workers, actual class reloading, MaxMind
database reload/load behavior, and host-specific adapter readiness remain unverified.
