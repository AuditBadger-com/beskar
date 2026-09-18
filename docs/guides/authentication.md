# Authentication admission and account locks

Authentication enforcement is independent of audit persistence. Disabling
`security_tracking`, or a failed optional audit write, does not turn off rate
limits or risk-based locking. A request-local attempt ID correlates the decision
with any audit records that were successfully written.

## Devise

Include `Beskar::Models::SecurityTrackable` on each protected model. The engine
wraps Devise's database-password strategy: it identifies the target account and
reserves IP/account (and opt-in global) capacity **before password verification**. This includes
Devise HTTP Basic password authentication. Unknown accounts receive hashed,
normalized identity keys; password values are not used as counter keys.

The Warden outcome hook reuses the same admission instead of counting twice.
Protected-page visits without credentials and session fetches do not manufacture
failed logins. Devise scope aliases are resolved through `Devise.mappings`.

Risk-based Devise locking requires `:lockable`. A confirmed lock always rejects
the current attempt; `immediate_signout` defaults true and legacy false no longer
bypasses a lock. Normal persisted `locked_at` changes rotate a durable account
generation, invalidating all existing Devise sessions and remember-me cookies.
Unlock never restores an older generation. This includes Devise's own lockable
locks and manual model updates, not bulk SQL bypasses. Unrelated accounts/scopes
remain signed in. Generation reads bypass Active Record's query cache.

**Upgrade:** the new session/remember-cookie salt format signs out existing
Devise clients once. Drain old workers; mixed versions cannot safely enforce the
new credentials. All authentication models and state must use one writer pool.

Devise owns its own `unlock_strategy` and `unlock_in`. Beskar's `auto_unlock_time`
does **not** override Devise's class-level unlock policy. Configure it in Devise.
Standard custom Warden strategies now reserve IP capacity before `_run!`
verification; invalid tokens count. The account is charged once when an opaque
strategy identifies it. Warden `set_user` is guarded even with
`run_callbacks: false`, covering OAuth-style manual sign-in and stateless Warden.
Session fetch checks locks without counting a login. A custom strategy overriding
Warden's dispatcher, model serialization, or credential verifier needs its own
review. Beskar cannot revoke a host bearer token that omits the generation check.
See [Security hardening and rollout](../operations/security-hardening.md) for API and WebSocket adapters.

## Rails-native authentication: required integration

The old logging-only controller calls are insufficient. Upgrade the login
controller to reserve admission before `authenticate_by`, then guard session
creation:

```ruby
class User < ApplicationRecord
  has_secure_password
  has_many :sessions, dependent: :destroy
  normalizes :email_address, with: ->(email) { email.strip.downcase }
  include Beskar::Models::SecurityTrackableAuthenticable
end

class SessionsController < ApplicationController
  include Authentication
  include Beskar::Controllers::SecurityTracking

  allow_unauthenticated_access only: %i[new create]
  before_action -> { admit_authentication_attempt(User, :user) }, only: :create

  def create
    if (user = User.authenticate_by(params.permit(:email_address, :password)))
      return unless complete_authentication(user) { start_new_session_for(user) }
      redirect_to after_authentication_url
    else
      track_authentication_failure(User, :user)
      redirect_to new_session_path, alert: "Try another email address or password."
    end
  end
end
```

For custom identity fields, pass an explicit identity-only hash through
`admit_authentication_attempt(User, :user, credentials: {...})`. Match the identity
lookup used by your authentication code. Never include passwords in that hash.

The session-creation block runs in a retryable database transaction; restrict it
to session creation and response-cookie assignment, not external notifications or
other non-idempotent external actions. Users, sessions, and Beskar state must use
the same writer connection pool for these transactions to be atomic. Sharded or
cross-database authentication models need a separately designed adapter.

Existing-session readers must also honor the persistent lock. In Rails'
`Authentication` concern, adapt `resume_session` along these lines:

```ruby
def resume_session
  Current.session ||= find_session_by_cookie
  if Current.session && !Beskar::Services::SessionRevocation.native_session_allowed?(Current.session, request: request)
    Current.session = nil
    cookies.delete(:session_id)
  end
  Current.session
end
```

The dummy application contains the exercised integration. Include the check on
every other path that resumes a native session (including custom API or websocket
authentication). In-flight requests cannot be retroactively canceled by a lock.

Native locks use `beskar_security_states`; no lock columns on the user table are
required. The default strategy selects native locking for native models. A lock
revokes all database sessions, never compares their IDs to the unrelated Rack
session ID, and serializes with guarded new-session creation. If a host session
destruction callback fails or aborts, the persistent lock remains authoritative,
access is denied by the reader guard, and physical cleanup failure is logged.
That lock becomes manual-only so expiry cannot reactivate old sessions. Explicit
unlock retries cleanup and only clears the lock if every session was removed.

`auto_unlock_time` controls native lock duration. Set it to `nil` for manual-only
unlocking. To explicitly unlock:

```ruby
Beskar::Services::AccountLocker.new(user, risk_score: 0).unlock!
```

Native lock rows retain their deadline inside their data; periodic expired-state
cleanup does not erase manual locks. Account-lifecycle cleanup remains separate.

## Policy and failure boundaries

- Monitor mode and whitelisted IPs suppress Beskar automatic account locks,
  sign-outs, and emergency password resets. Observed authentication counters do
  not consume enforced global/account capacity.
- Devise's own failed-attempt Lockable policy and host Rails rate limiters are
  independent. Beskar does not disable those host policies in monitor mode.
- Admission denials return HTTP 429 with a retry deadline. Native lock denials
  return HTTP 403. Required authentication-state or enforced risk-assessment
  failures reject authentication with HTTP 503. Optional audit/enrichment failures
  are logged and do not reject an otherwise allowed attempt.
- Direct model tracking methods preserve their optional `SecurityEvent` return
  contract; that return is **not** an admission decision. Native controllers should
  use `complete_authentication`, not infer authorization from whether an event
  saved. `track_authentication_success` now returns a boolean for custom callers;
  ignoring it is unsafe and does not provide the concurrent session guard.

## Audit and recovery

Known failed targets are associated with their user record for account-history
analysis. Rejected admissions/sessions use `authentication_blocked`, not
`login_success`. `metadata["authentication"]` records the attempt ID, scope,
admission outcome, and actual lock result. Lock events reference that same attempt
ID; the login audit row may not yet exist or may be disabled.

Deleting an account retains its linked events unchanged, including the original
`user_type` and `user_id`. This is not anonymization; no event expiry or automatic
purge is added. See [Audit lifecycle](audit-lifecycle.md) for retention, missing-user
presentation, and the separate required journal for dashboard ban changes.

Authentication context no longer stores Rack session IDs. Referrers are restricted
to HTTP(S), with credentials, queries, and fragments removed. Other WAF/export
privacy findings are still tracked separately; this is not a complete audit-data
redaction policy.

Emergency reset remains opt-in. Thresholds count confirmed account-lock evidence,
not strings containing a false travel/device flag or duplicate success events.
Password invalidation, session revocation, and the mandatory recovery audit commit
together; failure rolls them back. `require_manual_unlock: true` removes the native
automatic-unlock deadline. Notification hooks run after all enclosing transactions
commit.

Account-lock and native emergency-reset notifications now use opt-in post-commit
Action Mailer jobs. The three notification flags default to false; configure a
sender, HTTPS recovery entry page, and any security-team recipients before enabling
them. See [Notifications and recovery](notifications-and-recovery.md) for retries,
legacy hook overrides, delivery/privacy limits, and the tested native recovery
handoff. A successful password reset does not bypass a Beskar manual lock. Real
production delivery and host-specific recovery verification remain necessary.
Normalized risk evidence and removal of unsafe automatic trust discounts are
documented in [Risk scoring](risk-scoring.md).

See [Configuration](configuration.md) for validated lock strategies and the
optional host-owned, post-commit analysis hook. The old `:custom` placeholder is
rejected; use a supported strategy or explicit `:none`. No built-in background
analyzer is supplied; analysis and notification delivery are separate job paths.
