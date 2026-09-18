# Notifications and recovery delivery

Beskar supplies opt-in plain-text email for confirmed account locks (Devise and
Rails-native), Rails-native emergency password resets, and security-team reset
alerts. Delivery uses the host's Active Job and Action Mailer configuration.
These notices describe precautionary actions, not proof of account compromise.

## Enable explicitly

All three notification flags now default to **false**. Their former true defaults
only logged intent; enabling them now requires real delivery configuration:

```ruby
# config/initializers/beskar.rb
Beskar.configure do |config|
  config.notifications = {
    from: "security@your-domain.example",
    recovery_url: "https://your-domain.example/account-recovery",
    security_team_recipients: ["security-team@your-domain.example"]
  }
  config.risk_based_locking[:notify_user] = true
  config.emergency_password_reset[:send_notification] = true
  config.emergency_password_reset[:notify_security_team] = true
end
```

Replace the example mailboxes and URL with your own. Notification flags do not
enable risk locking or emergency resets; configure those policies separately.
Enabling notifications is independent of optional audit logging and background
analysis. No sender fallback or hardcoded production recipient is used.

The sender and recipients must be plain, single mailbox addresses, without display
names, comma-separated lists, or header-control characters. Up to 20 security-team
recipients are supported, with one separate message/job per list entry. An enabled
team flag requires a nonempty list. User messages require a configured recovery
URL. Invalid settings stop startup/configure publication; delivery workers also
validate the notification settings they use.

The recovery URL must be an absolute HTTPS **entry page**, without userinfo,
query parameters, or a fragment. It must not contain a password-reset/sign-in token
in its path either; syntax validation cannot determine whether a path contains a
secret. Beskar never constructs this URL from a request's Host header. For multiple
authentication models, provide a host page that routes users to the appropriate
recovery/support flow. URL ownership, availability, and recovery correctness are
host responsibilities, not validated by a network request at boot.

Configure `config.active_job.queue_adapter` for your host and run workers consuming
`beskar_notifications` (including any host queue prefix). Beskar jobs inherit the
engine's `ApplicationJob < ActiveJob::Base`, not a host-defined `ApplicationJob`;
host-only subclass callbacks/settings do not automatically apply. The normal Rails
application-wide queue settings do apply. Configure Action Mailer transport/sender
authorization, with `perform_deliveries` and `raise_delivery_errors` enabled.
Disabled/suppressed delivery is treated as a failure, not a successful notice.

## Transaction and failure contract

Notification scheduling follows a confirmed lock/reset and waits for every
enclosing Active Record transaction to commit. Outer rollbacks and rolled-back
savepoints cancel callbacks. With no open transaction, enqueueing happens
immediately after the operation. Enqueue attempts never occur inside retryable
security-state mutation blocks.

Monitor mode and IP whitelist policy suppress the automatic security action and
its notification. A failed lock or rolled-back reset produces no notice. A failed
optional account-lock audit does not prevent notification of the actual lock.
Password invalidation, session revocation, and the mandatory emergency-reset audit
remain transactional; notification delivery is outside that transaction.

The user-reset and security-team hooks are independent: one failing hook does not
suppress the other. Initial enqueue exceptions/aborted enqueues are logged without
changing admission or rolling back committed work. There is no durable pending
row to retry an initial enqueue failure automatically.

`Beskar::NotificationJob` retries delivery failures up to five total attempts with
Active Job's polynomial backoff. Exhausted failures remain raised for the backend
to retain/report. A failed retry enqueue also raises visibly. Configure backend
failure monitoring and reconciliation; backend-level retries may add attempts.

This is **not an outbox or exactly-once delivery system**. A process crash between
commit and enqueue can lose a notice. SMTP acceptance followed by a timeout,
backend retries, or host delivery-observer failures can duplicate email. Separate
recipient jobs avoid retrying all team members for one member's delivery failure.
Successful execution means the configured transport returned successfully, not
that the recipient received or read the message. No delivery-status audit/table,
bounce handling, or verified recipient confirmation is supplied.

## Data and logging boundaries

Jobs contain only `user_type`, `user_id`, `kind`, and an optional
`recipient_index`. No email, password, reset token, model object, raw request
metadata, or risk explanation is serialized into job arguments. IDs are still
personal identifiers and require appropriate queue access/retention controls.

Workers load the current account and email (`email_address` for native accounts,
`email` for Devise), and current sender/recovery URL/team list. They recheck the
notification flag. Deleted accounts and removed recipient indices are skipped.
A reordered/replaced team list changes the recipient at a queued index; drain
pending jobs before changing the list if a fixed recipient snapshot is required.
User address changes similarly affect pending delivery. These jobs are historical
notices, not checks that the user is still locked when mail is delivered.

User bodies contain only fixed explanatory text and the configured recovery page.
Team bodies contain the model name and account ID, not the user's email or raw
security evidence. Review the authenticated dashboard for incident details.

Job argument logging is disabled for the notification job. Preparation/delivery
errors are replaced with static class-based errors, without their original causes,
before the normal job retry/failure reporting. This mailer uses
`deliver.beskar_notification` instrumentation with the mailer name, timing, and
sanitized exception information instead of Action Mailer's encoded-message and
recipient delivery payload. Subscribe to that event if your monitoring normally
depends on `deliver.action_mailer`. Other host mailers are unchanged.

Host queue-adapter logging, custom instrumentation/interceptors/observers, SMTP
debugging, and external error-reporting systems have their own privacy boundaries.
Beskar does not globally filter them, protect a transport's internal logs, or
anonymize mail recipients. Review those settings before production rollout.

## Recovery remains a host flow

The notice links to your existing recovery page; it does not issue a bearer token,
expose the random replacement password, authenticate the recipient, unlock an
account, or establish trusted-device/IP evidence. The host must supply secure
password-reset issuance, expiry, redemption, anti-enumeration/rate limiting,
identity verification, and authorized manual unlock where required.

For native accounts, emergency invalidation changes the password digest, revokes
sessions, and invalidates Rails' previous password-reset tokens. A later successful
password reset does **not** remove a Beskar manual lock. Follow the authorized
unlock procedure in [Authentication](authentication.md). Devise owns its own
Recoverable/Lockable recovery semantics; this repair adds Devise lock notices,
not a second Devise password-reset or unlock implementation.

The public native `send_emergency_reset_notification(reason)` and
`notify_security_team_of_reset(reason, event)` hooks remain overridable. Their
defaults now enqueue these emails. Overrides still run independently after commit,
but own their delivery, retry, and privacy behavior; do not call `super` if that
would duplicate your delivery. Enabling their flags still requires the validated
notification settings above. The optional analysis job is a separate read-only
extension point, not a recovery-delivery adapter.

## Verification and rollout

Local Ruby 4.0.6 tests exercise real outer commits/savepoint rollbacks, both
authentication paths, user/team hook and queue failures, all five delivery
attempts, invalid recipients, disabled delivery, and sanitized logging. Mail is
sent only to Rails' **test** delivery backend. The native integration test follows
the recovery notice through the dummy host's recovery form, reset-token email and
redemption, confirms token invalidation, and requires manual unlock before login.

Real SMTP delivery, production worker durability, email-client rendering, host
support processes, and broader host recovery integrations have not been verified.
The dummy Devise reset-email/token handoff now verifies its email-unlock policy,
one-time token use, and that old sessions remain revoked. Configure and
exercise those before enabling emergency resets in production. This batch adds
no database migration and does not change the any-`Rails.cache` coordination
contract. Remaining work is tracked in [Repair status](../audits/repair-status.md).
