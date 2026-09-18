# Audit lifecycle and administrative changes

This is the eighth remediation batch's contract. Earlier documentation describing
account-deletion cascades or unaudited dashboard ban changes is historical.

## Account deletion: retain events unchanged

Deleting a native or Devise account no longer destroys its linked security events.
Beskar leaves every stored event field unchanged, including `user_type`, `user_id`,
timestamps, attempted email, IP address, and metadata. The association resolves to
nil once the account is gone; dashboard pages and exports tolerate that absence.
JSON exports retain the original polymorphic identifiers without embedding a
nonexistent user. Existing read-time privacy filters still apply without rewriting
stored rows.

This is **retention, not anonymization**. Identifiers and evidence can still identify
people. Beskar does not nullify the linkage, impose an expiry, or supply an automatic
event purge. Unidentified failed-login events also remain independent of account
deletion. Previously cascade-deleted events are not recovered, and this change
does not rewrite historical data or backups.

Hosts must choose and operate any retention period, access controls, backup policy,
or explicitly authorized erasure workflow separately. Avoid reusing account IDs;
the retained polymorphic reference can resolve to a replacement row with the same
type/ID. Model renames/removals also require a host migration strategy. Host-defined
callbacks, bulk SQL, and database rules can override this lifecycle. Normal
SecurityEvent save/update/update_columns/destroy/delete operations are now
rejected after creation. This is append-only model behavior, not tamper-proof
database storage or a restriction on privileged host code.

## Trusted administrative actor

Dashboard writes require both the existing authorization callback and a separate
server-side `audit_actor` resolver. For a host with a Devise `User#admin?` role:

```ruby
Beskar.configure do |config|
  config.authenticate_admin = ->(request) do
    request.env["warden"]&.authenticate(scope: :user)&.admin?
  end
  config.audit_actor = ->(request) do
    user = request.env["warden"]&.user(scope: :user)
    "User:#{user.id}" if user&.admin?
  end
  config.authorize_admin = ->(request, permission) do
    user = request.env["warden"]&.user(scope: :user)
    user&.admin? && user.beskar_permissions.include?(permission.to_s)
  end
end
```

Adapt the scope, role, and `beskar_permissions` lookup to the host. Permission
names are `read`, `manage_bans`, `export`, and `read_audit`; none is implied by
another or by successful authentication. Missing grants deny access (403).
These callbacks run in controller
context; the actor callback runs only after dashboard authorization and CSRF
verification, once per mutation request. Native hosts should derive the identifier
from their already authenticated administrative session. A shared Basic/token
credential may use an explicit stable service identifier, but that records a
shared identity, not which individual used it.

The resolver must return an opaque string of 1–200 ASCII characters, starting with
a letter/digit and otherwise containing letters, digits, `:`, `_`, `.`, `/`, or `-`.
Use a stable type/ID, never an email, password, token, request parameter, or
unverified header. Beskar cannot verify the truth of a host callback's identity.
Authorization's boolean result is not inferred to be an actor.

`audit_actor` defaults to nil. Separately authorized reads still work, but mutations and exports return
503 when the resolver is missing, invalid, or raises. Startup validates Proc-or-nil
without executing the callback. Every mutation also requires `audit_reason`, a
nonblank string of at most 1,000 characters; invalid input returns 422. Prefer a
case reference and short explanation. Key-based filtering cannot identify arbitrary
secrets embedded in free text.

## Journal and transactional behavior

Apply `ExpandAdministrativeActionTargets` as well as the original journal migration.
Entries now distinguish `BannedIp`, `SecurityEvent`, and `Configuration` targets;
collection/configuration entries have no target ID. Export preparation records
the actor, required reason, request, format, filtered query, count, ID bounds,
and truncation before sending data. A journal failure returns 503 without an
export body. Supply `audit_reason` or `X-Beskar-Audit-Reason` on every cursor page.
The record is not proof of successful client download. Runtime configuration
publication has a separate permission and journal; see [Configuration](configuration.md).

`beskar_administrative_actions` records dashboard ban creation, updates, unbans,
extensions, and conversion to permanent bans. Each changed target receives:

- A server-resolved actor, required reason, action name, ban ID, and creation time.
- A server-generated operation UUID shared by all targets of one bulk operation.
- The Rails request ID, bounded to 200 characters, for correlation only. It may
  originate in a client `X-Request-ID` header and is not proof of identity.
- Filtered, bounded before/after projections of ban ID/IP, reason, details,
  permanence, ban/expiry times, violation count, and metadata. Creation has an empty
  before-state; unban has an empty after-state.

The projections use [AuditData filtering and bounds](audit-and-waf.md), not a raw
database copy. Timestamp precision, redaction, and truncation can make projections
look identical despite a real stored change; such changes still receive an entry.
The journal is not a full-fidelity restore backup.

Ban changes and required journal inserts share one writer-database transaction and
the same coordination keys used by automatic escalation. Bulk requests accept
1–100 positive ban IDs, deduplicate and sort them, and require every target to
exist. Missing targets return 404; malformed inputs and unsupported operations or
extension durations return 422. Supported extensions are `1h`, `6h`, `24h`, `7d`,
and `30d`; making a ban permanent is a separate operation. Existing permanent bans
cannot be extended. Manual extensions do not increment violation counts; automatic
`BannedIp.extend_ban!` behavior is unchanged. Dashboard edits cannot change a ban's
IP identity.

There is no partial bulk success. A failed target callback or required history
insert rolls back the transaction, including earlier items. Success messages follow
successful completion; Active Record errors and rejected persistence callbacks
return 503 rather than claiming success (other unexpected exceptions propagate).
If a connection fails during commit, the client may not know whether the
transaction committed: reload state/history before retrying. Operation UUIDs are
correlation, not a client retry/idempotency protocol. Exact no-op updates create no
history, and the bulk response reports the count actually changed.

Authenticated history pages at `/beskar/administrative_actions` and `/:id` are
read-only, paginated (at most 100 rows/page), HTML-escaped, and marked `no-store`.
Filter the index with `target_id`. There are no history edit/delete/export routes.
History has no actor or ban foreign key and survives their deletion. Ordinary
instance save/update, `update_columns`, destroy, and delete attempts are rejected.
This is **not tamper-proof storage**: low-level counter/bulk APIs, raw SQL, and
privileged database access can bypass model protections. Database access policy,
external archival, and tamper detection remain separate work.

Unban and row-extension links now open review pages with real forms and required
reasons; their GET requests do not mutate state. New/edit/inline-extension/bulk
forms also require reasons. Batch nine consolidates behavior in a nonce-bearing
script, removes inline event handlers/method-link synthesis, and adopts native
navigation. See [Dashboard and search](dashboard-and-search.md) for UTC inputs,
JavaScript-disabled behavior, browser verification, and the remaining style-CSP limit.

## Coverage and deployment boundaries

The journal is prospective and covers dashboard exports, audited runtime
configuration publication, and dashboard/explicit `AdministrativeBans` changes.
It does **not** automatically journal every
direct model/manager/console write, WAF transition, expiry cleanup, or failed action
attempt. Existing administrative history is not reconstructed. For host-owned
manual workflows, authorize the operator first, then create one service instance
per operation with trusted `actor:`, required `reason:`, and a nonblank `request_id:`:

```ruby
Beskar::Services::AdministrativeBans.new(
  actor: "Operator:42", reason: "Case 123: false positive", request_id: SecureRandom.uuid
).change!([ban.id], action: "unban")
```

The service itself is not an authorization boundary. As with coordinated security
state, bans, journal, and state rows must use the same authoritative writer pool.
Any `Rails.cache` backend remains supported.

Before rollout, copy and apply `CreateBeskarAdministrativeActions` and
`ExpandAdministrativeActionTargets` along with any
missing earlier migrations (`bin/rails beskar:install:migrations`, then
`bin/rails db:migrate`). Configure `authorize_admin` and `audit_actor`, update scripted dashboard callers
to supply `audit_reason`, and drain/restart old workers: older code can still delete
events on account deletion or mutate bans without the journal. The new table was
applied only to the local test database; no production database was changed.

No cleanup job is added for either audit table. Per-entry bounds do not bound total
storage; hosts must monitor growth and choose retention deliberately. Local tests
cover both account adapters, unchanged raw rows after deletion/read/export, real
CSRF rejection, required-history and later-bulk-item rollback, escaped HTML/forms,
fresh migration execution, and simultaneous manual/automatic updates using separate
SQLite connections. Batch nine adds Chromium form/CSRF/navigation checks. Live
PostgreSQL/MySQL, production load, broader host browser flows, and tamper-resistant
external archival remain unverified.
