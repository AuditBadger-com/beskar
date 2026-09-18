# Audit data, exports, and WAF matching

This contract was introduced in the fourth remediation batch. The fifth batch
adds [consistent dashboard reporting and search](dashboard-and-search.md).
The eighth batch adds [account-deletion retention and administrative history](audit-lifecycle.md).
Earlier examples
that retain full URLs/exception messages or score every Rails exception are
historical. See [Repair status](../audits/repair-status.md) for remaining findings.

## Audit capture and disclosure

WAF matching uses request data transiently. Persisted WAF evidence contains rule
IDs, static descriptions/categories, severity, rules version, decoding-pass count,
an allowlisted HTTP method/exception class, timestamps, and scores. The event
retains the Rails-resolved IP for attribution, subject to host audit filters.
Raw/canonical paths, query strings, exception messages, and User-Agent headers are
not copied into WAF events, ban metadata, state, or WAF messages. Public
`record_violation` calls also project old-style analysis onto this bounded schema.
The state API strips legacy raw-path/description fields on reads and on the next
normal write; it does not bulk-rewrite historical database contents.

Authentication audits still retain bounded paths, cleaned HTTP(S) referrers,
device/geographic evidence, IPs, and bounded User-Agent text. Referrers exclude
credentials, queries, and fragments; session IDs and raw forwarded headers are
not captured. These records remain sensitive and require access controls.

`Services::AuditData` bounds metadata and applies both built-in sensitive-key
filters and `Rails.application.config.filter_parameters`. Built-ins cover
passwords, secrets, tokens, authorization, cookies, session IDs, CSRF,
`exception_message`, `fullpath`, and `matched_path`. Nested keys are filtered.
Host email filters now redact attempted emails and associated-user presentation
in views and exports; account associations and hashed admission counters remain intact.
Plaintext email searches cannot find newly redacted email values.

Model validation and model loading sanitize:

| Model | Filtered audit fields |
| --- | --- |
| SecurityEvent | Metadata, event type (100 characters), IP text (64), User-Agent (500), attempted email (320) |
| BannedIp | Metadata, reason (100 characters), details (2,048) |
| AdministrativeAction | Actor/request ID (200), reason (1,000), bounded before/after state projections |
| Native lock state | Metadata supplied when locking; lock authority is separate |

Ban IP addresses, permanence, expiry, IDs, and other enforcement fields are
deliberately not passed through audit filters. They remain visible to authorized
dashboard/export readers. Redacting a ban IP must never disable enforcement.
Host filters targeting event types, geolocation, or authentication evidence can
reduce audit reporting and history-based risk enrichment; review that policy
explicitly. Admission state does not depend on a successful optional audit write.

Metadata admits JSON-compatible values, at most 64 entries per hash, 50 per
array, depth 10, and a 512-node traversal budget. Keys are at most 128 bytes;
string values are at most 2,048 characters, with controls replaced and invalid
UTF-8 repaired. Non-finite numbers become null. Excessively large serialized
metadata becomes `{"_truncated":true}` (64-KiB limit); depth/budget exhaustion uses
`[TRUNCATED]`. Do not treat truncated audit data as complete evidence.

Read-time filtering changes loaded objects, not stored legacy rows. Raw SQL,
`pluck`/`pick`, bulk inserts, and writes that skip validation bypass model
sanitization. No historic rows, logs, backups, or exports were purged by this
repair. Arbitrary secrets embedded in allowed free text, path segments, or
User-Agent text cannot be reliably identified by key-based filters. Hosts must
filter/drop those fields if their application places secrets there.

Beskar's rescued-exception log messages now use the exception class instead of
its message. This does not sanitize the host application's own request logs,
exception reporters, custom callbacks, or externally supplied free-text log
arguments. Account deletion now retains events unchanged, and dashboard ban changes
require transactional administrative history; see [Audit lifecycle](audit-lifecycle.md).
An operational retention period, historical cleanup, and tamper-resistant archival
remain separate work.

## Export contract

Both event and ban exports require dashboard authentication, an explicit `:export`
permission, trusted actor, and a nonblank reason (`audit_reason` or
`X-Beskar-Audit-Reason`). Each page requires a persisted administrative export
record before data is sent; see [Audit lifecycle](audit-lifecycle.md).
CSV and JSON return at most 1,000 records in descending ID order. They set
`Cache-Control: private, no-store`, `X-Content-Type-Options: nosniff`, and:

- `X-Beskar-Export-Limit: 1000`.
- `X-Beskar-Export-Truncated: true|false`.
- `X-Beskar-Next-Cursor` when more rows remain.

Pass that cursor as `before_id` with the same filters and format for the next
page. Malformed/nonpositive/out-of-range IDs return 422. Exports no longer load
the entire relation or silently override ordering with `find_each`.
Pagination is not a transactional snapshot: concurrent edits/deletions and
relative-time filters can change membership. Newly inserted higher IDs require
starting a new export. The 1,000-row cap bounds rows, not database query cost.

CSV fields are quoted/escaped, bounded, and dangerous textual prefixes receive a
visible `text: ` marker. Detection covers leading `=`, `+`, `-`, and `@`,
including preceding controls/whitespace/formatting characters and Unicode
compatibility variants. Numeric database fields stay numeric. This intentionally
changes exported text; JSON preserves the filtered text without a spreadsheet
marker. Neither format exports an associated user object's custom serialization:
only its ID and filtered email are included.

Quoting alone is not a formula defense, and spreadsheet import/save/reopen
behavior varies. The visible prefix avoids relying solely on a removable
apostrophe. See [OWASP's CSV injection guidance](https://owasp.org/www-community/attacks/CSV_Injection).
Automated tests cover emitted CSV cells and parsed column boundaries, not actual
Excel/LibreOffice/Sheets clients or their save/reopen behavior. Test the supported
client workflow before claiming spreadsheet-client safety.

## WAF matching contract

The WAF is a scanner-path heuristic, not a general SQL injection/XSS engine.
It does not parse request bodies or implement JavaScript challenges/honeypots.

- Match at most 8,192 path bytes, with at most two percent-decoding passes.
- Convert backslashes to slashes, preserve literal plus signs, and retain dot
  segments so traversal is detectable rather than erased by normalization.
- Flag oversized paths, malformed escapes, invalid UTF-8/control bytes, and
  excessive encoding as medium-severity malformed-path evidence.
- Use root/segment boundaries to avoid matches inside ordinary words.
  Ordinary `.well-known` routes are not scanner signatures.
- Ignore arbitrary query text. Only a flat, exact `format` query key with an
  allowlisted executable value is checked; queries over 8,192 bytes are skipped.
- Retain matched rule IDs with `rules_version: 1`, not the matching input.

Use narrow exclusions for legitimate host routes:

```ruby
Beskar.configure do |config|
  config.waf[:exception_detection] = :suspicious
  config.waf[:request_exclusions] = [
    {path: %r{\A/wp-content/}, methods: ["GET", "HEAD"],
     categories: [:wordpress_static]},
    {path: %r{\A/reports/}, methods: ["GET"], categories: [:unknown_format]}
  ]
end
```

Exclusions use the decoded path. Omitted methods/categories mean all methods/
categories for that path. A static-file exclusion does not exclude traversal or
configuration-file rules. Existing `record_not_found_exclusions` still apply
to RecordNotFound exception analysis, not independent path signatures.

Exception policies:

- `:suspicious` (default): ordinary known Rails exceptions need independent
  path/format evidence. A missing record or unsupported format alone is not abuse.
- `:all`: opt into broad scoring of the four known exception classes; legitimate
  errors can accumulate enough points to ban an IP.
- `:none`: disable exception scoring, without disabling request-path matching.

The known classes are UnknownFormat, InvalidType, RecordNotFound, and
IpSpoofAttackError (matched by exact class name). Middleware only attributes
IP-spoof exceptions when an IP was safely resolved; it never substitutes an
attacker-supplied forwarded header. Application exceptions still propagate.

One middleware pass records at most one violation. Matching several path rules
uses the highest path severity; a subsequent application exception neither
adds another charge nor upgrades that earlier charge. Scores remain cumulative:
one critical signature adds 95 points, below the default threshold of 150.
This is not a promise to block the first exploit request. Monitor/whitelist
observations remain isolated from enforcement state.

## Rollout and remaining verification

The fourth-batch changes require only the first batch's shared-state migration;
batch eight also requires the administrative-action table described in
[Audit lifecycle](audit-lifecycle.md). Review changed audit fields, host filters, cursor-based export
consumers, and default exception policy before deployment. Existing enforced bans
are not automatically forgiven by the narrower matching policy.

Run monitor-first against real host routes and mounted paths. Local benign/attack
corpora cover percent/double encoding, backslashes, query poisoning, boundaries,
exclusions, ordinary Rails exceptions, legacy state, and single-charge behavior.
These tests do not establish production false-positive rates or complete scanner
coverage. Production database fault/load tests, spreadsheet-client QA, historical
data cleanup, and operational retention policies remain unverified or unimplemented.
