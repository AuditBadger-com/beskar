# Dashboard and search contract

Reporting/search behavior introduced in the fifth repair batch, which required
no new migration. The eighth batch adds a history table and required actor/reason
for dashboard writes; see [Audit lifecycle](audit-lifecycle.md).
See [Audit data and WAF](audit-and-waf.md) for capture, redaction, export paging,
and privacy limitations, and [Repair status](../audits/repair-status.md) for open work.

## One set of reporting bands

`Beskar::RiskLevel` supplies model predicates/scopes, dashboard counts, event
filters (including exports), badges, labels, colors, and filter option text:

| Band | Event score | Badge |
| --- | --- | --- |
| Low | 0–29 | success |
| Medium | 30–69 | warning |
| High | 70–89 | danger |
| Critical | 90–100 | critical |

The model's existing high/critical boundaries of 70 and 90 are authoritative.
`high_risk` and the dashboard's High Risk Events total include critical events;
the `risk_level=high` filter selects only 70–89. This distinguishes a minimum
threat threshold from an exclusive histogram bucket.

Invalid/missing/out-of-range scores are unknown, not critical. They receive a
neutral badge and are excluded from score-band counts, while still counting as
events in overall totals. Fractional aggregate scores use the same boundaries:
69.9 remains medium, 89.9 remains high.

These are reporting bands, not a change to scoring weights, configured account
lock thresholds, WAF severity points, or cumulative WAF ban thresholds.
Older dashboard thresholds of 61/86 and the conflicting boundary at 30 are
removed. Review saved filters/report consumers that relied on those old ranges.

## Statistics and user presentation

Overview event totals and failed-login counts reuse one grouped event-type
query. Risk-band and high/critical counts reuse one grouped score query. The
selected statistics period has both a lower bound and a current-time upper
bound, excluding future-dated records. The recent-activity list remains the
latest ten events across periods, as its own section describes.

These separate queries are not a transactional snapshot: concurrent writes can
still change results between queries. Grouped counts reduce repeated queries
but do not remove the cost of scanning a large selected period.

Ban details compute count, average, maximum, first seen, and last seen from all
events for that IP. The table still shows only the latest 20. Related-event
tables preload their user associations; lists with equal timestamps use IDs
as a descending tie-breaker. Pagination remains offset-based for HTML lists;
exports retain their separate descending-ID cursor contract.

Associated user labels support both Devise `email` and native `email_address`.
The same bounded, filtered presentation is used by dashboard/event/ban views
and exports. Native associated email addresses honor both `email_address` and
the common `email` filter name; this does not rewrite the host user record.
Attempted-email and metadata fields retain their own audit-key filtering
contract. Configure a broad `:email` filter to cover those email-bearing keys.
Where no address is available, views use an attempted email or user-ID fallback.

## Search semantics and database support

Event index and both export formats use `Services::EventSearch`:

- General search covers IP, User-Agent, attempted email, event type, and a text
  representation of metadata on all three database families below.
- The email filter checks the attempted-email column, falling back only when
  that column is null to the top-level `metadata.attempted_email` value.
  Unrelated metadata prose and the user's current email are not email matches.
- Terms are bounded to 256 characters, lowercased for ASCII-insensitive matching,
  and passed as SQL values. Percent, underscore, and the chosen escape character
  (`!`) are literal text, not user-controlled LIKE wildcards.
- Missing/empty/non-text search values do not add a filter. Non-ASCII case folding,
  collation behavior, and serialized-JSON escaping remain database-dependent.

JSON cannot be handled as an ordinary string column everywhere. PostgreSQL
extracts legacy email text with `->>`; SQLite uses `json_extract`; MySQL uses
`JSON_EXTRACT` plus `JSON_UNQUOTE`, preserving JSON-null behavior. The centralized
expressions follow the respective primary references:
[PostgreSQL JSON operators](https://www.postgresql.org/docs/current/functions-json.html),
[SQLite JSON functions](https://www.sqlite.org/json1.html), and
[MySQL JSON search functions](https://dev.mysql.com/doc/refman/8.4/en/json-search-functions.html).

General metadata search uses a TEXT cast on PostgreSQL/SQLite and a CHAR cast on
MySQL (Mysql2/Trilogy), instead of applying LIKE directly to a JSON column.
This is text search, not a structured JSON query language or a full-text index.

SQLite execution, request/export integration, literal-wildcard handling, and
PostgreSQL/MySQL SQL generation are tested locally. No live PostgreSQL/MySQL
server, production collation matrix, query plan, or throughput benchmark has
been exercised by this batch. Other adapters have no implemented legacy-email
extractor and fail explicitly when that filter is used.

Search operates on stored values, before read-time model filtering. It can
therefore match sensitive legacy values that are hidden when rendered, revealing
record membership to an authorized administrator. Read-time redaction is not
historical erasure; remediate legacy storage separately if that inference is
unacceptable. Searches over newly redacted values cannot recover the original.
Leading-substring and JSON-text search can still be expensive despite paging.

## Public routes and remaining work

Removed the unimplemented `/beskar/api/v1/*` routes and their route helpers.
They previously pointed to missing controllers. Supported read exports remain
`/beskar/security_events/export.csv|json` and
`/beskar/banned_ips/export.csv|json`, behind dashboard authorization.
There is no versioned programmatic administration API.

The fifth batch verified rendered HTML and controllers. Batch nine additionally
exercises the forms in Chromium as described below. Administrative lifecycle and
opt-in notifications have their own contracts in [Audit lifecycle](audit-lifecycle.md)
and [Notifications and recovery](notifications-and-recovery.md).

## Ban forms and timezones

New/edit expiry fields are explicitly **UTC**, independent of browser timezone and
the host application's `Time.zone`. A timezone-free dashboard value such as
`2030-11-03T01:30` means 01:30 UTC, not a DST-dependent local wall time. Scripted
dashboard requests may also supply ISO 8601 timestamps with `Z` or a numeric
`+HH:MM`/`-HH:MM` offset. These are normalized to the identified UTC instant.
The parser accepts valid calendar dates with four-digit positive years, hours
0–23, optional seconds, and up to six fractional digits. Malformed dates, overflow
times, leap seconds, non-string shapes, and excessive precision return 422 rather
than normalizing to another date or silently selecting a default.

HTML datetime controls use millisecond precision. Edit forms mark that precision
with `expiry_precision=milliseconds`; submitting the unchanged displayed instant
preserves existing database microseconds. Scripted requests without that form
marker retain their explicit precision. This is not optimistic locking against
stale form edits. Report timestamps outside these inputs continue to use their
existing Rails/application-zone presentation; they are not reinterpreted as UTC
wall-clock input.

Creation presets are computed on the server, once: a positive integer number of
seconds, capped at 90 days. An explicit custom expiry takes precedence; absent/empty
duration and custom expiry use 24 hours. Invalid supplied presets and unknown ban
types return 422. Permanent creation ignores temporary duration/expiry values.
This restriction applies to dashboard creation/the manager, not a new global ban
duration cap. Direct `BannedIp.ban!` and administrative extension contracts remain
separate. Valid custom dates can be in the past, permitting an explicit expiry;
the database does not silently advance them.

Quick edit buttons add elapsed UTC hours to the later of the displayed expiry or
the browser's current time; they never convert a UTC string through the browser's
local timezone. They only edit the field until the operator submits. Switching a
permanent ban to temporary requires an expiry; JavaScript suggests 24 hours if the
field is empty. Switching to permanent disables temporary controls, and server
normalization clears expiry. Presets are not converted to client-clock timestamps
on submission. Create-form validation retries retain the selected duration rather
than turning it into a stale custom expiry. Existing custom reasons remain selectable,
and blank-expiry validation renders without a secondary view error.

## Script policy and native navigation

One layout behavior script carries the host-generated nonce. Inline `onclick`,
`onchange`, and submission handlers are removed from the dashboard. Delegated
listeners are installed once per document; initial load and restored pages refresh
the control state without adding duplicate handlers. Validation errors and notices
are no longer automatically removed after five seconds.

The engine does not loosen the host's CSP. Hosts enforcing script CSP must provide
a nonce generator and allow that nonce in `script-src`, for example:

```ruby
# Host CSP configuration: merge with your existing policy, do not discard it.
config.content_security_policy_nonce_generator = ->(_) { SecureRandom.base64(24) }
config.content_security_policy_nonce_directives = %w[script-src style-src]
```

Local tests enforce `script-src 'self' 'nonce-…'`, `script-src-attr 'none'`, and no
script `unsafe-inline` or `unsafe-eval`. The layout's style block also receives a
nonce, but the existing views still contain **inline style attributes**. Tests
explicitly allow `style-src-attr 'unsafe-inline'`; hosts forbidding those attributes
will not get the intended styling. This is script-policy compatibility, not full
strict-style CSP support. Moving the remaining styles into classes/assets remains
open; hosts should not weaken script policy to accommodate dashboard controls.

The dashboard body explicitly opts out of Turbo Drive (`data-turbo="false"`).
Links and forms use native navigation even when the host has loaded Turbo. The
handwritten method-link/form synthesizer is removed; Rails forms carry their own
CSRF token and `_method` where needed. Beskar does not require Rails UJS, Turbo,
an import map, or a JavaScript bundler for its dashboard. Mutation redirects use
the existing Rails redirect flow; no new client-side submission protocol is added.

With JavaScript disabled or the behavior script blocked, normal new/edit/review
forms still work. Temporary fields and bulk controls remain available; server
authorization, reasons, validation, and CSRF remain mandatory. Quick edit buttons,
preview, selection helpers, automatic page-size submission, and bulk confirmation
dialogs are enhancements. A visible page-size submit button works without scripts.
Changing page size preserves filters, drops the old page number, and avoids duplicate
hidden `per_page` inputs. Row unban actions still require a separate review form;
bulk confirmation dialogs require JavaScript.

## Browser verification and remaining limits

Browser tests use the standard [Rails system-test integration](https://api.rubyonrails.org/v8.0/classes/ActionDispatch/SystemTestCase.html)
with Capybara and Selenium, installed only in the development project's test bundle.
Turbo Rails is a test-only dependency used to load the real host library, not a new
runtime dependency of Beskar. Run separately from the ordinary suite:

```sh
mise exec -- env PARALLEL_WORKERS=1 bin/rails test test/system/dashboard_test.rb
```

Use an installed Chrome/Chromium and matching ChromeDriver. Optional
`BESKAR_BROWSER_BINARY` and `BESKAR_BROWSER_DRIVER` select their paths; otherwise the
harness discovers local binaries/driver, with Selenium's usual fallback when no
driver is installed. Each test gets a fresh browser process. The local run uses
Chromium/ChromeDriver 152.0.7977.82 and Ruby 4.0.6. It does not use a production
account, copy the project runtime, or disable Chromium's sandbox.

Coverage includes UTC edits with multiple browser zones and DST-boundary dates,
microsecond preservation, server-relative presets with a skewed browser clock,
permanent/temporary toggles, persistent validation feedback/retry, bulk clear/cancel/
confirm, page-size filters, actual Turbo-loaded navigation, back navigation, no
duplicate audit operations, and JavaScript-disabled create/review/delete with real
CSRF protection. Browser console checks reject script/CSP errors (excluding a
missing favicon and the deliberately tested validation response's HTTP 422).
Screenshot inspection supplemented functional checks.

CI now includes a separate browser job with a
[matching Chrome/driver setup](https://github.com/browser-actions/setup-chrome).
That hosted job has not been executed here. Other browsers, full strict-style CSP,
mobile/accessibility review, arbitrary host layouts/authentication integrations,
Turbo Frames/Streams, and transactional stale-form protection remain unverified
or out of scope for this batch. No new database migration is required for batch
nine; the preceding administrative-history migration and actor configuration still
apply. Update scripted callers that previously relied on local-zone timestamps or
loosely parsed duration strings before deploying.
