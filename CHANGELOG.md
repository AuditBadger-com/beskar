# Changelog

All notable changes to Beskar will be documented in this file.

The entries below include historical behavior. For the current contract and
upgrade requirements, use the [documentation index](docs/README.md) and
[repair status](docs/audits/repair-status.md).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Fixed

- Monitor mode and whitelisted addresses no longer deny a login when one request
  sets a second user on a scope. Each user is recorded as a login of its own.
  Enforcement still denies it as `identity_changed`.
- A request with no usable client address no longer raises
  `IPAddr::InvalidAddressError` in the middleware. `RequestContext.ip` returns nil,
  and the middleware passes the request to the application without ban or WAF
  checks. A login from such a request succeeds without an audit row. Logins
  through non-password Warden strategies (such as OAuth) from such a request also
  reach authentication; rate limiting with no applicable tier is now an allowed
  no-op instead of raising `ArgumentError`.

## 0.2.0 - 2026-09-21

Security hardening, coordinated enforcement, and auditable administration.
This release includes breaking changes for 0.1.0 installations; read the
[rollout checklist](docs/operations/security-hardening.md#rollout) before upgrading.

### Breaking changes

- Security state is now coordinated through the database, independently of the
  `Rails.cache` backend. Apply the new state and administrative-history migrations
  before starting upgraded workers. Users, sessions, and security state must share
  the writer connection pool; old cache counters are not imported.
- Dashboard authentication no longer grants administrative permissions by itself.
  Configure `authorize_admin` separately for `:read`, `:manage_bans`, `:export`,
  and `:read_audit`. Ban mutations and exports require a trusted `audit_actor`,
  a reason, and successfully recorded administrative history.
- Configuration is validated and sealed at startup. Invalid or unsupported
  settings stop boot; direct runtime mutation is rejected. Runtime changes through
  `Beskar.configure` require separate authorization, actor/reason/request context,
  and an audit record. Runtime publication remains process-local.
- Global authentication budgets and request-wide blocking for exhausted IP login
  quotas now default off. Opt in with `global_attempts[:enabled]` and
  `ip_attempts[:block_requests]` under `rate_limiting` if those policies are needed.
  Notifications and automatic pattern analysis also default off and require
  explicit host configuration when enabled.
- Monitor-only mode records observations in separate state without automatically
  creating IP bans, locking accounts, or resetting passwords. Review bans created
  by older monitor-mode versions before enabling enforcement; existing bans are
  not automatically removed.
- Devise session and remember-cookie salts now include a durable revocation
  generation, causing a one-time sign-out of existing credentials. Confirmed locks
  revoke prior credentials regardless of `immediate_signout`; unlocking does not
  restore them. Risk-based locking itself remains opt-in.
- Rails-native authentication must use the admission, session-creation, and
  session-resumption guards. OAuth, custom tokens, API controllers, and Action Cable
  require the appropriate host integration; they are not automatically protected
  merely by mounting the engine.
- Deleting an account retains its security events unchanged, including their
  original account identifiers. Security events and administrative history reject
  ordinary model-level rewrites/deletes. This is not anonymization or protection
  against privileged SQL/bulk updates; hosts still own retention policy.
- Exports are bounded to 1,000 rows per cursor page and use filtered fields and
  CSV formula-injection defenses. Scripted consumers must supply an audit reason
  on every page and accommodate the revised export contract.

### Added

- Framework-neutral authentication admission, API and Action Cable session guards,
  explicit session revocation, and persistent Rails-native account locks with
  automatic or manual-only unlock policies.
- An append-only administrative journal and read-only history dashboard for ban
  changes, export preparation, and authorized runtime configuration changes, with
  actor, reason, request/operation correlation, and filtered before/after state.
- Opt-in post-commit notification delivery jobs with bounded retries, plus an
  explicit host-job contract for background analysis. Password recovery remains
  owned by the host application or Devise; no built-in analyzer or recovery-token
  issuer is supplied.
- Organized, gem-packaged guides and operational contracts under `docs/`, including
  authentication coverage, deployment requirements, and remaining limitations.
- Complete dashboard initializer examples for Rails built-in authentication and
  Devise, including permission checks and audit identity. The Rails example checks
  the signed session cookie and session revocation, with explicit instructions to
  include `SecurityTrackableAuthenticable` in the host user model. Installation
  guidance explains Devise's Warden scopes and the dashboard controller context.

### Security and fixes

- Enforce Devise password/HTTP Basic admission before credential verification;
  coordinate IP/account limits and backoff across workers without double-counting
  outcomes. Required enforcement-state failures deny access while optional audit
  failures do not undo authentication decisions.
- Honor monitor/whitelist policy for automatic enforcement and isolate observation
  counters. Whitelisted attempts do not consume enforced global capacity.
- Fix lost updates in rate-limit/WAF state, concurrent ban extensions, and mixed
  administrative/automatic changes. MySQL locking reads prevent stale transaction
  snapshots from overwriting ban updates or missing sessions during revocation;
  native cleanup also ignores stale loaded associations and preserves callbacks.
- Read ban decisions from the authoritative database, preserve permanent bans
  during cleanup, normalize individual IP addresses, and reject invalid durations.
  Administrative extensions no longer fabricate additional violations.
- Retain security events after account deletion, tolerate missing accounts in
  dashboards/exports, and make bulk administrative changes and their history
  transactional. Failed or aborted persistence no longer reports success.
- Bound and filter audit metadata, headers, identities, and error logging; use
  Rails-resolved client IPs and consistent Rack 3 headers and retry deadlines.
- Correct timestamped geographic risk history, impossible-travel calculations,
  provider/cache isolation, and shared decision/audit evidence. Mock geography
  cannot supply geographic risk evidence; repeated IP use and unlocks no longer
  grant implicit trust discounts.
- Narrow WAF exception scoring to relevant evidence by default, improve path
  canonicalization and exclusions, and prevent duplicate charges for one request.
- Fix dashboard reporting/search/pagination, UTC and DST-sensitive ban editing,
  unchanged microsecond expiry preservation, persistent validation messages, and
  nonce-based scripts. Native forms retain CSRF protection and work with JavaScript
  disabled or host Turbo loaded.
- Fix migration installation, MySQL JSON defaults and foreign-key types, Ruby 4
  test dependencies, Chrome sandbox setup, and browser navigation synchronization.
  CI covers Ruby 3.4/4.0, SQLite, PostgreSQL, MySQL, and Chromium system tests.

### Removed

- Nonfunctional versioned API routes and their helpers. Dashboard resource exports
  remain available behind their dedicated permissions.
- Claims of support for unimplemented capabilities: general SQL injection/XSS
  filtering, JavaScript challenges, honeypots, and a built-in automatic pattern
  analyzer. Unsupported custom lock strategies and geolocation providers are
  rejected rather than silently accepted.

### Upgrading from 0.1.0

1. Copy and apply all engine migrations with `bin/rails beskar:install:migrations`
   and `bin/rails db:migrate`, including the administrative-action target expansion.
2. Configure administrative permissions, actor resolution, and reasons; review
   [configuration](docs/guides/configuration.md) and
   [audit lifecycle](docs/guides/audit-lifecycle.md) for the changed contracts.
3. Adopt the [authentication guards](docs/guides/authentication.md), review all
   credential entry points, and plan the one-time Devise sign-out. Legacy custom
   tokens without a revocation generation must be rejected or reissued.
4. Drain old workers and restart from the same reviewed configuration. Review
   legacy bans and risk evidence in monitor mode before enforcing, and schedule
   `bin/rails beskar:cleanup_security_state` to reclaim expired enforcement state.
   This task does not purge audit events or account-lifetime revocation generations.
5. Validate host recovery/delivery, shared-NAT behavior, and database load/failure
   handling in staging. Cache independence does not remove database availability
   requirements or establish production capacity guarantees.

## 0.1.0 - 2025-11-25

Historical notes carried forward from the 0.1.0 release. In particular, the
monitor-mode ban creation described below is superseded by 0.2.0.

### ⚠️ BREAKING CHANGES

- **Monitor-only mode refactored to top-level configuration**
  - `config.waf[:monitor_only]` has been **removed**
  - Use `config.monitor_only = true/false` at the configuration root level instead
  - The method `Beskar.configuration.waf_monitor_only?` has been **removed**
  - Use `Beskar.configuration.monitor_only?` instead
  - See [Current upgrade guidance](docs/operations/security-hardening.md) for detailed migration guide

- **Dashboard authentication now required in all environments**
  - Previous behavior: Dashboard allowed access in development/test without authentication
  - New behavior: `config.authenticate_admin` must be explicitly configured for all environments
  - **Why this change**: Prevents production security surprises by requiring explicit authentication setup
  - **Migration**: Add `config.authenticate_admin` proc to your initializer (see examples in template)
  - Developers who want to bypass auth in development must explicitly configure it

### Added

- Ban records (`Beskar::BannedIp`) are now created even in monitor-only mode
  - Provides full visibility into what would be blocked
  - Allows querying `Beskar::BannedIp.active` to see potential blocks
  - Makes verification and testing much more reliable
- Global monitor-only mode affecting all blocking features (WAF, rate limiting, IP bans)
- **Centralized logging system** (`Beskar::Logger`)
  - Consistent log formatting with automatic `[Beskar]` or `[Beskar::Component]` prefixes
  - Component name aliasing for cleaner output (e.g., `Beskar::Services::Waf` → `WAF`)
  - Configurable log levels and output backends
  - Include module support for automatic component detection in classes
  - Single point of configuration for all logging
- **Security Dashboard** - Mountable web interface for monitoring and managing security
  - Real-time security event monitoring with advanced filtering and pagination
  - IP ban management with bulk actions, extend, and unban capabilities
  - Statistics overview with risk distribution and threat analysis
  - Export functionality for security events and banned IPs (CSV/JSON)
  - Stripe-inspired minimalist design with embedded styles (no CSS dependencies)
  - Custom pagination and filtering (no Kaminari/Pagy dependency)
  - Configurable authentication via `config.authenticate_admin` proc
  - Rails 7+ compatible with built-in CSRF protection
  - Install generator for easy setup (`rails generate beskar:install`)
  - Full documentation in [Current dashboard guide](docs/guides/dashboard-and-search.md)
- **WAF Rails Exception Detection** - Enhanced security through Rails exception analysis
  - Detects `ActionController::UnknownFormat` exceptions (e.g., `/users/1.exe`) as potential scanning attempts
  - Detects `ActionDispatch::RemoteIp::IpSpoofAttackError` as critical IP spoofing attacks
  - Detects `ActiveRecord::RecordNotFound` as potential record enumeration scans
  - Configurable exclusion patterns for `RecordNotFound` to prevent false positives
  - New configuration: `config.waf[:record_not_found_exclusions]` accepts regex patterns
  - Different severity levels: Critical (IP spoofing), Medium (UnknownFormat), Low (RecordNotFound)
  - Exception-based violations count toward auto-blocking thresholds
  - Works seamlessly alongside existing WAF vulnerability patterns
- **Enhanced Dashboard Authentication System**
  - Helpful error messages with configuration examples when authentication not configured
  - Clear, actionable guidance shows 4 authentication strategy examples (Devise, token-based, HTTP Basic, development bypass)
  - Error response includes properly formatted code examples in initializer format
  - Authentication configuration prominently documented at top of initializer template
  - Support for any authentication strategy via flexible proc-based configuration

### Changed

- **Refactored ApplicationController authentication for better maintainability**
  - Simplified authentication flow from deeply nested conditionals to flat, single-responsibility methods
  - Reduced method complexity: main `authenticate_admin!` is now 4 lines (was 20+ lines with 3-4 nesting levels)
  - Extracted authentication logic into focused methods:
    - `authenticate_admin!`: Routes to appropriate strategy (configuration check + delegation)
    - `handle_custom_authentication`: Executes configured authentication with error handling
    - `handle_missing_authentication_configuration`: Shows helpful error with examples
  - All authentication paths now explicitly return `true` (allow) or `false` (deny)
  - Consistent error handling for both HTML and JSON responses
  - Improved exception handling with detailed error logging
  - Added comprehensive test suite: 42 tests with 122 assertions covering all authentication scenarios

- Monitor-only mode is now a system-wide concept rather than WAF-specific
- Ban records are created but not enforced when `monitor_only = true`
- Security events include `monitor_only_mode` metadata flag
- All blocking decisions (WAF, rate limiting, authentication abuse) respect global monitor-only setting
- Improved logging with clear "MONITOR-ONLY" indicators
- Better separation of ban creation from ban enforcement
- All internal logging now uses `Beskar::Logger` instead of direct `Rails.logger` calls
- Log messages no longer require manual prefix formatting

### Fixed

- Monitor-only mode now provides actual data for verification (ban records exist)
- Consistent behavior across all security features
- Clearer semantics for what monitor-only mode means

### Security

- **Dashboard authentication hardening**: Removed environment-based authentication defaults
  - Eliminates risk of accidentally deploying without authentication configured
  - Forces explicit security decisions during initial setup
  - All environments (development, test, production) now require authentication configuration
  - Provides clear, immediate feedback when authentication is missing
  - Reduces attack surface by failing secure (deny by default)

### Documentation

- Updated README with new configuration structure
- Enhanced docs/operations/monitor-only-mode.md with examples of querying ban records
- Added migration guide in BREAKING_CHANGES.md
- Created docs/archive/project-documentation.md for development reference
- Updated docs/archive/project-documentation.md with comprehensive dashboard authentication section
  - Documented authentication flow and architecture
  - Added configuration examples and design principles
  - Included test coverage details
- Updated initializer template (`lib/beskar/templates/beskar_initializer.rb`) with prominent authentication documentation
  - Dashboard Authentication section moved to top (REQUIRED)
  - Four complete authentication strategy examples
  - Clear warnings about development-only bypass patterns


## Versioning policy

- Before 1.0, minor releases (0.X.0) may include explicitly documented breaking changes.
- Patch releases (0.X.Y) contain backward-compatible fixes.
- From 1.0 onward, breaking changes require a major version increment.

## Upgrade guide

When upgrading between versions with breaking changes:

1. Read the [Current upgrade guidance](docs/operations/security-hardening.md) file
2. Update your configuration according to the migration guide
3. Run any new migrations: `rails db:migrate`
4. Test in development/staging before deploying to production
5. Start with `monitor_only = true` to verify behavior

## Support

- [GitHub issues](https://github.com/AuditBadger-com/beskar/issues)
- [Documentation](docs/README.md)
