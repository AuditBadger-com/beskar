# Changelog

All notable changes to Beskar will be documented in this file.

The entries below include historical behavior. For the current contract and
upgrade requirements, use the [documentation index](docs/README.md) and
[repair status](docs/audits/repair-status.md).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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


### Versioning Policy

- **Major version (X.0.0)**: Breaking changes that require code changes
- **Minor version (0.X.0)**: New features, backward compatible
- **Patch version (0.0.X)**: Bug fixes and minor improvements

### Upgrade Guide

When upgrading between versions with breaking changes:

1. Read the [Current upgrade guidance](docs/operations/security-hardening.md) file
2. Update your configuration according to the migration guide
3. Run any new migrations: `rails db:migrate`
4. Test in development/staging before deploying to production
5. Start with `monitor_only = true` to verify behavior

### Support

- GitHub Issues: https://github.com/humadroid-io/beskar/issues
- Documentation: https://humadroid.io/beskar

---

[Unreleased]: https://github.com/humadroid-io/beskar/compare/v0.0.2...HEAD
