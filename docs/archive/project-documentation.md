# Archived Beskar project overview

This overview predates the September 2026 remediation. Its cache and enforcement
descriptions are historical. Consult [State storage](../operations/state-storage.md) for the
current coordination contract, [Authentication](../guides/authentication.md) for current
admission/session integration, [Risk scoring](../guides/risk-scoring.md) for scored evidence
and removal of implicit trust discounts, [Audit data and WAF](../guides/audit-and-waf.md) for current
capture/export and matching behavior, [Dashboard and search](../guides/dashboard-and-search.md)
for current reporting/search/routes and UTC/CSP/browser behavior, [Configuration](../guides/configuration.md) for validation
and supported capabilities, [Notifications and recovery](../guides/notifications-and-recovery.md)
for opt-in delivery/host recovery, [Audit lifecycle](../guides/audit-lifecycle.md) for retained
events and administrative history, and [Repair status](../audits/repair-status.md) for verified
fixes and open findings. Local verification uses mise default Ruby 4.0.6.

## Quick Reference for Coding Agents

This document provides a comprehensive overview of the Beskar security engine project structure, architecture, and key implementation details for efficient coding sessions.

## Project Overview

**Beskar** is a Rails-native security engine (Rails 8.0+) that provides multi-layered protection for web applications. It's built as a mountable Rails Engine with minimal external dependencies.

### Core Information
- **Name**: Beskar
- **Version**: 0.1.0
- **Type**: Rails Engine (mountable)
- **Rails Version**: >= 8.0.0
- **Ruby Version**: Compatible with Ruby 3.x
- **License**: MIT
- **Author**: Maciej Litwiniuk

### Latest Release (v0.1.0)
- **Release Date**: 2024-12-20
- **Major Change**: Monitor-only mode refactored to top-level configuration
- **Breaking Change**: `config.waf[:monitor_only]` → `config.monitor_only`
- **Key Feature**: Ban records now created even in monitor-only mode for verification
- **Migration Required**: See [Current upgrade guidance](../operations/security-hardening.md)
- **Full Changelog**: See [CHANGELOG.md](../../CHANGELOG.md)

### Key Dependencies
- `rails` >= 8.0.0
- `maxminddb` ~> 0.1 (for GeoIP functionality)
- Development: `devise`, `debug`, `factory_bot_rails`, `mocha`
- Dashboard: No external CSS dependencies - uses embedded styles

## Architecture Overview

### Project Structure
```
beskar/
├── app/
│   ├── models/beskar/          # Active Record models
│   ├── controllers/beskar/     # Dashboard controllers
│   ├── jobs/                   # Background jobs
│   └── views/beskar/           # Dashboard views with embedded styles
├── lib/
│   ├── beskar/
│   │   ├── middleware/         # Rack middleware for request analysis
│   │   ├── models/             # Concerns and modules for user models
│   │   ├── services/           # Core service objects
│   │   ├── templates/          # Installation templates
│   │   ├── configuration.rb   # Configuration class
│   │   ├── engine.rb          # Rails engine definition
│   │   ├── logger.rb          # Centralized logging system
│   │   └── version.rb         # Version constant
│   └── tasks/                  # Rake tasks
├── db/migrate/                 # Database migrations
├── test/                       # Test suite
└── config/                     # Engine configuration
```

## Core Components

### 0. Dashboard Authentication (`app/controllers/beskar/application_controller.rb`)

#### ApplicationController
- **Purpose**: Base controller for all dashboard endpoints with mandatory authentication
- **Security Model**: Authentication REQUIRED for all environments (no defaults)
- **Key Features**:
  - Clean, maintainable authentication flow with single responsibility methods
  - Helpful error messages with configuration examples when authentication not configured
  - Support for any authentication strategy (Devise, token-based, HTTP Basic, custom)
  - Consistent error handling for both HTML and JSON responses
  - CSRF protection enabled
  - Helper methods for formatting timestamps, risk levels, and geolocation data

- **Authentication Flow**:
  ```ruby
  authenticate_admin!
    ↓
  Configuration present? → No → show_helpful_error_with_examples (401)
    ↓ Yes
  handle_custom_authentication
    ↓
  Call config.authenticate_admin.call(request)
    ↓
  true → allow access | false → unauthorized (401) | exception → log + unauthorized (401)
  ```

- **Configuration Required**:
  ```ruby
  # config/initializers/beskar.rb
  Beskar.configuration.authenticate_admin = ->(request) do
    # Return truthy to allow access, falsey to deny
    # Examples in initializer template
  end
  ```

- **Design Principles**:
  - No environment-based defaults (prevents production surprises)
  - Authentication must be explicitly configured
  - Clear separation between authentication logic and error handling
  - All paths return explicit true/false values
  - Comprehensive test coverage (42 tests, 122 assertions)

### 1. Models (`app/models/beskar/`)

#### BannedIp
- **Purpose**: Tracks IP addresses that are banned from the application
- **Key Fields**: 
  - `ip_address`: The banned IP
  - `reason`: Why it was banned (rate_limit_abuse, authentication_abuse, waf_violation)
  - `expires_at`: When the ban expires (nil for permanent)
  - `permanent`: Boolean flag
  - `violation_count`: Number of violations
  - `metadata`: JSON field for additional data
- **Key Methods**:
  - `.ban!(ip_address, reason:, duration:, ...)`: Ban an IP
  - `.banned?(ip_address)`: Check if IP is banned
  - `.preload_cache!`: Load banned IPs into cache
  - `#extend_ban!`: Extend existing ban (escalating durations)

#### SecurityEvent
- **Purpose**: Comprehensive audit log of security-related events
- **Key Fields**:
  - `user`: Polymorphic association (optional)
  - `event_type`: Type of event (login_success, login_failed, account_locked, etc.)
  - `ip_address`: Source IP
  - `user_agent`: Browser/client info
  - `risk_score`: Calculated risk (0-100)
  - `metadata`: JSON with event details
- **Event Types**:
  - Authentication: `login_success`, `login_failed`, `account_locked`
  - WAF: `waf_violation`, `vulnerability_scan`
  - Rate Limiting: `rate_limit_exceeded`
  - Patterns: `brute_force_attempt`, `credential_stuffing`

### 2. Services (`lib/beskar/services/`)

#### RateLimiter
- **Purpose**: Distributed rate limiting using Rails.cache
- **Key Methods**:
  - `.check_ip_rate_limit(ip)`: Check IP-based limits
  - `.check_account_rate_limit(user_id)`: Check account-based limits
  - `.is_rate_limited?(request, user)`: Combined check
- **Configuration**: Three tiers (IP, account, global) with configurable limits and periods

#### WAF (Web Application Firewall)
- **Purpose**: Detect and block vulnerability scanning attempts
- **Categories**:
  - `wordpress`: WordPress-specific paths
  - `php_admin`: PHPMyAdmin and similar
  - `config_files`: .env, .git, database.yml
  - `path_traversal`: Directory traversal attempts
  - `framework_debug`: Debug endpoints
  - `cms_scan`: CMS detection attempts
  - `common_exploits`: Known exploit files
- **Rails Exception Detection**:
  - `ActionController::UnknownFormat`: Unusual format requests (Medium severity)
  - `ActionDispatch::RemoteIp::IpSpoofAttackError`: IP spoofing attempts (Critical severity)
  - `ActionDispatch::Http::MimeNegotiation::InvalidType`: Invalid MIME types (Medium severity)
  - `ActiveRecord::RecordNotFound`: Record enumeration attempts (Low severity, configurable exclusions)
- **Key Methods**:
  - `.analyze_request(request)`: Check for vulnerability patterns
  - `.analyze_exception(exception, request)`: Analyze Rails exceptions as threats
  - `.should_block?(ip)`: Determine if IP should be blocked
  - `.record_violation(ip, analysis)`: Log violation and potentially ban

#### AccountLocker
- **Purpose**: Risk-based account locking with Devise integration
- **Risk Factors**:
  - Geographic anomalies (impossible travel)
  - Device fingerprints (bot detection)
  - Login velocity patterns
  - IP reputation
- **Adaptive Learning**: Reduces risk scores for established patterns after successful unlocks
- **Key Methods**:
  - `#should_lock?`: Check if account should be locked based on risk
  - `#lock!`: Lock the account (Devise or custom)
  - `#unlock!`: Unlock the account

#### GeolocationService
- **Purpose**: IP geolocation using MaxMind databases
- **Providers**:
  - `:maxmind`: Real MaxMind GeoLite2/GeoIP2 database
  - `:mock`: Mock data for development/testing
- **Key Methods**:
  - `.lookup(ip)`: Get location data
  - `.calculate_distance(coord1, coord2)`: Haversine distance
  - `.impossible_travel?(locations, time_diff)`: Detect impossible travel

#### IpWhitelist
- **Purpose**: Allow trusted IPs to bypass blocking
- **Features**:
  - Support for single IPs and CIDR ranges
  - IPv4 and IPv6 support
  - Still logs all activity for audit
- **Key Methods**:
  - `.whitelisted?(ip)`: Check if IP is whitelisted
  - `.add(ip_or_range)`: Add to whitelist
  - `.remove(ip_or_range)`: Remove from whitelist

#### DeviceDetector
- **Purpose**: Analyze user agents for risk assessment
- **Detection**:
  - Known bot signatures
  - Suspicious patterns
  - Missing/malformed user agents
- **Key Methods**:
  - `.detect(user_agent)`: Analyze and return device info
  - `.is_bot?(user_agent)`: Check for bot signatures

### 3. Logger (`lib/beskar/logger.rb`)

#### Beskar::Logger
- **Purpose**: Centralized logging system with consistent formatting
- **Features**:
  - Automatic `[Beskar]` or `[Beskar::Component]` prefix formatting
  - Component name aliasing for cleaner output
  - Configurable log levels and output backends
  - Include module for automatic component detection in classes
- **Key Methods**:
  - `.debug/info/warn/error/fatal(message, component:)`: Log at specific levels
  - `.logger=`: Set custom logger backend
  - `.level=`: Set minimum log level
  - `.component_aliases=`: Configure component name mappings
- **Usage**:
  ```ruby
  # Simple logging
  Beskar::Logger.info("User authenticated")
  
  # With component
  Beskar::Logger.warn("Rate limit exceeded", component: :WAF)
  
  # In classes
  class MyService
    include Beskar::Logger
    def process
      log_info("Processing...")  # Auto-uses class name as component
    end
  end
  ```

### 4. Middleware (`lib/beskar/middleware/`)

#### RequestAnalyzer
- **Purpose**: Main entry point for request security analysis
- **Processing Order**:
  1. Check IP whitelist status
  2. Check if IP is banned
  3. Apply rate limiting
  4. Analyze WAF patterns
  5. Process request or block
- **Responses**:
  - 403 Forbidden: Banned IP or WAF violation
  - 429 Too Many Requests: Rate limited
  - Normal processing: Allowed through

### 5. User Model Concerns (`lib/beskar/models/`)

#### SecurityTrackable
- **Purpose**: Main module for Devise integration (backward compatibility)
- **Usage**: `include Beskar::SecurityTrackable` in User model
- **Delegates to**: SecurityTrackableDevise

#### SecurityTrackableDevise
- **Purpose**: Devise-specific authentication tracking
- **Features**:
  - Automatic success/failure tracking
  - Risk score calculation
  - Account locking integration
  - Warden callback hooks

#### SecurityTrackableAuthenticable
- **Purpose**: Rails 8 has_secure_password integration
- **Features**: Similar to Devise module but for native Rails auth

#### SecurityTrackableGeneric
- **Purpose**: Shared functionality across all auth systems
- **Core Methods**:
  - `track_authentication_event(request, outcome)`: Main tracking method
  - `calculate_authentication_risk(request)`: Risk score calculation
  - `lock_if_high_risk!(security_event, request)`: Auto-lock logic

## Database Schema

### beskar_security_events
```sql
- id: bigint (primary key)
- user_type: string (polymorphic)
- user_id: bigint (polymorphic)
- event_type: string (required)
- ip_address: string
- attempted_email: string
- user_agent: text
- metadata: json
- risk_score: integer (0-100)
- created_at: datetime
- updated_at: datetime

Indexes: ip_address, event_type, attempted_email, created_at, risk_score, composite
```

### beskar_banned_ips
```sql
- id: bigint (primary key)
- ip_address: string (unique, required)
- reason: string (required)
- details: text
- banned_at: datetime (required)
- expires_at: datetime (null = permanent)
- permanent: boolean (default: false)
- violation_count: integer (default: 1)
- metadata: text (JSON)
- created_at: datetime
- updated_at: datetime

Indexes: ip_address (unique), banned_at, expires_at, composite
```

## Configuration Structure

Configuration is managed through `Beskar::Configuration` class, accessed via `Beskar.configuration`.

### Main Configuration Blocks

```ruby
Beskar.configure do |config|
  # ============================================================================
  # Dashboard Authentication (REQUIRED)
  # ============================================================================
  # Configure authentication for the Beskar dashboard.
  # This is REQUIRED and must be set for all environments.
  #
  # The authenticate_admin callback receives the request object and is executed
  # in the controller context, giving you access to all controller methods
  # (cookies, session, authenticate_or_request_with_http_basic, etc.).
  # The block should return truthy value to allow access, falsey to deny.
  #
  # Example 1: Devise with admin role (recommended for production)
  config.authenticate_admin = ->(request) do
    user = request.env['warden']&.authenticate(scope: :user)
    user&.admin?
  end
  #
  # Example 2: Simple token-based authentication
  # config.authenticate_admin = ->(request) do
  #   token = ENV['BESKAR_ADMIN_TOKEN']
  #   token.present? && Beskar::Services::RequestContext.secure_match?(request.headers['Authorization'], "Bearer #{token}")
  # end
  #
  # Example 3: For development/testing only (NOT for production!)
  # config.authenticate_admin = ->(request) do
  #   Rails.env.development? || Rails.env.test?
  # end
  #
  # Example 4: HTTP Basic Auth (uses controller method)
  # config.authenticate_admin = ->(request) do
  #   authenticate_or_request_with_http_basic do |username, password|
  #     Beskar::Services::RequestContext.secure_match?(username, ENV['BESKAR_USERNAME']) &&
  #       Beskar::Services::RequestContext.secure_match?(password, ENV['BESKAR_PASSWORD'])
  #   end
  # end
  #
  # Example 5: Cookie-based authentication (uses controller cookies)
  # config.authenticate_admin = ->(request) do
  #   Beskar::Services::RequestContext.secure_match?(cookies.signed[:admin_token], ENV['BESKAR_ADMIN_TOKEN'])
  # end

  # ============================================================================
  # Global Monitor-Only Mode (affects all blocking features)
  # ============================================================================
  config.monitor_only = true  # Start with true in production, set to false when ready

  # Security Tracking
  config.security_tracking = {
    enabled: true,
    track_successful_logins: true,
    track_failed_logins: true,
    auto_analyze_patterns: true
  }

  # Rate Limiting
  config.rate_limiting = {
    ip_attempts: { limit: 10, period: 1.hour, exponential_backoff: true },
    account_attempts: { limit: 5, period: 15.minutes, exponential_backoff: true },
    global_attempts: { limit: 100, period: 1.minute, exponential_backoff: false }
  }

  # WAF Configuration
  config.waf[:enabled] = true
  config.waf[:auto_block] = true
  config.waf[:block_threshold] = 3
  config.waf[:violation_window] = 1.hour
  config.waf[:block_durations] = [1.hour, 6.hours, 24.hours, 7.days]
  config.waf[:permanent_block_after] = 5
  config.waf[:create_security_events] = true

  # Risk-Based Locking
  config.risk_based_locking = {
    enabled: false,
    risk_threshold: 75,
    lock_strategy: :devise_lockable,
    auto_unlock_time: 1.hour,
    notify_user: true,
    log_lock_events: true,
    immediate_signout: false
  }

  # IP Whitelist
  config.ip_whitelist = [
    "192.168.1.100",
    "10.0.0.0/24"
  ]

  # Geolocation
  config.geolocation = {
    provider: :mock,  # or :maxmind
    maxmind_city_db_path: nil,
    cache_ttl: 4.hours
  }
end
```

## Key Features Implementation

### ⚠️ BREAKING CHANGE in v0.1.0
**Monitor-only mode is now a top-level configuration setting.** 
- Previous: `config.waf[:monitor_only]` 
- Current: `config.monitor_only`
- See `BREAKING_CHANGES.md` for migration guide

### 1. Monitor-Only Mode (Global)
- Set `config.monitor_only = true` (top-level setting affecting all blocking features)
- Creates ban records and security events normally
- Logs violations without actually blocking requests
- Ban records exist in database but are not enforced
- Useful for initial deployment, testing, and verification
- Allows you to query `Beskar::BannedIp` to see what would be blocked

### 2. Adaptive Risk Learning
- After 2+ successful logins from an IP, location becomes "established"
- Risk scores reduced to 30% for established patterns (max 25)
- Prevents repeated locks after user validation
- Stored in SecurityEvent metadata

### 3. Escalating Ban Durations
- Progressive bans: 1 hour → 6 hours → 24 hours → 7 days → permanent
- Applied to both rate limiting and WAF violations
- Violation count tracked in BannedIp model

### 4. Hybrid Blocking System
- **Cache Layer**: Fast checks via Rails.cache
- **Database Layer**: Persistent storage, survives restarts
- **Preloading**: BannedIps loaded into cache on startup

## Installation & Setup

### Installation Task
```bash
bin/rails beskar:install
```
This task:
1. Copies migrations to host app
2. Creates initializer at `config/initializers/beskar.rb`
3. Displays setup instructions

### Manual Setup Steps
1. Run migrations: `bin/rails db:migrate`
2. Add to User model: `include Beskar::SecurityTrackable`
3. Configure in initializer
4. Monitor for 24-48 hours with monitor_only mode
5. Review logs and adjust configuration
6. Disable monitor_only when ready

## Testing Structure

### Test Organization
```
test/
├── dummy/              # Dummy Rails app for testing
├── factories/          # FactoryBot factories
├── integration/        # Integration tests
├── models/            # Model tests
├── services/          # Service tests
└── test_helper.rb     # Test configuration
```

### Key Test Patterns
- Uses Minitest framework
- FactoryBot for fixtures
- Mocha for mocking
- Tests run against dummy Rails app

## Development Workflow

### Running Tests
```bash
cd beskar
bundle exec rails test
```

### Console Access
```bash
cd beskar/test/dummy
bin/rails console
```

### Key Development Files
- `beskar.gemspec`: Gem specification
- `lib/beskar/version.rb`: Version management
- `lib/beskar.rb`: Main module file
- `lib/beskar/engine.rb`: Engine configuration

## Common Patterns & Conventions

### Error Handling
- Services use safe error handling with logging
- Never break request flow for tracking failures
- Return nil or safe defaults on errors

### Logging
- **Centralized System**: All logging through `Beskar::Logger`
- **Automatic Formatting**: Component prefixes added automatically
- **Component Aliases**: Clean names (e.g., `Beskar::Services::Waf` → `WAF`)
- **Levels**: DEBUG for details, INFO for events, WARN for issues, ERROR for failures, FATAL for critical
- **Monitor-only mode**: Uses emoji indicators (🔍, 🔒)
- **Usage Examples**:
  ```ruby
  # Direct usage
  Beskar::Logger.info("Message")
  Beskar::Logger.warn("Warning", component: :WAF)
  
  # In classes
  include Beskar::Logger
  log_error("Error occurred")
  ```

### Cache Keys
- Namespaced: `beskar:feature:identifier`
- Examples:
  - `beskar:banned_ip:192.168.1.1`
  - `beskar:waf_violations:192.168.1.1`
  - `beskar:rate_limit:ip:192.168.1.1`

### Polymorphic Associations
- SecurityEvent uses polymorphic `user` association
- Supports multiple user types (User, Admin, etc.)
- Auto-detection via Devise mappings

## API Quick Reference

### Public Module Methods
```ruby
Beskar.configure { |config| ... }
Beskar.configuration
Beskar.rate_limiter
Beskar.rate_limited?(request, user)
```

### Logger Methods
```ruby
Beskar::Logger.debug(message, component: nil)
Beskar::Logger.info(message, component: nil)
Beskar::Logger.warn(message, component: nil)
Beskar::Logger.error(message, component: nil)
Beskar::Logger.fatal(message, component: nil)
Beskar::Logger.logger = custom_logger
Beskar::Logger.level = :warn
Beskar::Logger.component_aliases = { 'MyClass' => 'MC' }
```

### User Model Methods (with SecurityTrackable)
```ruby
user.security_events
user.track_authentication_event(request, :success/:failed)
user.calculate_authentication_risk(request)
user.recent_failed_attempts(time_window)
```

### Service Class Methods
```ruby
Beskar::BannedIp.ban!(ip, reason: ..., duration: ...)
Beskar::BannedIp.banned?(ip)
Beskar::Services::Waf.analyze_request(request)
Beskar::Services::RateLimiter.check_ip_rate_limit(ip)
Beskar::Services::IpWhitelist.whitelisted?(ip)
Beskar::Services::GeolocationService.lookup(ip)
```

## Important Considerations

### Performance
- Uses Rails.cache extensively (configure appropriately)
- Database queries optimized with indexes
- Preloading of banned IPs on startup
- Async job processing for pattern analysis

### Security
- No external service dependencies by default
- MaxMind database must be provided by user (licensing)
- All events logged for audit trail
- Whitelisted IPs still tracked but never blocked

### Compatibility
- Rails 8.0+ required
- Works with Devise out of the box
- Supports Rails native authentication (has_secure_password)
- Database-agnostic (SQLite, PostgreSQL, MySQL)

## Future Enhancements (Planned)
- Real-time security dashboard (mounted route)
- Email notifications for security events
- Advanced bot detection with JavaScript challenges
- Honeypot fields for form protection
- API rate limiting endpoints
- WebAuthn support for high-risk accounts

## Debugging Tips

### Check Security Events
```ruby
Beskar::SecurityEvent.where(event_type: 'waf_violation').recent
Beskar::SecurityEvent.where(user: some_user).order(created_at: :desc)
```

### Monitor Banned IPs
```ruby
Beskar::BannedIp.active
Beskar::BannedIp.by_reason('waf_violation')
```

### Test WAF Patterns
```ruby
request = ActionDispatch::Request.new(env)
Beskar::Services::Waf.analyze_request(request)
```

### Check Rate Limiting
```ruby
Beskar::Services::RateLimiter.check_ip_rate_limit('192.168.1.1')
```

## Support & Resources
- GitHub: https://github.com/humadroid-io/beskar
- Homepage: https://humadroid.io/beskar
- Changelog: [CHANGELOG.md](../../CHANGELOG.md)
- Breaking Changes: [Current upgrade guidance](../operations/security-hardening.md)
- Author: Maciej Litwiniuk (maciej@litwiniuk.net)
