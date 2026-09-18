# Beskar

Implementation repairs are tracked in [Repair status](docs/audits/repair-status.md). Read [Security hardening and rollout](docs/operations/security-hardening.md) before upgrading: session revocation, explicit admin permissions, export auditing, sealed configuration, and safer availability defaults change integration requirements. The original findings remain in [Original project review](docs/audits/project-review.md).

Account deletion retains security events unchanged. Dashboard ban changes now require
a trusted actor and reason, recorded in a new administrative-history table. See
[Audit lifecycle](docs/guides/audit-lifecycle.md) for configuration and upgrade requirements.

**Beskar** is a Rails-native security engine for authentication admission limits, risk-based account locking, IP bans, scanner-path detection, and an administrative audit dashboard. It requires a shared writer database for coordinated state and explicit host authentication integration. Its heuristic signals do not replace application authorization, input validation, or recovery delivery.

## Documentation

The [documentation index](docs/README.md) organizes current guides, operational
contracts, audit findings, research, and archived reference material. Start with
[configuration](docs/guides/configuration.md) and
[authentication](docs/guides/authentication.md) for integration, or the
[rollout checklist](docs/operations/security-hardening.md#rollout) for an upgrade.

## Screenshots

![Dashboard](https://humadroid-static-assets.s3.amazonaws.com/beskar/beskar-dashboard.png)

| Security Events | Banned IPs |
|:---------------:|:----------:|
| ![Security Events](https://humadroid-static-assets.s3.amazonaws.com/beskar/beskar-security-event.png) | ![Banned IPs](https://humadroid-static-assets.s3.amazonaws.com/beskar/beskar-banned-ips.png) |

## Table of Contents

- [Documentation](#documentation)
- [Features](#features)
- [Installation](#installation)
  - [Quick Start](#quick-start)
  - [Dashboard Authentication (REQUIRED)](#dashboard-authentication-required)
  - [Add to Your User Model](#add-to-your-user-model)
- [Configuration](#configuration)
- [Usage](#usage)
  - [Risk-Based Account Locking](#risk-based-account-locking-with-devise-lockable)
  - [Rate Limiting](#rate-limiting)
  - [IP Whitelisting](#ip-whitelisting)
  - [Web Application Firewall (WAF)](#web-application-firewall-waf)
  - [IP Blocking and Banning](#ip-blocking-and-banning)
  - [Security Events](#security-events)
  - [Middleware Integration](#middleware-integration)
- [WAF Pattern Reference](#waf-pattern-reference)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## Features

For current reporting bands, search semantics, native-user presentation, UTC ban
forms, script CSP/native-navigation behavior, and dashboard/export routes, see
[Dashboard and search](docs/guides/dashboard-and-search.md).
No versioned administration API is implemented.

See [Configuration](docs/guides/configuration.md) for startup validation, supported
strategies/providers, and opt-in host background analysis. Opt-in lock/reset email
delivery and its host recovery requirements are documented in
[Notifications and recovery](docs/guides/notifications-and-recovery.md).

-   **Devise Integration:** Admission, risk assessment, optional audit tracking and durable session/remember-cookie revocation on protected models.
-   **Risk-Based Account Locking:** Opt-in rules lock supported accounts at configured thresholds. Scores are heuristics, not proof of account takeover.
-   **Rate Limiting:** Database-coordinated IP/account and opt-in global admission limits with enforced backoff deadlines. Supports any Rails.cache backend. See [authentication integration](docs/guides/authentication.md) for required host guards.
-   **Authentication Pattern Helpers:** Bounded account/IP failure-history helpers; automatic background analysis requires an explicitly configured host job.
-   **IP Whitelisting:** Trusted IPs/CIDRs bypass automatic blocking while configured observations remain enabled; optional audit delivery is not guaranteed.
-   **Persistent IP Blocking:** Database-authoritative blocking across application restarts. WAF rules and opt-in request-wide quota-abuse escalation can create automatic bans.
-   **Web Application Firewall (WAF):** Bounded, decoded-path scanner signatures and narrowly scoped Rails exception signals, with cumulative scores, escalating bans, monitor-only mode, and method/path/category exclusions. This is not a general SQL injection or XSS filter.
-   **Security Event Tracking:** Filtered authentication/WAF evidence and required administrative history. Events survive account deletion; ordinary instance rewrites/deletes are rejected.
-   **IP Geolocation:** MaxMind GeoLite2-City database integration for country/city location, coordinates, timezone, and enhanced risk scoring (configurable, database not included due to licensing).
-   **Geographic Anomaly Detection:** Timestamped, admitted-login history and Haversine-based travel heuristics with explicit evidence. Mock locations do not trigger geographic risk; see [risk scoring](docs/guides/risk-scoring.md).
-   **User-Agent Heuristics:** Browser and bot-like User-Agent signals contribute to authentication risk. Headers are spoofable; JavaScript challenges and honeypots are not implemented.
-   **Modular Architecture:** Devise-specific code is isolated in separate services for maintainability and extensibility.
-   **Rails-Native Architecture:** Built as a mountable `Rails::Engine`, with Active Record-backed security state and optional caching for enrichment.
-   **Security Dashboard:** A mountable web interface for monitoring security events, managing IP bans, and viewing statistics. Features configurable authentication, real-time filtering, and export capabilities. See [Dashboard Authentication](#dashboard-authentication-required) section below.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'beskar'
```

And then execute:

```bash
bundle install
```

Run the installation task to set up Beskar:

```bash
bin/rails beskar:install
```

This will:
- Copy all necessary migrations to your application
- Create `config/initializers/beskar.rb` with sensible defaults
- Display next steps for completing the setup

Then run the database migrations:

```bash
bin/rails db:migrate
```

### Quick Start

**1. Configure Dashboard Authentication (Required)**

Before using Beskar, you must configure authentication for the dashboard. See the [Dashboard Authentication](#dashboard-authentication-required) section below for details and examples.

**2. Enable WAF Monitoring**

By default, Beskar enables the **Web Application Firewall (WAF) in monitor-only mode**. This means:
- ✅ Vulnerability scans are detected and logged
- ✅ Security events are created for analysis
- ⚠️ No requests are blocked yet (safe to enable in production)

After monitoring for 24-48 hours, review the logs and disable monitor-only mode to enable active blocking:

```ruby
# config/initializers/beskar.rb
Beskar.configure do |config|
  config.monitor_only = true # Change this to false to enable blocking
  config.waf[:enabled] = true
  # ... rest of configuration
end
```

### Dashboard Authentication (REQUIRED)

**⚠️ IMPORTANT: Dashboard authentication must be configured for all environments.**

The Beskar dashboard requires authentication to prevent unauthorized access. You must configure how users authenticate to access the dashboard by setting up the `authenticate_admin` callback:

```ruby
# config/initializers/beskar.rb
Beskar.configure do |config|
  # REQUIRED: Configure dashboard authentication
  # The block is executed in the controller context and receives the request object.
  # You have access to all controller methods (cookies, session, etc.) and helpers.
  config.authenticate_admin = ->(request) do
    # Return truthy to allow access, falsey to deny

    # Example 1: Devise with admin role (recommended for production)
    user = request.env['warden']&.authenticate(scope: :user)
    user&.admin?
  end
  # REQUIRED: grant individual capabilities using your host permission store.
  config.authorize_admin = ->(request, permission) do
    user = request.env['warden']&.user(scope: :user)
    user&.admin? && user.beskar_permissions.include?(permission.to_s)
  end
  # Adapt beskar_permissions to your host: read, manage_bans, export, read_audit.
  # REQUIRED for dashboard writes and exports: identify the authenticated operator.
  config.audit_actor = ->(request) do
    user = request.env['warden']&.user(scope: :user)
    "User:#{user.id}" if user&.admin?
  end
end
```

**Why this is required:** Previous versions allowed unauthenticated access in development/test environments, which could lead to production security issues. Now, authentication must be explicitly configured for all environments to prevent accidental exposure.

`audit_actor` is separate from authorization. Without it, authenticated reads work
but ban mutations return 503. Every mutation also requires a nonblank `audit_reason`
(at most 1,000 characters), supplied by the dashboard forms. Apply the history
migration and adapt other authentication strategies to return a trusted opaque
operator ID; never use request parameters or credentials as that identity. See
[administrative history](docs/guides/audit-lifecycle.md).

**Other Authentication Strategies:**

```ruby
# Token-based authentication
config.authenticate_admin = ->(request) do
  token = ENV['BESKAR_ADMIN_TOKEN']
  token.present? && Beskar::Services::RequestContext.secure_match?(request.headers['Authorization'], "Bearer #{token}")
end

# HTTP Basic Auth (uses controller method)
config.authenticate_admin = ->(request) do
  authenticate_or_request_with_http_basic do |username, password|
    Beskar::Services::RequestContext.secure_match?(username, ENV['BESKAR_USERNAME']) &&
      Beskar::Services::RequestContext.secure_match?(password, ENV['BESKAR_PASSWORD'])
  end
end

# Cookie-based authentication (uses controller cookies)
config.authenticate_admin = ->(request) do
  Beskar::Services::RequestContext.secure_match?(cookies.signed[:admin_token], ENV['BESKAR_ADMIN_TOKEN'])
end

# Development/Testing bypass (use with caution!)
config.authenticate_admin = ->(request) do
  Rails.env.development? || Rails.env.test?
end
```

**Accessing the Dashboard:**

After configuring authentication, mount the engine in your routes:

```ruby
# config/routes.rb
Rails.application.routes.draw do
  mount Beskar::Engine => "/beskar"
end
```

Then visit `http://localhost:3000/beskar` to access the dashboard.

**Dashboard Features:**
- 📊 Security event monitoring with filtering and search
- 🚫 IP ban management (view, extend, unban)
- 📈 Statistics and risk distribution analysis
- 📥 Export capabilities (CSV/JSON)
- 🔒 CSRF protection and secure by default

### Add to Your User Model

Include the `SecurityTrackable` concern in your Devise user model:

```ruby
# app/models/user.rb
class User < ApplicationRecord
  include Beskar::Models::SecurityTrackable

  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable
  # ... other Devise modules
end
```

## Configuration

You can configure Beskar in the initializer file created by the installer.

> **Note:** Dashboard authentication setup is covered in the [Dashboard Authentication](#dashboard-authentication-required) section above.

```ruby
# config/initializers/beskar.rb
Beskar.configure do |config|
  # === Dashboard Authentication (REQUIRED) ===
  # See "Dashboard Authentication" section above for examples and details
  config.authenticate_admin = ->(request) do
    user = request.env['warden']&.authenticate(scope: :user)
    user&.admin?
  end

  # === Security Tracking ===
  # Controls what security events are tracked and analyzed
  config.security_tracking = {
    enabled: true,                    # Master switch - disables all tracking when false
    track_successful_logins: true,    # Track successful authentication events
    track_failed_logins: true,        # Track failed authentication attempts
    auto_analyze_patterns: false,     # Opt in only with a host-owned Active Job
    analysis_job: nil                 # Example: "SecurityReviewJob"; see docs/guides/configuration.md
  }

  # === Rate Limiting ===
  config.rate_limiting = {
    ip_attempts: {
      limit: 10,                    # Max attempts per IP
      period: 1.hour,               # Time window
      exponential_backoff: true     # Enable exponential backoff
    },
    account_attempts: {
      limit: 5,                     # Max attempts per account
      period: 15.minutes,           # Time window
      exponential_backoff: true
    },
    global_attempts: {
      enabled: false,               # Opt-in: attackers can exhaust a shared login budget
      limit: 100,                   # System-wide limit
      period: 1.minute,
      exponential_backoff: false
    }
  }

  # === IP Whitelisting ===
  # See "IP Whitelisting" section below for detailed examples
  config.ip_whitelist = []  # Add trusted IPs here (supports CIDR notation)

  # === Web Application Firewall (WAF) ===
  # See "Web Application Firewall" section below for production examples
  # Defaults shown here - use [:key] syntax to preserve other defaults
  config.waf[:enabled] = true                        # Master switch for WAF
  # config.waf[:auto_block] = true                   # Default: true
  # config.waf[:score_threshold] = 150               # Default: 150 (cumulative risk score before blocking)
  # config.waf[:violation_window] = 6.hours          # Default: 6 hours (max time to track violations)
  # config.waf[:block_durations] = [1.hour, 6.hours, 24.hours, 7.days] # Escalating bans
  # config.waf[:permanent_block_after] = 500         # Permanent after cumulative score reaches 500
  # config.waf[:create_security_events] = true       # Log to SecurityEvent table
  # config.waf[:record_not_found_exclusions] = []    # Regex patterns for false positives
  # config.waf[:decay_enabled] = true                # Enable exponential decay of violation scores
  # config.waf[:decay_rates] = {                     # Decay rates by severity (half-life in minutes)
  #   critical: 360,  # 6 hour half-life
  #   high: 120,      # 2 hour half-life
  #   medium: 45,     # 45 minute half-life
  #   low: 15         # 15 minute half-life
  # }
  # config.waf[:max_violations_tracked] = 50         # Maximum violations to track per IP

  # === Risk-Based Account Locking ===
  # Automatically lock accounts when authentication risk score exceeds threshold
  config.risk_based_locking = {
    enabled: false,                    # Master switch for risk-based locking
    risk_threshold: 75,                # Lock account if risk score >= this value (0-100)
    lock_strategy: :devise_lockable,   # Strategy: :devise_lockable, :rails_auth, :none
    auto_unlock_time: 1.hour,          # Native locks only; Devise owns unlock_in
    notify_user: false,                # Opt-in email; configure notifications first
    log_lock_events: true              # Create security event for locks
  }

  # === IP Geolocation ===
  # Configure IP geolocation for enhanced risk assessment
  # Note: You must provide your own MaxMind GeoLite2-City database due to licensing
  # Download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
  config.geolocation = {
    provider: :maxmind,                # Provider: :maxmind or :mock (for testing)
    maxmind_city_db_path: Rails.root.join('db', 'geoip', 'GeoLite2-City.mmdb').to_s,
    cache_ttl: 4.hours                 # How long to cache geolocation results
  }
end

```

## Usage

For current admission, account-lock, and recovery behavior—including the required
Rails-native controller/session-reader upgrade—see [Authentication](docs/guides/authentication.md).

> **Note:** If you haven't already, see the [Add to Your User Model](#add-to-your-user-model) section in Quick Start for setting up `SecurityTrackable`.

### Risk-Based Account Locking (with Devise Lockable)

Beskar can automatically lock user accounts when the calculated risk score exceeds a configured threshold. This prevents compromised accounts from being accessed even after successful authentication.

**Setup with Devise Lockable:**

1. Enable the `:lockable` module in your User model:

```ruby
class User < ApplicationRecord
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable,
         :lockable  # Add this for risk-based locking

  include Beskar::Models::SecurityTrackable
end
```

2. Generate and run the migration to add lockable columns:

```bash
rails generate devise User  # This will add lockable columns if not present
# Or manually add:
# - failed_attempts (integer)
# - unlock_token (string)
# - locked_at (datetime)
rails db:migrate
```

3. Enable risk-based locking in your initializer:

```ruby
# config/initializers/beskar.rb
Beskar.configure do |config|
  config.risk_based_locking = {
    enabled: true,                     # Enable the feature
    risk_threshold: 75,                # Lock when risk >= 75
    lock_strategy: :devise_lockable,   # Use Devise's lockable module
    auto_unlock_time: 1.hour,          # Native locks only; configure Devise's unlock_in separately
    notify_user: false,                # Opt-in email; see docs/guides/notifications-and-recovery.md
    log_lock_events: true              # Create security events
  }
end
```

**How it works:**

- Each authentication assessment records a score (0–100), named factors, and evidence: timestamped geographic observations, unverified User-Agent claims, application-local mobile hours, and recent account failures.
- Repeated IP use and unlock events do not establish verified trust. The former automatic risk discount and geographic bypass have been removed.

- If the risk score meets or exceeds the configured threshold, the account is automatically locked
- Confirmed locks reject the current attempt and revoke prior Devise sessions/remember cookies. Unlock does not resurrect them. `immediate_signout` defaults true; legacy false no longer bypasses a lock. Unrelated accounts remain signed in.
- Optional audit events record lock details; missing audit rows do not change enforcement.
- Devise controls its own unlock policy; Rails-native locks use Beskar's `auto_unlock_time` and persistent session guards.

See [Risk scoring](docs/guides/risk-scoring.md) for factor weights, bounded history, provider
behavior, and rollout limitations. Scores are heuristics, not calibrated
probabilities; validate the corrected inputs in monitor mode before enforcement.

**Lock Reasons:**

The system identifies specific reasons for locking:
- `:impossible_travel` - Login from location requiring impossible travel speed
- `:suspicious_device` - Bot signature or suspicious user agent detected
- `:geographic_anomaly` - Changed known country
- `:high_risk_authentication` - General high-risk authentication pattern

**Manual Lock/Unlock Operations:**

```ruby
# Manually lock an account based on risk
locker = Beskar::Services::AccountLocker.new(
  user,
  risk_score: 85,
  reason: :suspicious_device,
  metadata: { ip_address: request.ip }
)

if locker.should_lock?
  locker.lock!  # Lock the account
end

# Check if account is locked
locker.locked?  # => true/false

# Manually unlock
locker.unlock!
```

### Security Event Tracking

Beskar automatically tracks login attempts and creates security events with rich metadata:

```ruby
# Check recent failed attempts for a user
user.recent_failed_attempts(within: 1.hour)

# Check if user has suspicious login patterns
user.suspicious_login_pattern?

# Get recent successful logins
user.recent_successful_logins(within: 24.hours)

# Access security events
user.security_events.login_failures.recent
```

### Rate Limiting

Check if a request should be rate limited:

```ruby
# In a controller or middleware
if Beskar.rate_limited?(request, current_user)
  render json: { error: 'Rate limit exceeded' }, status: 429
  return
end

# Manual rate limiting check
rate_limiter = Beskar::Services::RateLimiter.new(request.ip, current_user)
unless rate_limiter.allowed?
  # Handle rate limiting
  time_until_reset = rate_limiter.time_until_reset
end
```

### Security Events Analysis

Security events are automatically created and include:

- **Event Type**: `login_success`, `login_failure`
- **IP Address**: Client IP with proxy detection
- **User Agent**: Browser and device information
- **Risk Score**: 0-100 based on various factors
- **Metadata**: Device info, geolocation, timestamps
- **Attack Patterns**: Detection of brute force, credential stuffing, etc.

### Attack Pattern Detection

Beskar can identify different types of attacks:

```ruby
rate_limiter = Beskar::Services::RateLimiter.new(ip_address, user)
attack_type = rate_limiter.attack_pattern_type

case attack_type
when :brute_force_single_account
  # Single IP attacking one account
when :distributed_single_account
  # Multiple IPs attacking one account
when :single_ip_multiple_accounts
  # One IP attacking multiple accounts (credential stuffing)
when :mixed_attack_pattern
  # Complex attack pattern
end
```

### IP Whitelisting

Whitelist trusted IPs to bypass all security blocking while maintaining full audit logs:

```ruby
# In config/initializers/beskar.rb
Beskar.configure do |config|
  config.ip_whitelist = [
    "203.0.113.0/24",      # Office network (CIDR notation)
    "198.51.100.50",       # VPN gateway (single IP)
    "2001:db8::1"          # IPv6 address
  ]
end
```

**How it works:**
- Whitelisted IPs bypass **all blocking** (banned IPs, rate limits, WAF violations)
- All requests from whitelisted IPs are **still logged** for audit purposes
- Supports individual IPs and CIDR notation (IPv4 and IPv6)
- Configuration is validated on startup
- Efficient caching for high-performance checks

**Check if an IP is whitelisted:**
```ruby
if Beskar::Services::IpWhitelist.whitelisted?(request.ip)
  # IP is trusted - allow but log activity
end

# Optional compatibility method; configuration changes are detected automatically.
Beskar::Services::IpWhitelist.clear_cache!
```

### Web Application Firewall (WAF)

Beskar's WAF uses a **score-based blocking system with exponential decay** for scanner-path signatures and selected Rails exceptions. See [the matching and privacy contract](docs/guides/audit-and-waf.md) for canonicalization, exclusions, and limitations.

**Attack Categories Detected:**
1. **WordPress Scans** (High: 80 points) - `/wp-admin`, `/wp-login.php`, `/wp-content/*.php`, `/xmlrpc.php`
2. **WordPress Static Files** (Low: 30 points) - `/wp-content/*.css`, `/wp-content/*.js`, `/wp-content/*.jpg` (broken links, not attacks)
3. **PHP Admin Panels** (High: 80 points) - `/phpmyadmin`, `/admin.php`, `/phpinfo.php`
4. **Config Files** (Critical: 95 points) - `/.env`, `/.git`, `/database.yml`
5. **Path Traversal** (Critical: 95 points) - `/../../../etc/passwd`, URL encoded variants
6. **Framework Debug** (Medium: 60 points) - `/rails/info/routes`, `/__debug__`, `/telescope`
7. **CMS Detection** (Medium: 60 points) - `/joomla`, `/drupal`, `/magento`
8. **Common Exploits** (Critical: 95 points) - `/shell.php`, `/c99.php`, `/webshell`
9. **Rails Format Paths** (Medium: 60 points) - Selected resource/extension signatures such as `/users/1.exe`, plus exact executable `format` query values
10. **Record Scanning Paths** (Low: 30 points) - Selected large-ID and scanner-name path signatures
11. **Rails Exceptions** - `UnknownFormat` and `InvalidType` (60), `RecordNotFound` (30), and `IpSpoofAttackError` (95). Ordinary Rails exceptions require independent path/format evidence by default; IP-spoof exceptions require safe resolved attribution in middleware. Exceptions alone can be scored by explicitly opting into `exception_detection: :all`.

**How Score-Based Blocking Works:**

Instead of counting violations (1, 2, 3...), Beskar tracks a **cumulative risk score** that decays over time:

- Each middleware pass records at most one violation, using the highest matched path severity (Critical=95, High=80, Medium=60, Low=30); a downstream exception does not add a second charge
- Violations **decay exponentially** based on severity (critical threats persist longer)
- IP is blocked when cumulative score reaches threshold (default: 150 points)
- Lower-severity violations decay faster; ordinary 404s do not add points by default, but signature-matching legitimate paths still can

**Example Scenarios:**
```ruby
# Scenario 1: Ordinary missing records, no matching scanner signature
# exception_detection: :suspicious (default)
10 × RecordNotFound = no WAF points
# Opting into :all changes this: ten rapid failures can cross the ban threshold.

# Scenario 2: Attacker scanning config files
2 × /.env access close together (95 points each) ≈ 190 points
→ Exceeds threshold (150) → Ban when enforcement and auto-block are enabled
→ One request alone is below the default threshold
→ Critical severity has a 6-hour half-life within the configured retention window

# Scenario 3: Mixed attack pattern
1 × WordPress scan (80) + 1 × Config access (95) = 175
→ Exceeds threshold → Ban triggered
→ Different decay rates for each violation type
```

**Configuration Profiles:**

```ruby
# 🔥 STRICT - High-security environment (financial, healthcare)
Beskar.configure do |config|
  config.waf[:enabled] = true
  config.waf[:auto_block] = true
  config.waf[:score_threshold] = 100           # Lower threshold = faster blocking
  config.waf[:violation_window] = 12.hours     # Longer memory
  config.waf[:permanent_block_after] = 300     # Permanent ban at 300 cumulative score
  config.waf[:block_durations] = [6.hours, 24.hours, 7.days, 30.days]

  # Slower decay = violations persist longer
  config.waf[:decay_rates] = {
    critical: 720,  # 12 hour half-life (very persistent)
    high: 360,      # 6 hour half-life
    medium: 120,    # 2 hour half-life
    low: 30         # 30 minute half-life
  }

  # Exclude legitimate 404-prone paths
  config.waf[:record_not_found_exclusions] = [
    %r{/posts/.*}, %r{/articles/\d+}, %r{/public/.*}
  ]
end

# ⚖️ BALANCED - Default production (recommended for most apps)
Beskar.configure do |config|
  config.waf[:enabled] = true
  config.waf[:auto_block] = true
  config.waf[:score_threshold] = 150           # Default threshold
  config.waf[:violation_window] = 6.hours      # Standard window
  config.waf[:permanent_block_after] = 500     # Permanent at 500 cumulative
  config.waf[:decay_enabled] = true
  # Uses default decay rates (critical: 360, high: 120, medium: 45, low: 15)

  config.waf[:record_not_found_exclusions] = [
    %r{/posts/.*}, %r{/products/[\\w-]+}
  ]
end

# 🧪 PERMISSIVE - High-traffic public site with many 404s
Beskar.configure do |config|
  config.waf[:enabled] = true
  config.waf[:auto_block] = true
  config.waf[:score_threshold] = 200           # Higher tolerance
  config.waf[:violation_window] = 3.hours      # Shorter memory
  config.waf[:permanent_block_after] = 800     # Rare permanent bans

  # Faster decay = violations forgotten quickly
  config.waf[:decay_rates] = {
    critical: 180,  # 3 hour half-life
    high: 60,       # 1 hour half-life
    medium: 20,     # 20 minute half-life
    low: 5          # 5 minute half-life (very forgiving)
  }

  # Extensive exclusions for public content
  config.waf[:record_not_found_exclusions] = [
    %r{/posts/.*}, %r{/articles/.*}, %r{/tags/.*},
    %r{/search/.*}, %r{/public/.*}, %r{/assets/.*}
  ]
end

# 🔍 MONITOR ONLY - Testing/staging (recommended before going live)
Beskar.configure do |config|
  config.monitor_only = true                   # Log violations but NEVER block
  config.waf[:enabled] = true
  config.waf[:create_security_events] = true
  config.ip_whitelist = ["127.0.0.1", "::1"]   # Whitelist localhost
end
```

**Blocking Behavior:**

With **default settings** (score_threshold: 150):
- **Violations accumulate**: Each violation adds points based on severity
- **Score threshold reached**: IP automatically banned when cumulative score ≥ 150
- **Exponential decay**: Violations lose impact over time based on severity
- **Ban duration escalates**: Based on total score accumulated:
  - 150-300 points → 1 hour ban
  - 300-450 points → 6 hour ban
  - 450-600 points → 24 hour ban
  - 600+ points → 7 day ban
  - 500+ cumulative score → **permanent ban**

**Key Advantages:**
- **Fewer false positives**: Low-severity violations (404s) decay quickly
- **Faster response to serious threats**: Critical violations persist longer
- **Adaptive blocking**: Mixed attack patterns properly weighted
- **Monitor mode compatible**: Set `config.monitor_only = true` to log without blocking

> **Production Tip:** Start with monitor mode for 24-48 hours to observe your traffic patterns, then adjust thresholds and exclusions before enabling blocking.

**Check WAF status:**
```ruby
# Get current risk score (with decay applied)
current_score = Beskar::Services::Waf.get_current_score(ip_address)
# => 145.3 (below threshold, not blocked)

# Get number of violations tracked
violation_count = Beskar::Services::Waf.get_violation_count(ip_address)
# => 3 (number of violations being tracked)

# Get detailed violation records
violations = Beskar::Services::Waf.get_violations(ip_address)
# => [{timestamp: ..., score: 95, severity: :critical, category: :config_files}, ...]

# Reset violations (admin action)
Beskar::Services::Waf.reset_violations(ip_address)

# Analyze a request without blocking
waf_analysis = Beskar::Services::Waf.analyze_request(request)
if waf_analysis
  puts "Detected: #{waf_analysis[:patterns].map { |p| p[:description] }}"
  puts "Severity: #{waf_analysis[:highest_severity]}"
  puts "Risk Score: #{waf_analysis[:risk_score]}"
end
```

### IP Blocking and Banning

Beskar uses indexed database ban checks. All workers must share the same authoritative database. Cache eviction, cache outages, and stale cache values cannot change ban enforcement.

**Automatic IP Banning Thresholds:**

| Trigger | Threshold | Time Window | Ban Duration | Configurable |
|---------|-----------|-------------|--------------|--------------|
| **Authentication attempt limit** | Configured IP limit (default 10) | Configured period (default 1 hour) | HTTP 429 until the actual retry deadline | Via rate_limiting config |
| **Rate Limit Violations** | 5 denied requests | Fixed 1 hour window | Adds 1 hour to a temporary ban | Fixed middleware policy |
| **WAF Violations** | Cumulative score (default 150) | Configured window with optional decay | Score-based durations or permanent | Via waf configuration |

Explicit extensions without a duration escalate to 6h, 24h, 7d, then permanent.
Extensions with a duration add that duration; already permanent bans remain permanent.
Monitor mode does not create automatic bans.

**Manual IP Management:**

```ruby
# Ban an IP address
Beskar::BannedIp.ban!(
  "203.0.113.50",
  reason: "manual_block",
  duration: 24.hours,
  details: "Suspicious activity reported by admin",
  metadata: { reporter: "admin@example.com", ticket: "#12345" }
)

# Permanent ban
Beskar::BannedIp.ban!(
  "203.0.113.51",
  reason: "confirmed_attack",
  permanent: true,
  details: "Confirmed malicious actor"
)

# Check if IP is banned
Beskar::BannedIp.banned?("203.0.113.50")  # => true

# Unban an IP
Beskar::BannedIp.unban!("203.0.113.50")

# Extend existing ban
ban = Beskar::BannedIp.find_by(ip_address: "203.0.113.50")
ban.extend_ban!(12.hours)  # Add 12 hours to current expiry
```

**Query banned IPs:**

```ruby
# Get all active bans
Beskar::BannedIp.active

# Get permanent bans
Beskar::BannedIp.permanent

# Get expired bans (not enforced but in database)
Beskar::BannedIp.expired

# Find bans by reason
Beskar::BannedIp.where(reason: 'waf_violation')
Beskar::BannedIp.where(reason: 'authentication_abuse')
Beskar::BannedIp.where(reason: 'rate_limit_abuse')

# Cleanup expired bans from database
removed_count = Beskar::BannedIp.cleanup_expired!
```

**State cleanup:**

Schedule `bin/rails beskar:cleanup_security_state` to reclaim expired coordination
rows. Audit-event retention is separate. Ban cache preloading is no longer required;
`Beskar::BannedIp.preload_cache!` remains a compatibility no-op.

### Security Events and Monitoring

**Query WAF violations:**

```ruby
# Recent WAF violations
waf_events = Beskar::SecurityEvent
  .where(event_type: 'waf_violation')
  .where('created_at > ?', 24.hours.ago)
  .order(created_at: :desc)

# High-risk WAF events
high_risk = Beskar::SecurityEvent
  .where(event_type: 'waf_violation')
  .where('risk_score >= ?', 80)
  .includes(:user)

# Group by IP to find repeat offenders
repeat_offenders = Beskar::SecurityEvent
  .where(event_type: 'waf_violation')
  .where('created_at > ?', 7.days.ago)
  .group(:ip_address)
  .having('COUNT(*) >= ?', 5)
  .count

# WAF violations by pattern type
waf_events.each do |event|
  patterns = event.metadata['waf_analysis']['patterns']
  patterns.each do |pattern|
    puts "#{event.ip_address}: #{pattern['category']} - #{pattern['description']}"
  end
end
```

**Scheduled maintenance:**

```ruby
# In a background job (e.g., daily)
class SecurityCleanupJob < ApplicationJob
  def perform
    # Remove expired bans from database
    removed = Beskar::BannedIp.cleanup_expired!
    Rails.logger.info "Cleaned up #{removed} expired IP bans"

    # Archive old security events (optional)
    Beskar::SecurityEvent.where('created_at < ?', 90.days.ago).delete_all

    # Generate security report (example)
    report = {
      active_bans: Beskar::BannedIp.active.count,
      permanent_bans: Beskar::BannedIp.permanent.count,
      waf_violations_today: Beskar::SecurityEvent.where(
        event_type: 'waf_violation',
        created_at: 24.hours.ago..Time.current
      ).count
    }

    # Send to monitoring service
    Rails.logger.info "Security Report: #{report}"
  end
end
```

### Middleware Integration

Beskar automatically injects its middleware (`Beskar::Middleware::RequestAnalyzer`) into the Rails stack to provide comprehensive request-level protection.

**Request Processing Order:**

Every request passes through these security checks in order:

1. **Whitelist Check** - Determine if IP is whitelisted (bypasses blocking but still logs)
2. **Banned IP Check** - Block immediately if IP is banned (403 Forbidden)
3. **Rate Limiting** - Check rate limits (429 Too Many Requests if exceeded)
4. **WAF Analysis** - Scan for vulnerability patterns (403 Forbidden if detected and threshold met)
5. **Request Processing** - Continue to application if all checks pass

**Features:**
- **Early exit** - Banned IPs are blocked immediately for performance
- **Whitelist bypass** - Trusted IPs bypass all blocking but activity is logged
- **Auto-blocking** - See [Automatic IP Banning Thresholds](#ip-blocking-and-banning) section for details
- **Custom error pages** - Returns helpful 403/429 error responses
- **Response headers** - Adds `X-Beskar-Blocked` and `X-Beskar-Rate-Limited` headers
- **Graceful degradation** - Continues working if cache is unavailable

**Middleware Logs:**

The middleware generates structured log messages for monitoring:

```
[Beskar::Middleware] Blocked request from banned IP: 203.0.113.50
[Beskar::Middleware] Rate limit exceeded for IP: 203.0.113.51
[Beskar::Middleware] WAF violation from whitelisted IP 192.168.1.100 (not blocking): WordPress vulnerability scan
[Beskar::Middleware] 🔒 Auto-blocked IP 203.0.113.52 after 3 WAF violations (duration: 1 hours)
[Beskar::Middleware] 🔒 Auto-blocked IP 203.0.113.53 for authentication brute force (15 failures)
```

Security events are logged to the `beskar_security_events` table for analysis and will be visualized in the forthcoming security dashboard.

## WAF Pattern Reference

| Category | Severity | Example Patterns | Risk Score |
|----------|----------|------------------|------------|
| WordPress Scans | High | `/wp-admin`, `/wp-login.php`, `/wp-content/*.php` | 80 |
| WordPress Static Files | Low | `/wp-content/*.css`, `/wp-content/*.jpg` | 30 |
| PHP Admin Panels | High | `/phpmyadmin`, `/admin.php`, `/phpinfo.php` | 80 |
| Config Files | **Critical** | `/.env`, `/.git`, `/database.yml`, `/config.php` | **95** |
| Path Traversal | **Critical** | `/../../../etc/passwd`, `%2e%2e/` | **95** |
| Framework Debug | Medium | `/rails/info/routes`, `/__debug__`, `/telescope` | 60 |
| CMS Detection | Medium | `/joomla`, `/drupal`, `/magento` | 60 |
| Common Exploits | **Critical** | `/shell.php`, `/c99.php`, `/webshell` | **95** |
| Rails Format Paths | Medium | `/users/1.exe`, `/reports?format=exe` | 60 |
| Record Scanning Paths | Low | `/account/999999` | 30 |
| IP Spoofing Exception | **Critical** | Conflicting IP headers | **95** |
| UnknownFormat / InvalidType Exceptions | Medium | Requires path/format evidence by default | 60 |
| RecordNotFound Exception | Low | Requires path/format evidence by default | 30 |

**Pattern matching:**

- Uses an at-most-8-KiB path with up to two percent-decoding passes; backslashes become slashes and dot segments are retained.
- Uses case-insensitive matching for most signatures, with explicit root/segment boundaries.
- Ignores arbitrary query text and request bodies; only the exact `format` query key is examined.
- Can match several rules but charges once per middleware pass; ordinary `.well-known` endpoints are not signatures.
- Supports explicit method/path/category exclusions. `exception_detection` defaults to `:suspicious`; `:all` opts into broad exception scoring and `:none` disables exception scoring.

## Security Best Practices

### 1. Start with Monitor Mode

When first enabling WAF, use monitor-only mode to tune thresholds:

```ruby
config.monitor_only = true  # Log but don't block
config.waf[:enabled] = true
config.waf[:create_security_events] = true
```

After reviewing logs for false positives, enable blocking:

```ruby
config.monitor_only = false
config.waf[:enabled] = true
config.waf[:auto_block] = true
```

### 2. Whitelist Carefully

Only whitelist truly trusted IPs:

```ruby
# ✅ Good - Documented, legitimate sources
config.ip_whitelist = [
  "203.0.113.0/24",    # Office network - IT approved
  "198.51.100.50"      # VPN gateway - documented in wiki
]

# ❌ Bad - Whitelisting unknown IPs
config.ip_whitelist = ["0.0.0.0/0"]  # Never do this!
```

### 3. Regular Maintenance

Set up a scheduled job to clean up old data:

```ruby
# Schedule daily via cron or Sidekiq
SecurityCleanupJob.perform_later

# Or in initializer for quick cleanup on restart
Rails.application.config.after_initialize do
  Beskar::BannedIp.cleanup_expired! if Rails.env.production?
end
```

### 4. Monitor Security Events

Set up alerts for high-risk events:

```ruby
# Example monitoring
high_risk_count = Beskar::SecurityEvent
  .where('created_at > ?', 1.hour.ago)
  .where('risk_score >= ?', 80)
  .count

alert_service.notify if high_risk_count > 10
```

### 5. Document Whitelist Changes

Keep a record of why each IP is whitelisted:

```ruby
# config/initializers/beskar.rb
config.ip_whitelist = [
  "203.0.113.0/24",    # Office HQ network (added 2024-01-15, ticket #1234)
  "198.51.100.50",     # Partner API server (added 2024-02-01, contract #5678)
  "192.0.2.10"         # Security scanner (added 2024-03-01, vendor: SecurityCo)
]
```

### 6. Test WAF in Staging

Before deploying to production, test WAF rules in staging to catch false positives.

### 7. Review Ban Reasons

Periodically review banned IPs to ensure blocking is working correctly:

```ruby
# Check recent auto-bans
recent_bans = Beskar::BannedIp
  .where('created_at > ?', 7.days.ago)
  .group(:reason)
  .count

# Review specific ban details
waf_bans = Beskar::BannedIp.where(reason: 'waf_violation')
waf_bans.each do |ban|
  puts "#{ban.ip_address}: #{ban.details} (violations: #{ban.violation_count})"
end
```

## Troubleshooting

### Issue: Legitimate users being blocked

**Solution:** Review matching rules in monitor mode, add narrow exclusions, or raise the cumulative score threshold:

```ruby
config.waf[:score_threshold] = 250  # Increase from default 150; not a violation count
```

Or whitelist specific IPs:
```ruby
config.ip_whitelist = ["user.ip.address.here"]
```

### Issue: Too many false positives

**Solution:** Enable monitor-only mode and review patterns:

```ruby
config.monitor_only = true  # This is a global setting, not WAF-specific

# Review what's being flagged
Beskar::SecurityEvent.where(event_type: 'waf_violation').last(20).each do |event|
  puts "Path: #{event.metadata['request_path']}"
  puts "Patterns: #{event.metadata['waf_analysis']['patterns']}"
end
```

### Issue: Banned IPs persist after restart

**Solution:** This is intentional (database persistence). To unban:

```ruby
Beskar::BannedIp.unban!("ip.address.here")

# Or unban all expired
Beskar::BannedIp.cleanup_expired!
```

### Issue: Performance concerns

**Solution:** Measure database query latency, connection-pool contention, and global
counter throughput. Redis is not required and cannot replace the authoritative
database. See [state-storage trade-offs](docs/operations/state-storage.md).

## Migration from Previous Versions

Copy engine migrations with `bin/rails beskar:install:migrations`, then run
`bin/rails db:migrate` before starting new workers. Drain old cache-based workers:
mixed versions do not share counters. Existing cache counters are not imported.
Review legacy bans and schedule state cleanup as described in
[the upgrade notes](docs/operations/state-storage.md#upgrade).

## Performance Characteristics

Ordinary requests read indexed ban state. Request-wide IP quota checks are opt-in. Authentication
attempts update applicable counters transactionally; WAF violations update per-IP
history. The global counter is disabled by default; enabling it serializes authentication accounting. No fixed
requests-per-second or latency guarantee is asserted; benchmark the deployed
database and workload.

## Development

After checking out the repo, run `bundle install` to install dependencies. The gem contains a dummy Rails application in `test/dummy` for development and testing.

To run the test suite, use the standard Rails command:

```bash
# From the gem's root directory
$ bin/rails test
```

## Contributing

Bug reports and pull requests are welcome on GitHub at [https://github.com/prograis/beskar](https://github.com/prograils/beskar).

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Just be nice to each other.
