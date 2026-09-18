# frozen_string_literal: true

Beskar.configure do |config|
  # ============================================================================
  # DASHBOARD AUTHENTICATION (REQUIRED)
  # ============================================================================
  # Configure how to authenticate access to the Beskar security dashboard.
  # This is REQUIRED for all environments.
  #
  # The authenticate_admin callback receives the request object and is executed
  # in the controller context, giving you access to all controller methods
  # (cookies, session, authenticate_or_request_with_http_basic, etc.).
  # The block should return truthy value to allow access, falsey to deny.

  # Option 1: Using Devise with admin role (recommended for production)
  # config.authenticate_admin = ->(request) do
  #   user = request.env['warden']&.authenticate(scope: :user)
  #   user&.admin?
  # end

  # Option 2: HTTP Basic Authentication (uses controller method)
  # config.authenticate_admin = ->(request) do
  #   authenticate_or_request_with_http_basic("Beskar Admin") do |username, password|
  #     username == ENV['BESKAR_ADMIN_USERNAME'] &&
  #     password == ENV['BESKAR_ADMIN_PASSWORD']
  #   end
  # end

  # Option 3: Token-based authentication
  # config.authenticate_admin = ->(request) do
  #   request.headers['Authorization'] == "Bearer #{ENV['BESKAR_ADMIN_TOKEN']}"
  # end

  # Option 4: Cookie-based authentication (uses controller cookies)
  # config.authenticate_admin = ->(request) do
  #   cookies.signed[:admin_token] == ENV['BESKAR_ADMIN_TOKEN']
  # end

  # Option 5: Using CanCanCan (uses controller method)
  # config.authenticate_admin = ->(request) do
  #   authorize! :manage, :beskar_dashboard
  # end

  # Option 6: Using Pundit (uses controller method)
  # config.authenticate_admin = ->(request) do
  #   authorize :beskar_dashboard, :access?
  # end

  # Option 7: For development/testing ONLY (NOT for production!)
  # config.authenticate_admin = ->(request) do
  #   Rails.env.development? || Rails.env.test?
  # end

  # ============================================================================
  # MONITOR-ONLY MODE
  # ============================================================================
  # When enabled, Beskar will log all security events but won't actually block
  # any requests. Useful for testing or initial deployment.
  config.monitor_only = true

  # ============================================================================
  # IP WHITELIST
  # ============================================================================
  # IPs that should never be blocked (your office, monitoring services, etc.)
  config.ip_whitelist = [
    # '192.168.1.0/24',  # Local network
    # '10.0.0.0/8',      # Private network
    # '127.0.0.1',       # Localhost
  ]

  # ============================================================================
  # WAF (WEB APPLICATION FIREWALL) - Score-Based Blocking
  # ============================================================================
  # Enable WAF to protect against common attacks and vulnerability scans.
  # Uses score-based blocking with exponential decay for intelligent threat detection.
  config.waf[:enabled] = true

  # Optionally customize WAF settings (these are the defaults):
  # config.waf[:auto_block] = true                 # Automatically block IPs after threshold
  # config.waf[:score_threshold] = 150             # Cumulative risk score before blocking
  # config.waf[:violation_window] = 6.hours        # Maximum time window to track violations
  # config.waf[:block_durations] = [1.hour, 6.hours, 24.hours, 7.days] # Escalating durations
  # config.waf[:permanent_block_after] = 500       # Permanent block when cumulative score reaches this
  # config.waf[:create_security_events] = true     # Create SecurityEvent records
  #
  # === Exponential Decay Configuration ===
  # Violations decay over time based on severity (reduces false positives)
  # config.waf[:decay_enabled] = true
  # config.waf[:decay_rates] = {                   # Half-life in minutes
  #   critical: 360,  # 6 hour half-life (config files, path traversal)
  #   high: 120,      # 2 hour half-life (WordPress, PHP admin scans)
  #   medium: 45,     # 45 minute half-life (unknown formats)
  #   low: 15         # 15 minute half-life (RecordNotFound/404s)
  # }
  # config.waf[:max_violations_tracked] = 50       # Maximum violations to track per IP
  #
  # === RecordNotFound Exclusions ===
  # Exclude legitimate 404-prone paths from triggering violations
  # config.waf[:record_not_found_exclusions] = [
  #   %r{/posts/.*},              # Blog posts with slugs
  #   %r{/products/[\w-]+},       # Product URLs with slugs
  #   %r{/public/.*}              # Public content
  # ]
  #
  # === Illustrative thresholds ===
  # See docs/guides/audit-and-waf.md for matching rules and tuning limitations:
  # - STRICT: score_threshold = 100 (high-security)
  # - BALANCED: score_threshold = 150 (recommended default)
  # - PERMISSIVE: score_threshold = 200 (high-traffic sites)

  # ============================================================================
  # SECURITY TRACKING
  # ============================================================================
  # Security tracking is enabled by default. To disable or customize:
  # config.security_tracking[:enabled] = false
  # config.security_tracking[:track_successful_logins] = true
  # config.security_tracking[:track_failed_logins] = true
  # config.security_tracking[:auto_analyze_patterns] = true

  # ============================================================================
  # RATE LIMITING
  # ============================================================================
  # Rate limiting is configured by default. To customize:
  # config.rate_limiting[:ip_attempts][:limit] = 10
  # config.rate_limiting[:ip_attempts][:period] = 1.hour
  # config.rate_limiting[:ip_attempts][:exponential_backoff] = true
  #
  # config.rate_limiting[:account_attempts][:limit] = 5
  # config.rate_limiting[:account_attempts][:period] = 15.minutes
  # config.rate_limiting[:account_attempts][:exponential_backoff] = true
  #
  # config.rate_limiting[:global_attempts][:limit] = 100
  # config.rate_limiting[:global_attempts][:period] = 1.minute
  # config.rate_limiting[:global_attempts][:exponential_backoff] = false

  # ============================================================================
  # RISK-BASED ACCOUNT LOCKING
  # ============================================================================
  # Risk-based locking is disabled by default. To enable:
  # config.risk_based_locking[:enabled] = true
  # Confirmed locks always reject sign-in and revoke old sessions.
  # config.risk_based_locking[:risk_threshold] = 75        # Risk score threshold for locking
  # config.risk_based_locking[:auto_unlock_time] = 1.hour  # How long to lock the account
  # config.risk_based_locking[:notify_user] = true         # Notify user on lock
  # config.risk_based_locking[:log_lock_events] = true     # Log lock events

  # ============================================================================
  # GEOLOCATION
  # ============================================================================
  # Geolocation uses a mock provider by default. To use MaxMind:
  # 1. Download GeoLite2-City database from maxmind.com
  # 2. Place it in config/GeoLite2-City.mmdb
  # 3. Configure:
  # config.geolocation[:provider] = :maxmind
  # config.geolocation[:maxmind_city_db_path] = Rails.root.join('config', 'GeoLite2-City.mmdb').to_s
  # config.geolocation[:cache_ttl] = 4.hours

  # ============================================================================
  # AUTHENTICATION MODELS
  # ============================================================================
  # Authentication models are auto-detected by default. To customize:
  # config.authentication_models[:auto_detect] = false  # Disable auto-detection
  # config.authentication_models[:devise] = [:user, :admin]
  # config.authentication_models[:rails_auth] = [:customer]

  # ============================================================================
  # EMERGENCY PASSWORD RESET
  # ============================================================================
  # Emergency password reset is disabled by default. To enable:
  # config.emergency_password_reset[:enabled] = true
  # config.emergency_password_reset[:impossible_travel_threshold] = 3
  # config.emergency_password_reset[:suspicious_device_threshold] = 5
  # config.emergency_password_reset[:total_locks_threshold] = 5
  # config.emergency_password_reset[:send_notification] = true
  # config.emergency_password_reset[:notify_security_team] = true
  # config.emergency_password_reset[:require_manual_unlock] = false
end
