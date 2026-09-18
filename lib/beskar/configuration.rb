module Beskar
  class Configuration
    class Error < ArgumentError; end
    SECTIONS = %i[rate_limiting security_tracking risk_based_locking geolocation waf authentication_models emergency_password_reset notifications].freeze
    LOCK_STRATEGIES = %i[devise_lockable rails_auth none].freeze
    GEOLOCATION_PROVIDERS = %i[mock maxmind].freeze
    attr_accessor :rate_limiting, :security_tracking, :risk_based_locking, :geolocation, :ip_whitelist, :waf, :authentication_models, :emergency_password_reset, :notifications, :monitor_only, :authenticate_admin, :audit_actor, :authorize_admin, :authorize_configuration

    def initialize
      @monitor_only = false # Global monitor-only mode - logs everything but doesn't block
      @ip_whitelist = [] # Array of IP addresses or CIDR ranges

      # Dashboard authentication - configure this to restrict access to the dashboard
      # Example: config.authenticate_admin = proc { |request| request.env["warden"]&.authenticate(scope: :admin).present? }
      @authenticate_admin = nil
      @audit_actor = nil # Proc returning a stable opaque actor ID; required for dashboard writes
      @authorize_admin = nil # (request, permission), controller context; nil denies every dashboard action
      @authorize_configuration = nil # (opaque_actor), trusted host code; nil denies runtime changes

      # Authentication models configuration
      # Auto-detect by default, or can be explicitly configured
      @authentication_models = {
        devise: [], # Will be auto-detected: [:devise_user, :admin, etc.]
        rails_auth: [], # Will be auto-detected: [:user, etc.]
        auto_detect: true # Set to false to use only explicitly configured models
      }

      @waf = {
        enabled: false,                  # Master switch for WAF
        auto_block: true,                # Automatically block IPs after threshold
        score_threshold: 150,            # Cumulative risk score before blocking (replaces block_threshold)
        violation_window: 6.hours,       # Maximum time window to track violations
        block_durations: [1.hour, 6.hours, 24.hours, 7.days], # Escalating block durations
        permanent_block_after: 500,      # Permanent block after cumulative score reaches this (nil = never)
        create_security_events: true,    # Create SecurityEvent records
        exception_detection: :suspicious, # :suspicious, :all (opt-in broad scoring), or :none
        request_exclusions: [],          # {path: Regexp, methods: [...], categories: [...]}
        record_not_found_exclusions: [], # Regex patterns to exclude from RecordNotFound detection
        decay_enabled: true,             # Enable exponential decay of violation scores over time
        decay_rates: {                   # Decay rates by severity (half-life in minutes)
          critical: 360,                 # Critical violations: 6 hour half-life
          high: 120,                     # High violations: 2 hour half-life
          medium: 45,                    # Medium violations: 45 minute half-life
          low: 15                        # Low violations: 15 minute half-life
        },
        max_violations_tracked: 50       # Maximum number of violations to track per IP (oldest pruned)
      }
      @security_tracking = {
        enabled: true,
        track_successful_logins: true,
        track_failed_logins: true,
        auto_analyze_patterns: false, # No built-in background analyzer. Opt in with a host Active Job.
        analysis_job: nil
      }
      @rate_limiting = {
        ip_attempts: {
          block_requests: false, # Authentication quotas do not block unrelated traffic behind a shared NAT
          limit: 10,
          period: 1.hour,
          exponential_backoff: true
        },
        account_attempts: {
          limit: 5,
          period: 15.minutes,
          exponential_backoff: true
        },
        global_attempts: {
          enabled: false, # Opt-in availability tradeoff: a distributed attacker can consume this shared budget
          limit: 100,
          period: 1.minute,
          exponential_backoff: false
        }
      }
      @risk_based_locking = {
        enabled: false,                    # Master switch for risk-based locking
        risk_threshold: 75,                # Lock account if risk score >= this value
        lock_strategy: :devise_lockable,   # Strategy: :devise_lockable, :rails_auth, :none
        auto_unlock_time: 1.hour,          # Native lock duration; nil for manual unlock. Devise owns unlock_in.
        notify_user: false,                # Opt-in email; configure notifications first
        log_lock_events: true,             # Create security event for locks
        immediate_signout: true            # Locked attempts are always denied; retained for compatibility
      }
      @geolocation = {
        provider: :mock,                   # Provider: :maxmind, :mock
        maxmind_city_db_path: nil,         # Path to MaxMind GeoLite2-City.mmdb or GeoIP2-City.mmdb
        cache_ttl: 4.hours                 # How long to cache geolocation results
      }
      @emergency_password_reset = {
        enabled: false,                    # Master switch for emergency password reset
        impossible_travel_threshold: 3,    # Reset after N impossible travel events in 24h
        suspicious_device_threshold: 5,    # Reset after N suspicious device events in 24h
        total_locks_threshold: 5,          # Reset after N total locks in 24h (any reason)
        send_notification: false,          # Opt-in recovery instructions via Action Mailer
        notify_security_team: false,        # Opt-in security-team email
        require_manual_unlock: false       # Require manual admin unlock after reset
      }
      @notifications = {
        from: nil,                        # One sender mailbox; no example-address fallback
        recovery_url: nil,                # HTTPS recovery entry page, not a token-bearing URL
        security_team_recipients: []       # Separate message/job for each configured mailbox
      }
    end

    # Section assignment overlays library defaults, not the previous section.
    # Nested edits in a configure block instead retain the current settings.
    SECTIONS.each do |section|
      define_method(:"#{section}=") do |value|
        raise Error, "#{section} must be a hash with symbol keys" unless value.is_a?(Hash)
        defaults = Configuration.new.public_send(section)
        instance_variable_set(:"@#{section}", defaults.deep_merge(value.deep_dup))
      end
    end

    def initialize_copy(other)
      super
      SECTIONS.each { |section| instance_variable_set(:"@#{section}", other.public_send(section).deep_dup) }
      @ip_whitelist = other.ip_whitelist.deep_dup
    end

    def validate!(resolve_jobs: true)
      ConfigurationValidator.new(self).validate!(resolve_jobs: resolve_jobs)
      self
    end

    def seal!
      freeze_value = lambda do |value|
        case value
        when Hash
          value.each { |key, item|
            freeze_value.call(key)
            freeze_value.call(item)
          }
          value.freeze
        when Array
          value.each { |item| freeze_value.call(item) }
          value.freeze
        when String, Regexp then value.freeze
        end
      end
      (SECTIONS + [:ip_whitelist]).each { |name| freeze_value.call(public_send(name)) }
      freeze
    end

    def analysis_job_class
      configured = @security_tracking[:analysis_job]
      job = configured.is_a?(String) ? configured.safe_constantize : configured
      unless job.is_a?(Class) && job < ActiveJob::Base
        raise Error, "security_tracking.analysis_job must identify a host ActiveJob::Base subclass"
      end
      job
    rescue NameError
      raise Error, "security_tracking.analysis_job could not be loaded"
    end

    def security_tracking_enabled?
      @security_tracking[:enabled]
    end

    def track_successful_logins?
      security_tracking_enabled? && @security_tracking[:track_successful_logins]
    end

    def track_failed_logins?
      security_tracking_enabled? && @security_tracking[:track_failed_logins]
    end

    def auto_analyze_patterns?
      security_tracking_enabled? && @security_tracking[:auto_analyze_patterns]
    end

    # Risk-based locking configuration helpers
    def risk_based_locking_enabled?
      @risk_based_locking[:enabled]
    end

    def risk_threshold
      @risk_based_locking[:risk_threshold] || 75
    end

    def lock_strategy
      strategy = @risk_based_locking[:lock_strategy]
      raise Error, "risk_based_locking.lock_strategy must be devise_lockable, rails_auth, or none" unless LOCK_STRATEGIES.include?(strategy)
      strategy
    end

    def auto_unlock_time
      @risk_based_locking.fetch(:auto_unlock_time, 1.hour)
    end

    def notify_user_on_lock?
      @risk_based_locking[:notify_user] == true
    end

    def log_lock_events?
      @risk_based_locking[:log_lock_events] != false
    end

    def immediate_signout?
      @risk_based_locking[:immediate_signout] == true
    end

    # Geolocation configuration helpers
    def geolocation_provider
      @geolocation[:provider] || :mock
    end

    def maxmind_city_db_path
      @geolocation[:maxmind_city_db_path]
    end

    def geolocation_cache_ttl
      @geolocation[:cache_ttl] || 4.hours
    end

    # WAF configuration helpers
    def waf_enabled?
      @waf && @waf[:enabled]
    end

    def waf_auto_block?
      waf_enabled? && @waf[:auto_block] && !@monitor_only
    end

    # General monitor-only mode check (affects all blocking)
    def monitor_only?
      @monitor_only == true
    end

    # IP Whitelist configuration helpers
    def ip_whitelist_enabled?
      @ip_whitelist.is_a?(Array) && @ip_whitelist.any?
    end

    # Authentication models helpers
    def devise_scopes
      return @authentication_models[:devise] unless @authentication_models[:auto_detect]

      # Auto-detect Devise models
      detected = []
      if defined?(Devise)
        Devise.mappings.keys.each do |scope|
          detected << scope
        end
      end

      # Merge with explicitly configured models
      (detected + Array(@authentication_models[:devise])).uniq
    end

    def rails_auth_scopes
      return @authentication_models[:rails_auth] unless @authentication_models[:auto_detect]

      # Auto-detect Rails authentication models (has_secure_password)
      detected = []
      if defined?(ActiveRecord::Base)
        # Try to find models with has_secure_password
        # This is a heuristic - models that have password_digest column
        ActiveRecord::Base.descendants.each do |model|
          next unless model.table_exists?
          if model.column_names.include?("password_digest")
            scope = model.name.underscore.to_sym
            detected << scope unless devise_scopes.include?(scope)
          end
        rescue => e
          # Ignore errors during detection
          Beskar::Logger.debug("Error detecting Rails auth model #{model.name}: #{e.class}")
        end
      end

      # Merge with explicitly configured models
      (detected + Array(@authentication_models[:rails_auth])).uniq
    end

    def all_auth_scopes
      (devise_scopes + rails_auth_scopes).uniq
    end

    def model_class_for_scope(scope)
      return Devise.mappings[scope.to_sym].to if defined?(Devise) && scope && Devise.mappings.key?(scope.to_sym)
      scope.to_s.camelize.constantize
    rescue NameError
      nil
    end
  end
end
