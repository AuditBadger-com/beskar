require "ipaddr"
require "uri"
require "mail"

module Beskar
  # Validation errors name known setting paths, never supplied values/secrets.
  # Pure configuration checks do not query application models or Rails.cache.
  class ConfigurationValidator
    def initialize(configuration)
      @config = configuration
    end

    def validate!(resolve_jobs: true)
      defaults = Configuration.new
      Configuration::SECTIONS.each do |section|
        shape(@config.public_send(section), defaults.public_send(section), section.to_s)
      end
      boolean(@config.monitor_only, "monitor_only")
      invalid!("authenticate_admin", "must be a Proc or nil") unless @config.authenticate_admin.nil? || @config.authenticate_admin.is_a?(Proc)
      invalid!("audit_actor", "must be a Proc or nil") unless @config.audit_actor.nil? || @config.audit_actor.is_a?(Proc)
      %i[authorize_admin authorize_configuration].each do |name|
        value = @config.public_send(name)
        invalid!(name.to_s, "must be a Proc or nil") unless value.nil? || value.is_a?(Proc)
      end
      whitelist
      waf
      locking
      geolocation
      auth_models
      analysis_job(resolve_jobs)
      validate_notifications!
      true
    end

    # Also checked by delivery workers, since low-level configuration is mutable.
    def validate_notifications!
      settings = @config.notifications
      shape(settings, Configuration.new.notifications, "notifications")
      sender = settings[:from]
      invalid!("notifications.from", "must be one email address") unless sender.nil? || self.class.mailbox?(sender)
      recipients = settings[:security_team_recipients]
      unless recipients.size <= 20 && recipients.all? { |item| self.class.mailbox?(item) }
        invalid!("notifications.security_team_recipients", "must contain at most 20 email addresses")
      end
      url = settings[:recovery_url]
      invalid!("notifications.recovery_url", "must be an HTTPS entry-page URL without credentials, query, or fragment") unless url.nil? || self.class.recovery_url?(url)

      user_delivery = @config.notify_user_on_lock? || @config.emergency_password_reset[:send_notification] == true
      team_delivery = @config.emergency_password_reset[:notify_security_team] == true
      invalid!("notifications.from", "is required when notifications are enabled") if (user_delivery || team_delivery) && sender.nil?
      invalid!("notifications.recovery_url", "is required for user notifications") if user_delivery && url.nil?
      invalid!("notifications.security_team_recipients", "must not be empty when team notifications are enabled") if team_delivery && recipients.empty?
      true
    end

    def self.mailbox?(value)
      return false unless value.is_a?(String) && value.bytesize <= 254 && value.match?(/\A[^\s<>@,;]+@[^\s<>@,;]+\z/)
      parsed = Mail::Address.new(value)
      parsed.address == value && parsed.domain.present?
    rescue Mail::Field::ParseError
      false
    end

    def self.recovery_url?(value)
      return false unless value.is_a?(String) && value.bytesize <= 2048 && !value.match?(/[[:cntrl:]]/)
      uri = URI.parse(value)
      uri.is_a?(URI::HTTPS) && uri.host.present? && uri.userinfo.nil? && uri.query.nil? && uri.fragment.nil?
    rescue URI::InvalidURIError
      false
    end

    private

    def invalid!(path, message)
      raise Configuration::Error, "#{path} #{message}"
    end

    def shape(value, defaults, path)
      invalid!(path, "must be a hash with symbol keys") unless value.is_a?(Hash)
      invalid!(path, "contains unknown or non-symbol keys") unless (value.keys - defaults.keys).empty?
      defaults.each do |key, default|
        child = "#{path}.#{key}"
        invalid!(child, "is missing") unless value.key?(key)
        item = value[key]
        case default
        when Hash then shape(item, default, child)
        when TrueClass, FalseClass then boolean(item, child)
        when ActiveSupport::Duration then positive(item, child, optional: key == :auto_unlock_time)
        when Numeric
          if child == "risk_based_locking.risk_threshold"
            invalid!(child, "must be a finite number between 0 and 100") unless number?(item) && (0..100).cover?(item)
          else
            positive(item, child, optional: key == :permanent_block_after)
            if [:limit, :max_violations_tracked, :impossible_travel_threshold, :suspicious_device_threshold, :total_locks_threshold].include?(key)
              invalid!(child, "must be an integer") unless item.is_a?(Integer)
            end
          end
        when Array then invalid!(child, "must be an array") unless item.is_a?(Array)
        end
      end
    end

    def number?(value)
      value.is_a?(Numeric) && value.real? && value.finite?
    end

    def positive(value, path, optional: false)
      return if optional && value.nil?
      numeric = value.is_a?(ActiveSupport::Duration) ? value.to_f : value
      invalid!(path, "must be finite and positive#{" or nil" if optional}") unless number?(numeric) && numeric.positive?
    end

    def boolean(value, path)
      invalid!(path, "must be true or false") unless value == true || value == false
    end

    def whitelist
      invalid!("ip_whitelist", "must be an array") unless @config.ip_whitelist.is_a?(Array)
      @config.ip_whitelist.each_with_index do |entry, index|
        path = "ip_whitelist[#{index}]"
        invalid!(path, "must be an IP address or CIDR string") unless entry.is_a?(String) && entry.present?
        begin
          IPAddr.new(entry.strip)
        rescue IPAddr::Error
          invalid!(path, "must be a valid IP address or CIDR")
        end
      end
    end

    def waf
      settings = @config.waf
      invalid!("waf.exception_detection", "must be suspicious, all, or none") unless %i[suspicious all none].include?(settings[:exception_detection])
      invalid!("waf.block_durations", "must not be empty") if settings[:block_durations].empty?
      settings[:block_durations].each_with_index { |value, index| positive(value, "waf.block_durations[#{index}]") }
      regexps(settings[:record_not_found_exclusions], "waf.record_not_found_exclusions")
      categories = Services::Waf::VULNERABILITY_PATTERNS.keys + Services::Waf::EXCEPTION_RULES.values.map(&:first) + [:malformed_path]
      settings[:request_exclusions].each_with_index do |rule, index|
        path = "waf.request_exclusions[#{index}]"
        invalid!(path, "must be a hash with path, methods, and/or categories") unless rule.is_a?(Hash) && (rule.keys - %i[path methods categories]).empty?
        invalid!("#{path}.path", "must be a Regexp") unless rule[:path].is_a?(Regexp)
        if rule.key?(:methods)
          valid = rule[:methods].is_a?(Array) && rule[:methods].all? do |item|
            (item.is_a?(String) || item.is_a?(Symbol)) && %w[GET HEAD POST PUT PATCH DELETE OPTIONS CONNECT TRACE OTHER].include?(item.to_s.upcase)
          end
          invalid!("#{path}.methods", "must contain HTTP method names") unless valid
        end
        if rule.key?(:categories)
          invalid!("#{path}.categories", "must contain known WAF categories") unless rule[:categories].is_a?(Array) && rule[:categories].all? { |item| categories.any? { |category| category.to_s == item.to_s } }
        end
      end
    end

    def regexps(values, path)
      invalid!(path, "must contain only Regexp entries") unless values.all? { |value| value.is_a?(Regexp) }
    end

    def locking
      @config.lock_strategy
    end

    def geolocation
      settings = @config.geolocation
      invalid!("geolocation.provider", "must be mock or maxmind") unless Configuration::GEOLOCATION_PROVIDERS.include?(settings[:provider])
      path = settings[:maxmind_city_db_path]
      invalid!("geolocation.maxmind_city_db_path", "must be a path string or nil") unless path.nil? || path.is_a?(String)
      if settings[:provider] == :maxmind
        readable = path.present? && !path.include?("\0") && File.file?(path) && File.readable?(path)
        invalid!("geolocation.maxmind_city_db_path", "must identify a readable database file") unless readable
      end
    end

    def auth_models
      %i[devise rails_auth].each do |kind|
        names = @config.authentication_models[kind]
        invalid!("authentication_models.#{kind}", "must contain scope names") unless names.all? { |name| (name.is_a?(String) || name.is_a?(Symbol)) && name.to_s.match?(/\A[a-zA-Z]\w*(?:(?:::|\/)\w+)*\z/) }
      end
    end

    def analysis_job(resolve)
      job = @config.security_tracking[:analysis_job]
      valid = job.nil? || job.is_a?(Class) || (job.is_a?(String) && job.match?(/\A[A-Z]\w*(?:::[A-Z]\w*)*\z/))
      invalid!("security_tracking.analysis_job", "must be a job class, class name, or nil") unless valid
      return unless @config.auto_analyze_patterns?
      invalid!("security_tracking.analysis_job", "is required when automatic analysis is enabled") unless job
      @config.analysis_job_class if resolve || job.is_a?(Class)
    end
  end
end
