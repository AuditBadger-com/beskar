require "beskar/version"
require "beskar/configuration"
require "beskar/configuration_validator"
require "beskar/logger"
require "beskar/risk_level"
require "beskar/middleware"
require "beskar/middleware/request_analyzer"
require "beskar/models/security_trackable_generic"
require "beskar/models/security_trackable_devise"
require "beskar/models/security_trackable_authenticable"
require "beskar/models/security_trackable"
require "beskar/services/rate_limiter"
require "beskar/services/device_detector"
require "beskar/services/geolocation_service"
require "beskar/services/location_assessment"
require "beskar/services/risk_assessment"
require "beskar/services/account_locker"
require "beskar/services/ip_whitelist"
require "beskar/services/waf"
require "beskar/services/waf_request"
require "beskar/services/audit_data"
require "beskar/services/event_search"
require "beskar/services/request_context"
require "beskar/services/authentication_attempt"
require "beskar/services/authentication"
require "beskar/services/native_account_lock"
require "beskar/services/session_revocation"
require "beskar/services/notifications"
require "beskar/services/administrative_bans"
require "beskar/services/administrative_audit"
require "beskar/services/ban_expiry"
require "beskar/devise_authentication"
require "beskar/warden_authentication"
require "beskar/engine"

module Beskar
  class << self
    def configuration=(value)
      raise Configuration::Error, "Use audited Beskar.configure for runtime changes" if configuration.frozen?
      @configuration = value
    end
  end

  CONFIGURATION_MUTEX = Mutex.new

  def self.configure(actor: nil, reason: nil, request_id: nil)
    CONFIGURATION_MUTEX.synchronize do
      original = configuration
      if original.frozen?
        allowed = original.authorize_configuration&.call(actor) == true
        raise Configuration::Error, "Runtime configuration change is not authorized" unless allowed
        raise Configuration::Error, "Runtime configuration cannot run in a database transaction" if AdministrativeAction.connection.transaction_open?
      end
      candidate = original.dup
      yield(candidate)
      candidate.validate!(resolve_jobs: !!Rails.application&.initialized?)
      published = candidate.dup
      if original.frozen?
        published.seal!
        Services::AdministrativeAudit.record!(actor: actor, reason: reason, request_id: request_id,
          action: "configuration_changed", target_type: "Configuration",
          before_state: Services::AdministrativeAudit.configuration_snapshot(original),
          after_state: Services::AdministrativeAudit.configuration_snapshot(published).merge(
            "changed_settings" => original.instance_variables.filter_map do |name|
              name.to_s.delete_prefix("@") unless original.instance_variable_get(name) == published.instance_variable_get(name)
            end, "process_id" => Process.pid
          ))
      end
      @configuration = published
    end
  end

  def self.configuration
    @configuration ||= Configuration.new
  end

  # Convenience method to access the rate limiter
  def self.rate_limiter
    Services::RateLimiter
  end

  # Check if a request should be rate limited
  def self.rate_limited?(request, user = nil)
    Services::RateLimiter.is_rate_limited?(request, user)
  end
end
