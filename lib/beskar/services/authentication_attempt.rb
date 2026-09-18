require "digest"

module Beskar
  module Services
    # Request-local decisions are independent of optional SecurityEvent writes.
    # Adapters reserve before password verification and pass the same attempt to
    # the outcome callback, so a single attempt cannot consume capacity twice.
    class AuthenticationAttempt
      class Unavailable < StandardError; end

      attr_reader :id, :scope, :rate_limit, :ip_address, :attempted_email, :request_path
      attr_accessor :user, :event, :locked_now, :completed

      def self.current(request, scope)
        request.env.dig("beskar.authentication_attempts", scope.to_s) if request.respond_to?(:env) && request.env
      end

      def self.reserve(request, model:, scope:, user: nil, credentials: {}, cache: false)
        existing = current(request, scope) if cache
        return existing if existing

        attempt = new(request, scope: scope, user: user, model: model, credentials: credentials)
        if cache && request.respond_to?(:env) && request.env
          (request.env["beskar.authentication_attempts"] ||= {})[scope.to_s] = attempt
        end
        attempt
      rescue ActiveRecord::ActiveRecordError => error
        Beskar::Logger.error("Authentication state unavailable (#{error.class})")
        raise Unavailable, "Authentication temporarily unavailable"
      end

      def initialize(request, scope:, user:, model:, credentials:)
        @id = SecureRandom.uuid
        @scope = scope.to_s
        @ip_address = RequestContext.ip(request)
        @request_path = RequestContext.path(request)
        @user = user
        @generation = SessionRevocation.token(user) if user
        identity = credentials.to_h.stringify_keys
        @attempted_email = identity["email"] || identity["email_address"]
        @locked_now = false
        @completed = false
        @identity_reserved = user || credentials.present?
        @rate_limit = RateLimiter.check_authentication_attempt(request, :attempt, user,
          account_key: user ? nil : self.class.credential_key(model, credentials))
        @allowed = !RequestContext.enforce?(ip_address) || rate_limit[:allowed]
        @reason = :rate_limit_exceeded unless @allowed
        if user&.respond_to?(:beskar_access_locked?) && RequestContext.enforce?(ip_address) && user.beskar_access_locked?
          deny!(:account_locked)
        end
      end

      def self.credential_key(model, credentials)
        return if credentials.empty?
        normalized = credentials.to_h.sort_by { |key, _| key.to_s }.map do |key, value|
          value = value.to_s
          value = value.strip if !model.respond_to?(:strip_whitespace_keys) || model.strip_whitespace_keys.map(&:to_s).include?(key.to_s)
          value = value.downcase if !model.respond_to?(:case_insensitive_keys) || model.case_insensitive_keys.map(&:to_s).include?(key.to_s)
          [key.to_s, value]
        end
        "#{model.name}:credentials:#{Digest::SHA256.hexdigest(normalized.to_json)}"
      end

      def allowed?
        @allowed
      end

      def session_token
        @generation
      end

      # Opaque strategies cannot identify an account until verification succeeds.
      # Charge that account once, independently of the already reserved IP tier.
      def bind_user!(resource)
        if user && user != resource
          deny!(:identity_changed)
          return
        end
        unless user
          @user = resource
          @generation = SessionRevocation.token(resource)
          account_result = RateLimiter.reserve_account(resource, ip_address: ip_address)
          if RequestContext.enforce?(ip_address) && !account_result[:allowed]
            @rate_limit = account_result
            deny!(:rate_limit_exceeded)
          end
        end
        verify_generation!
        if RequestContext.enforce?(ip_address)
          locked = resource.respond_to?(:beskar_access_locked?) ? resource.beskar_access_locked? : (resource.respond_to?(:access_locked?) && resource.reload.access_locked?)
          deny!(:account_locked) if locked
        end
      end

      def verify_generation!
        deny!(:session_revoked) if user && @generation != SessionRevocation.token(user)
      end

      def bind_identity!(model, credentials)
        return if user || @identity_reserved || credentials.empty?
        @identity_reserved = true
        result = RateLimiter.reserve_account(nil, ip_address: ip_address,
          account_key: self.class.credential_key(model, credentials))
        if RequestContext.enforce?(ip_address) && !result[:allowed]
          @rate_limit = result
          deny!(:rate_limit_exceeded)
        end
      end

      def persist_outcome!
        return unless event && !event.persisted? && Beskar.configuration.track_successful_logins?
        event.event_type = "authentication_blocked" unless allowed?
        event.metadata = (event.metadata || {}).merge("authentication" => metadata)
        user.send(:persist_authentication_audit, event)
        user.analyze_suspicious_patterns_async if allowed? && Beskar.configuration.auto_analyze_patterns?
      end

      def deny!(reason)
        @allowed = false
        @reason = reason
      end

      def metadata
        {"attempt_id" => id, "scope" => scope, "allowed" => allowed?,
         "reason" => @reason&.to_s, "rate_limit_allowed" => rate_limit[:allowed], "locked_now" => !!locked_now}
      end

      def response
        status = (@reason == :rate_limit_exceeded) ? 429 : 403
        headers = {"content-type" => "application/json", "cache-control" => "no-store"}
        headers["retry-after"] = [rate_limit[:retry_after].to_i, 1].max.to_s if status == 429
        [status, headers, [{error: (status == 429) ? "Too many authentication attempts" : "Authentication denied"}.to_json]]
      end

      def self.unavailable_response
        [503, {"content-type" => "application/json", "cache-control" => "no-store", "retry-after" => "60"},
          [{error: "Authentication temporarily unavailable"}.to_json]]
      end
    end
  end
end
