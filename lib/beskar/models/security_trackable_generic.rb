module Beskar
  module Models
    # Generic security tracking functionality shared by all authentication systems
    # This module provides the core security event tracking, risk scoring,
    # and risk evidence shared by the supported authentication adapters
    module SecurityTrackableGeneric
      extend ActiveSupport::Concern

      included do
        # Audit rows outlive the account, retaining the original polymorphic
        # identity and stored evidence without deletion or nullification.
        has_many :security_events, class_name: "Beskar::SecurityEvent", as: :user
      end

      module ClassMethods
        # Track failed authentication attempt without a user context
        # Used when authentication fails and we don't have a user object
        def track_failed_authentication(request, scope, attempt: nil)
          attempted_email = extract_attempted_email(request, scope)
          attempt ||= Services::AuthenticationAttempt.current(request, scope)
          unless attempt
            key = attribute_names.include?("email_address") ? :email_address : :email
            credentials = attempted_email ? {key => attempted_email} : {}
            user = if credentials.empty?
              nil
            elsif respond_to?(:find_for_database_authentication)
              find_for_database_authentication(credentials)
            else
              find_by(credentials)
            end
            attempt = Services::AuthenticationAttempt.reserve(request, model: self, scope: scope,
              user: user, credentials: credentials)
          end
          attempted_email ||= attempt.attempted_email
          return attempt.event if attempt.completed

          attempt.completed = true
          return unless Beskar.configuration.track_failed_logins?

          assessment = Services::RiskAssessment.new(request, user: attempt.user, result: :failure) if attempt.allowed?
          event = Beskar::SecurityEvent.new(
            user_type: attempt.user&.class&.polymorphic_name, user_id: attempt.user&.id,
            event_type: attempt.allowed? ? "login_failure" : "authentication_blocked",
            ip_address: Services::RequestContext.ip(request),
            user_agent: Services::RequestContext.text(request.user_agent),
            attempted_email: attempted_email,
            metadata: Services::RequestContext.security_metadata(request, enrich: false).merge(assessment&.metadata || {}).merge(scope: scope.to_s,
              request_path: attempt.request_path, authentication: attempt.metadata),
            risk_score: assessment&.score || 0
          )
          event.beskar_attempt = attempt
          attempt.event = event
          Beskar::SecurityEvent.transaction(requires_new: true) { event.save! }
          event
        rescue Services::AuthenticationAttempt::Unavailable
          raise
        rescue => error
          Beskar::Logger.warn("Failed authentication audit unavailable (#{error.class})")
          attempt&.event
        end

        private

        def extract_attempted_email(request, scope)
          # Try different param patterns based on scope
          request.params.dig(scope.to_s, "email") ||
            request.params.dig(scope.to_s, "email_address") ||
            request.params.dig("devise_user", "email") ||
            request.params.dig("user", "email") ||
            request.params.dig("user", "email_address") ||
            request.params.dig("email_address") ||
            request.params["email"]
        end

        def calculate_failure_risk_score(request)
          Services::RiskAssessment.new(request, result: :failure).score
        end
      end

      # Track authentication event (success or failure) for a specific user
      def track_authentication_event(request, result, attempt: nil, persist: true)
        return unless request

        attempt ||= Services::AuthenticationAttempt.reserve(request, model: self.class,
          scope: self.class.name.underscore, user: self)
        attempt.bind_user!(self)
        return attempt.event if attempt.completed
        tracking = (result == :success) ? Beskar.configuration.track_successful_logins? : Beskar.configuration.track_failed_logins?
        assessment_required = tracking || (result == :success && Beskar.configuration.risk_based_locking_enabled?)
        unless assessment_required
          attempt.completed = true
          return
        end

        # Build the decision even when audit persistence is disabled. A rejected
        # credential attempt is never recorded as a trusted successful login.
        # Do not build through has_many: saving/locking the user can autosave its
        # unsaved children and accidentally make optional audit writes mandatory.
        assessment = assess_authentication_risk(request, result)
        security_event = Beskar::SecurityEvent.new(
          user_type: self.class.polymorphic_name, user_id: id,
          event_type: (result == :success) ? "login_success" : "login_failure",
          ip_address: Services::RequestContext.ip(request),
          user_agent: Services::RequestContext.text(request.user_agent),
          attempted_email: extract_user_email,
          metadata: Services::RequestContext.security_metadata(request, enrich: false).merge(assessment.metadata),
          risk_score: assessment.score
        )
        security_event.beskar_attempt = attempt
        attempt.event = security_event

        if result == :success && attempt.allowed?
          attempt.locked_now = !!check_and_lock_if_high_risk(security_event, request)
          if attempt.locked_now
            attempt.deny!(:account_locked)
          end
        end

        attempt.verify_generation!
        security_event.event_type = "authentication_blocked" unless attempt.allowed?
        security_event.metadata = (security_event.metadata || {}).merge("authentication" => attempt.metadata)
        attempt.completed = true
        return unless tracking && persist

        persist_authentication_audit(security_event)
        analyze_suspicious_patterns_async if result == :success && attempt.allowed? && Beskar.configuration.auto_analyze_patterns?
        security_event
      rescue Services::AuthenticationAttempt::Unavailable
        raise
      rescue => error
        Beskar::Logger.error("Authentication risk assessment unavailable (#{error.class})")
        # A broken risk assessment must not silently admit a potentially locked
        # account. Audit writes have their own non-fatal boundary below.
        if Beskar.configuration.risk_based_locking_enabled? && Services::RequestContext.enforce?(attempt&.ip_address)
          raise Services::AuthenticationAttempt::Unavailable, "Authentication temporarily unavailable"
        end
        attempt.completed = true if attempt
        nil
      end

      def analyze_suspicious_patterns_async
        return unless Beskar.configuration.auto_analyze_patterns?
        job = Beskar.configuration.analysis_job_class
        arguments = {user_type: self.class.base_class.name, user_id: id, event_type: "login_success"}
        # Never enqueue for an outer transaction that later rolls back. The job
        # is optional enrichment, not delayed authentication enforcement.
        ActiveRecord.after_all_transactions_commit do
          result = job.perform_later(**arguments)
          Beskar::Logger.warn("Security analysis job was not enqueued") unless result
        rescue => error
          Beskar::Logger.warn("Failed to queue security analysis (#{error.class})")
        end
      rescue => e
        Beskar::Logger.warn("Failed to prepare security analysis (#{e.class})")
      end

      def beskar_session_token
        Services::SessionRevocation.token(self)
      end

      def revoke_beskar_sessions!
        Services::SessionRevocation.revoke!(self)
      end

      def beskar_session_valid?(request, token:)
        Services::SessionRevocation.allowed?(self, request: request, token: token)
      end

      def recent_failed_attempts(within: 1.hour)
        security_events.where(
          event_type: "login_failure",
          created_at: within.ago..Time.current
        )
      end

      def recent_successful_logins(within: 24.hours)
        security_events.where(
          event_type: "login_success",
          created_at: within.ago..Time.current
        )
      end

      def suspicious_login_pattern?
        # Check for rapid successive attempts
        recent_attempts = recent_failed_attempts(within: 5.minutes)
        return true if recent_attempts.count >= 3

        # Check for geographic anomalies
        return true if geographic_anomaly_detected?

        false
      end

      private

      def persist_authentication_audit(event)
        Beskar::SecurityEvent.transaction(requires_new: true) { event.save }
      rescue => error
        Beskar::Logger.warn("Authentication audit unavailable (#{error.class})")
        false
      end

      def extract_user_email
        # Try different email attribute names
        if respond_to?(:email)
          email
        else
          (respond_to?(:email_address) ? email_address : nil)
        end
      end

      def extract_security_context(request)
        Services::RequestContext.security_metadata(request)
      end

      def assess_authentication_risk(request, result)
        Services::RiskAssessment.new(request, user: self, result: result)
      end

      # Numeric compatibility helper; authentication uses the complete assessment.
      def calculate_risk_score(request, result)
        assess_authentication_risk(request, result).score
      end

      def geographic_anomaly_detected?
        observations = Services::RiskAssessment.observations(self)
        observations.sort_by { |entry| [entry[:occurred_at], entry[:event_id]] }.each_cons(2).any? do |previous, current|
          assessment = Services::LocationAssessment.new(current[:location], observations: [previous], at: current[:occurred_at]).call
          assessment[:location][:impossible_travel]
        end
      end

      # Check if the account should be locked based on risk score
      def check_and_lock_if_high_risk(security_event, request)
        return unless Beskar.configuration.risk_based_locking_enabled?
        return unless security_event.risk_score

        locker = Beskar::Services::AccountLocker.new(
          self,
          risk_score: security_event.risk_score,
          reason: determine_lock_reason(security_event),
          metadata: {
            ip_address: Beskar::Services::RequestContext.ip(request),
            user_agent: Services::RequestContext.text(request.user_agent),
            security_event_id: security_event.id,
            authentication_attempt_id: security_event.beskar_attempt&.id,
            geolocation: security_event.geolocation,
            device_info: security_event.device_info,
            risk_assessment: security_event.metadata["risk_assessment"]
          }
        )

        security_event.metadata["lock_decision"] = {
          "threshold" => Beskar.configuration.risk_threshold,
          "strategy_available" => locker.supported?,
          "would_lock" => locker.supported? && security_event.risk_score >= Beskar.configuration.risk_threshold && !locker.locked?,
          "enforcement_enabled" => Services::RequestContext.enforce?(Services::RequestContext.ip(request))
        }

        if locker.lock_if_necessary!
          Beskar::Logger.warn("Account locked due to high risk score: #{security_event.risk_score}")

          # Trigger auth-system-specific lock handling
          handle_high_risk_lock(security_event, request)
          true
        else
          false
        end
      end

      # Determine the specific reason for locking
      def determine_lock_reason(security_event)
        metadata = (security_event.metadata || {}).deep_stringify_keys

        # Check for impossible travel
        if metadata.dig("geolocation", "impossible_travel") == true
          return :impossible_travel
        end

        # Check for suspicious device
        device_info = metadata["device_info"] || {}
        if device_info["bot"] == true || device_info["bot_signature"] == true || device_info["suspicious"] == true
          return :suspicious_device
        end

        # Check for geographic anomaly
        geolocation = metadata["geolocation"] || {}
        if geolocation["country_change"] == true || geolocation["high_risk_country"] == true
          return :geographic_anomaly
        end

        # Default to high risk authentication
        :high_risk_authentication
      end

      # Override this in auth-system-specific modules
      def handle_high_risk_lock(security_event, request)
        Beskar::Logger.debug("High risk lock handled - override in specific module")
      end

      # Kept for integrations that called these former private helpers. Repeated
      # IP use, automatic unlocks, and account-lock attempts do not establish trust.
      def established_pattern?(_request)
        false
      end

      def location_established?(_ip_address)
        false
      end
    end
  end
end
