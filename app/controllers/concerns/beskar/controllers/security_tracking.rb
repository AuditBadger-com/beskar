module Beskar
  module Controllers
    # Rails-native integration:
    # before_action -> { admit_authentication_attempt(User, :user) }, only: :create
    # After User.authenticate_by succeeds:
    # return unless complete_authentication(user) { start_new_session_for(user) }
    # Existing-session readers must also call user.beskar_access_allowed?(request).
    module SecurityTracking
      extend ActiveSupport::Concern

      private

      # Run before password verification. Credentials are identity fields only;
      # passwords must never be included in a persistent counter key.
      def admit_authentication_attempt(model, scope = :user, credentials: nil)
        values = params[scope].is_a?(ActionController::Parameters) ? params[scope] : params
        key = model.attribute_names.include?("email_address") ? :email_address : :email
        credentials ||= {key => values[key]}
        user = model.find_by(credentials)
        @beskar_authentication_attempt = Services::AuthenticationAttempt.reserve(request,
          model: model, scope: scope, user: user, credentials: credentials, cache: true)
        return true if @beskar_authentication_attempt.allowed?

        model.track_failed_authentication(request, scope, attempt: @beskar_authentication_attempt)
        render_authentication_response(@beskar_authentication_attempt.response)
        false
      rescue Services::AuthenticationAttempt::Unavailable, ActiveRecord::ActiveRecordError
        render_authentication_response(Services::AuthenticationAttempt.unavailable_response)
        false
      end

      # The preferred Rails-native API. Final audit persistence happens after the
      # session guard, so a denied session is never learned as a successful login.
      def complete_authentication(user)
        return false unless user
        attempt = native_authentication_attempt(user)
        user.track_authentication_event(request, :success, attempt: attempt, persist: false)
        if attempt.allowed?
          admitted = user.with_beskar_session(request, generation: attempt.session_token) { yield }
          attempt.deny!(:account_locked) unless admitted
        end
        if attempt.event
          attempt.event.event_type = "authentication_blocked" unless attempt.allowed?
          attempt.event.metadata = (attempt.event.metadata || {}).merge("authentication" => attempt.metadata)
          if Beskar.configuration.track_successful_logins?
            user.send(:persist_authentication_audit, attempt.event)
            user.analyze_suspicious_patterns_async if attempt.allowed? && Beskar.configuration.auto_analyze_patterns?
          end
        end
        render_authentication_response(attempt.response) unless attempt.allowed?
        attempt.allowed?
      rescue Services::AuthenticationAttempt::Unavailable, ActiveRecord::ActiveRecordError
        render_authentication_response(Services::AuthenticationAttempt.unavailable_response)
        false
      end

      # Compatibility API for custom integrations; callers must honor the boolean
      # result and guard session creation. Prefer complete_authentication above.
      def track_authentication_success(user)
        return false unless user
        attempt = native_authentication_attempt(user)
        user.track_authentication_event(request, :success, attempt: attempt)
        render_authentication_response(attempt.response) unless attempt.allowed?
        attempt.allowed?
      rescue Services::AuthenticationAttempt::Unavailable
        render_authentication_response(Services::AuthenticationAttempt.unavailable_response)
        false
      end

      def native_authentication_attempt(user)
        @beskar_authentication_attempt ||= Services::AuthenticationAttempt.reserve(request,
          model: user.class, scope: user.class.name.underscore, user: user, cache: true)
      end

      def track_authentication_failure(model_class, scope = :user)
        model_class.track_failed_authentication(request, scope, attempt: @beskar_authentication_attempt)
      end

      def render_authentication_response(response)
        return if performed?
        status, headers, body = response
        headers.each { |name, value| self.response.set_header(name, value) }
        render body: body.join, status: status
      end

      def track_logout(user)
        return unless user && Beskar.configuration.security_tracking_enabled?
        user.security_events.create!(
          event_type: "logout", ip_address: Services::RequestContext.ip(request),
          user_agent: Services::RequestContext.text(request.user_agent), risk_score: 0,
          metadata: {timestamp: Time.current.iso8601, request_path: Services::RequestContext.path(request)}
        )
      rescue => error
        Beskar::Logger.warn("Logout audit unavailable (#{error.class})")
      end
    end
  end
end
