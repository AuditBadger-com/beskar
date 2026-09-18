module Beskar
  module Models
    # Devise-specific security tracking functionality
    # This module hooks into Devise/Warden callbacks and provides
    # Devise-specific authentication tracking and account locking
    module SecurityTrackableDevise
      extend ActiveSupport::Concern

      included do
        # Include the generic functionality first
        include Beskar::Models::SecurityTrackableGeneric
        prepend SessionCredentials

        after_update :revoke_beskar_sessions_after_lock

        # The engine registers the single Warden outcome callback. Devise's
        # after_database_authentication is an instance hook, not a callback macro.
      end

      module SessionCredentials
        def authenticatable_salt
          Digest::SHA256.hexdigest([super, beskar_session_token].to_json)
        end

        def rememberable_value
          Digest::SHA256.hexdigest([super, beskar_session_token].to_json)
        end
      end

      # Track successful login via Devise callback
      def track_successful_login
        # Skip tracking if disabled in configuration
        unless Beskar.configuration.track_successful_logins?
          Beskar::Logger.debug("Successful login tracking disabled in configuration")
          return
        end

        if (current_request = request_from_context)
          track_authentication_event(current_request, :success)
        end
      rescue => e
        Beskar::Logger.warn("Failed to track successful login: #{e.class}")
        nil
      end

      # PUBLIC method called from Warden callback in engine.rb
      # Checks if account was just locked due to high risk and signs out if needed
      def check_high_risk_lock_and_signout(auth, scope: nil, attempt: nil)
        return unless Beskar.configuration.risk_based_locking_enabled?
        return unless scope
        attempt ||= Services::AuthenticationAttempt.current(auth.request, scope) if auth.respond_to?(:request)
        return unless attempt && attempt.user == self && attempt.scope == scope.to_s && attempt.locked_now
        return unless Services::RequestContext.enforce?(attempt.ip_address)
        auth.logout(scope)
        throw :warden, scope: scope, message: :account_locked_due_to_high_risk
      end

      private

      # Runs in the user save transaction, including Devise's own failed-password
      # lock and ordinary updates of locked_at, not just Beskar risk-based locks.
      def revoke_beskar_sessions_after_lock
        revoke_beskar_sessions! if has_attribute?(:locked_at) && saved_change_to_locked_at? && locked_at.present?
      end

      # Devise-specific: Try to get request from various Warden/Devise contexts
      def request_from_context
        # Try to get request from various contexts
        if defined?(Current) && Current.respond_to?(:request)
          Current.request
        elsif Thread.current[:request]
          Thread.current[:request]
        elsif defined?(ActionController::Base) && ActionController::Base.respond_to?(:current_request)
          ActionController::Base.current_request
        elsif defined?(Warden) && Warden::Manager.respond_to?(:current_request)
          Warden::Manager.current_request
        end
      rescue => e
        Beskar::Logger.debug("Could not get request from context: #{e.class}")
        nil
      end

      # Devise-specific: The current attempt carries the completed lock result.
      # The actual sign-out is handled by Warden callback in engine.rb
      def handle_high_risk_lock(security_event, request)
        Beskar::Logger.debug("Devise account locked - Warden callback will handle sign-out")
        # The Warden callback uses the attempt, independently of audit writes.
      end
    end
  end
end
