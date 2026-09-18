module Beskar
  module Models
    # Rails 8 authentication-specific security tracking functionality
    # This module provides security tracking for models using has_secure_password
    # and session-based authentication (Rails 8 built-in authentication)
    module SecurityTrackableAuthenticable
      extend ActiveSupport::Concern

      included do
        # Include the generic functionality first
        include Beskar::Models::SecurityTrackableGeneric

        # No automatic callbacks like Devise - tracking is done explicitly
        # in controllers via the Beskar::Controllers::SecurityTracking concern
      end

      # Make handle_high_risk_lock public (it's private in Generic)
      public

      def beskar_access_locked?
        Services::NativeAccountLock.locked?(self)
      end

      def beskar_access_allowed?(request)
        !Services::RequestContext.enforce?(Services::RequestContext.ip(request)) || !beskar_access_locked?
      end

      def with_beskar_session(request, generation: nil, &block)
        Services::NativeAccountLock.with_session(self, request, generation: generation, &block)
      end

      # Rails 8 auth-specific: Handle high risk lock by destroying sessions
      # Public method called when high-risk event is detected
      def handle_high_risk_lock(security_event, request)
        return unless Services::RequestContext.enforce?(Services::RequestContext.ip(request))
        return unless beskar_access_locked?
        reason = determine_lock_reason(security_event)

        Beskar::Logger.warn("Rails auth high-risk lock detected: #{reason}")

        # NativeAccountLock already revoked every database session atomically
        # with the lock. A Rack session ID is not a sessions-table primary key.

        # Check if this warrants emergency password reset
        if should_reset_password?(security_event, reason)
          perform_emergency_password_reset(security_event, reason)
        end
      end

      # Destroy all user sessions (for impossible travel / high-risk scenarios)
      def destroy_all_sessions(except: nil)
        if respond_to?(:sessions) && sessions.respond_to?(:destroy_all)
          if except
            # Keep current session but destroy all others
            sessions.where.not(id: except).destroy_all
            Beskar::Logger.info("Destroyed #{sessions.count} sessions except current")
          else
            # Destroy ALL sessions including current
            count = sessions.count
            sessions.destroy_all
            Beskar::Logger.info("Destroyed all #{count} sessions")
          end
        else
          Beskar::Logger.warn("Model does not have sessions association, cannot destroy sessions")
        end
      rescue => e
        Beskar::Logger.error("Failed to destroy sessions: #{e.class}")
      end

      # Determine if emergency password reset is warranted
      def should_reset_password?(security_event, reason)
        config = Beskar.configuration.emergency_password_reset
        return false unless config[:enabled]
        return false unless Services::RequestContext.enforce?(security_event.ip_address)

        events = security_events.where(event_type: "account_locked")
          .where("created_at >= ?", 24.hours.ago)
        threshold = case reason
        when :impossible_travel then config[:impossible_travel_threshold] || 3
        when :suspicious_device then config[:suspicious_device_threshold] || 5
        else config[:total_locks_threshold] || 5
        end

        count = 0
        events.find_each do |event|
          data = (event.metadata || {}).deep_stringify_keys
          context = data["additional_context"] || {}
          matches = case reason
          when :impossible_travel
            data["reason"] == "impossible_travel" ||
              data.dig("geolocation", "impossible_travel") == true ||
              context.dig("geolocation", "impossible_travel") == true
          when :suspicious_device
            data["reason"] == "suspicious_device" ||
              data.dig("device_info", "suspicious") == true ||
              context.dig("device_info", "suspicious") == true
          else true
          end
          count += 1 if matches
          return true if count >= threshold
        end
        false
      end

      # Password invalidation and its mandatory recovery audit are one transaction.
      # Notification hooks run after commit, never inside a retryable state block.
      def perform_emergency_password_reset(security_event, reason)
        config = Beskar.configuration.emergency_password_reset
        return false unless config[:enabled]
        return false unless Services::RequestContext.enforce?(security_event.ip_address)

        self.class.transaction(requires_new: true) do
          new_password = SecureRandom.base58(32)
          update!(password: new_password, password_confirmation: new_password)
          Services::NativeAccountLock.require_manual_unlock!(self) if config[:require_manual_unlock]
          revoke_beskar_sessions!
          security_events.create!(
            event_type: "emergency_password_reset", ip_address: security_event.ip_address,
            user_agent: security_event.user_agent, risk_score: 100,
            metadata: {reason: reason.to_s, triggering_event_id: security_event.id,
                       authentication_attempt_id: security_event.beskar_attempt&.id,
                       timestamp: Time.current.iso8601, reset_method: "automatic"}
          )
        end
        # Keep the extension hooks independent: a failed user hook must not
        # suppress the security-team notification or undo the committed reset.
        Services::Notifications.after_commit { send_emergency_reset_notification(reason) } if config[:send_notification]
        Services::Notifications.after_commit { notify_security_team_of_reset(reason, security_event) } if config[:notify_security_team]
        true
      rescue => error
        Beskar::Logger.error("Emergency password reset failed (#{error.class})")
        false
      end

      # Send notification to user about emergency password reset
      def send_emergency_reset_notification(reason)
        Services::Notifications.enqueue(self, "emergency_password_reset")
      end

      # Notify security team about emergency password reset
      def notify_security_team_of_reset(reason, security_event)
        Services::Notifications.enqueue(self, "security_team_reset")
      end
    end
  end
end
