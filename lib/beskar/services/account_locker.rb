# frozen_string_literal: true

module Beskar
  module Services
    # Service for locking user accounts based on risk scores
    #
    # This service provides a modular approach to account locking that can work
    # with Devise's lockable module or the Rails-native lock adapter. It keeps
    # Devise-specific code isolated for maintainability.
    #
    # @example Basic usage with Devise lockable
    #   locker = Beskar::Services::AccountLocker.new(user, risk_score: 85, reason: :high_risk_login)
    #   locker.lock_if_necessary!
    #
    # @example Check if account should be locked
    #   if locker.should_lock?
    #     locker.lock!
    #   end
    #
    class AccountLocker
      attr_reader :user, :risk_score, :reason, :metadata

      # Initialize the account locker
      #
      # @param user [ActiveRecord::Base] The user to potentially lock
      # @param risk_score [Integer] The calculated risk score (0-100)
      # @param reason [Symbol] The reason for potential lock (:high_risk_login, :impossible_travel, etc.)
      # @param metadata [Hash] Additional context for the lock decision
      def initialize(user, risk_score:, reason: :high_risk_authentication, metadata: {})
        @user = user
        @risk_score = risk_score
        @reason = reason
        @metadata = metadata.deep_symbolize_keys
      end

      # Check if account should be locked based on configuration
      #
      # @return [Boolean] true if account should be locked
      def should_lock?
        return false unless Beskar.configuration.risk_based_locking_enabled?
        return false unless user
        return false unless RequestContext.enforce?(metadata[:ip_address])
        return false if user_already_locked?

        risk_score >= Beskar.configuration.risk_threshold
      end

      # Lock the account if necessary (based on should_lock? check)
      #
      # @return [Boolean] true if account was locked, false otherwise
      def lock_if_necessary!
        return false unless should_lock?
        lock!
      end

      # Lock the account using the configured strategy
      #
      # @return [Boolean] true if lock was successful, false otherwise
      def lock!
        return false unless user
        return false unless RequestContext.enforce?(metadata[:ip_address])

        strategy = effective_strategy

        result = case strategy
        when :devise_lockable
          lock_with_devise_lockable
        when :rails_auth
          NativeAccountLock.lock!(user, duration: Beskar.configuration.auto_unlock_time, metadata: metadata)
        when :none
          false
        else
          Beskar::Logger.warn("Unknown lock strategy: #{strategy}", component: :AccountLocker)
          false
        end

        # Always log lock events when risk-based locking is enabled
        # This creates an audit trail even if actual locking fails
        if Beskar.configuration.log_lock_events?
          log_lock_event(result)
        end

        if result
          notify_user if Beskar.configuration.notify_user_on_lock?
        end

        result
      end

      # Unlock the account using the configured strategy
      #
      # @return [Boolean] true if unlock was successful
      def unlock!
        return false unless user

        strategy = effective_strategy

        result = case strategy
        when :devise_lockable
          unlock_with_devise_lockable
        when :rails_auth
          NativeAccountLock.unlock!(user)
        when :none
          false
        else
          false
        end

        # Log the administrative unlock; this does not establish trusted history.
        if result && Beskar.configuration.log_lock_events?
          log_unlock_event
        end

        result
      end

      # Check if user is currently locked
      #
      # @return [Boolean] true if user is locked
      def locked?
        user_already_locked?
      end

      def supported?
        case effective_strategy
        when :devise_lockable then devise_lockable_available?
        when :rails_auth then user.respond_to?(:beskar_access_locked?) && user.respond_to?(:sessions)
        else false
        end
      end

      private

      def effective_strategy
        strategy = Beskar.configuration.lock_strategy
        if strategy == :devise_lockable && user.respond_to?(:beskar_access_locked?)
          :rails_auth
        else
          strategy
        end
      end

      # Check if user is already locked
      def user_already_locked?
        return false unless user

        if user.respond_to?(:beskar_access_locked?)
          user.beskar_access_locked?
        elsif user.respond_to?(:access_locked?)
          user.access_locked?
        elsif user.respond_to?(:locked_at)
          user.locked_at.present?
        else
          false
        end
      end

      # Lock account using Devise's lockable module
      def lock_with_devise_lockable
        unless devise_lockable_available?
          Beskar::Logger.warn("Devise lockable not available for #{user.class.name}", component: :AccountLocker)
          return false
        end

        begin
          # Use Devise's lock_access! method
          unless user.lock_access!(send_instructions: false)
            raise AuthenticationAttempt::Unavailable, "Account lock could not be persisted"
          end

          # Devise owns its unlock policy (unlock_strategy/unlock_in). Beskar's
          # auto_unlock_time applies to Rails-native locks, not Devise columns.

          Beskar::Logger.info("Locked account #{user.id} (#{user.class.name}) - Risk: #{risk_score}, Reason: #{reason}", component: :AccountLocker)
          true
        rescue ActiveRecord::ActiveRecordError
          raise AuthenticationAttempt::Unavailable, "Account lock could not be persisted"
        rescue AuthenticationAttempt::Unavailable
          raise
        rescue => e
          Beskar::Logger.error("Failed to lock account (#{e.class})", component: :AccountLocker)
          raise AuthenticationAttempt::Unavailable, "Account lock could not be persisted"
        end
      end

      # Unlock account using Devise's lockable module
      def unlock_with_devise_lockable
        unless devise_lockable_available?
          Beskar::Logger.warn("Devise lockable not available for #{user.class.name}", component: :AccountLocker)
          return false
        end

        begin
          user.unlock_access!
          Beskar::Logger.info("Unlocked account #{user.id} (#{user.class.name})", component: :AccountLocker)
          true
        rescue => e
          Beskar::Logger.error("Failed to unlock account: #{e.class}", component: :AccountLocker)
          false
        end
      end

      # Check if Devise lockable is available for this user
      def devise_lockable_available?
        defined?(Devise) &&
          user.class.respond_to?(:devise_modules) &&
          user.class.devise_modules.include?(:lockable) &&
          user.respond_to?(:lock_access!)
      end

      # Log the lock event to security events
      # Always logs, even if actual lock fails, to maintain audit trail
      def log_lock_event(lock_succeeded = true)
        return unless user.respond_to?(:security_events)

        begin
          event_type = lock_succeeded ? "account_locked" : "lock_attempted"

          Beskar::SecurityEvent.transaction(requires_new: true) do
            Beskar::SecurityEvent.create!(
              user_type: user.class.polymorphic_name, user_id: user.id,
              event_type: event_type,
              ip_address: metadata[:ip_address] || "system",
              user_agent: metadata[:user_agent] || "beskar_system",
              risk_score: risk_score,
              metadata: {
                reason: reason,
                risk_threshold: Beskar.configuration.risk_threshold,
                lock_strategy: effective_strategy,
                auto_unlock_time: Beskar.configuration.auto_unlock_time,
                locked_at: Time.current.iso8601,
                lock_succeeded: lock_succeeded,
                additional_context: metadata
              }
            )
          end
        rescue => e
          Beskar::Logger.warn("Failed to log lock event: #{e.class}", component: :AccountLocker)
        end
      end

      # Log the administrative action without granting IP/device trust.
      def log_unlock_event
        return unless user.respond_to?(:security_events)

        begin
          Beskar::SecurityEvent.transaction(requires_new: true) do
            Beskar::SecurityEvent.create!(
              user_type: user.class.polymorphic_name, user_id: user.id,
              event_type: "account_unlocked",
              ip_address: metadata[:ip_address] || "system",
              user_agent: metadata[:user_agent] || "beskar_system",
              risk_score: 0, # Unlock has no risk
              metadata: {
                unlocked_at: Time.current.iso8601,
                unlock_method: "manual",
                additional_context: metadata
              }
            )
          end
        rescue => e
          Beskar::Logger.warn("Failed to log unlock event: #{e.class}", component: :AccountLocker)
        end
      end

      # Notify user about account lock
      def notify_user
        Notifications.enqueue(user, "account_locked")
      end
    end
  end
end
