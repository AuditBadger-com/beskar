module Beskar
  module Services
    # Account-lifetime state. Never expire or clear generations on unlock: doing
    # so would resurrect credentials issued before a lock. No cache authority.
    class SessionRevocation
      def self.token(user)
        SecurityState.uncached { SecurityState.read(NativeAccountLock.key(user)).fetch("generation", "0") }
      rescue ActiveRecord::ActiveRecordError
        raise AuthenticationAttempt::Unavailable, "Session state unavailable"
      end

      def self.revoke!(user)
        SecurityState.mutate(NativeAccountLock.key(user), ttl: nil) do |state|
          rotate!(state.fetch(NativeAccountLock.key(user)))
          NativeAccountLock.revoke_sessions!(user) if user.respond_to?(:beskar_access_locked?)
        end
      rescue ActiveRecord::ActiveRecordError
        raise AuthenticationAttempt::Unavailable, "Session revocation unavailable"
      end

      def self.rotate!(data)
        data["generation"] = SecureRandom.uuid
      end

      # Rails-native database sessions need no new session column. Check the
      # persisted row as well as the account lock, including stale Current objects.
      def self.native_session_allowed?(record, request:)
        return false unless record&.persisted?
        record.reload
        user = record.user
        user&.beskar_access_allowed?(request)
      rescue ActiveRecord::RecordNotFound
        false
      rescue ActiveRecord::ActiveRecordError
        raise AuthenticationAttempt::Unavailable, "Session state unavailable"
      end

      # Tokens must carry the generation captured at issuance inside their
      # authenticated server-side record or signed claims, never a request param.
      # Call on every protected request / WebSocket message, not just connect.
      def self.allowed?(user, request:, token:)
        return false unless user&.persisted? && token.is_a?(String)
        # Cable connections can retain a model object after its database row is
        # deleted. persisted? alone only describes that stale Ruby object.
        user = user.class.uncached { user.class.find_by(user.class.primary_key => user.id) }
        return false unless user
        data = SecurityState.uncached { SecurityState.read(NativeAccountLock.key(user)) }
        return false unless ActiveSupport::SecurityUtils.secure_compare(data.fetch("generation", "0"), token)
        return true unless RequestContext.enforce?(RequestContext.ip(request))
        if user.respond_to?(:beskar_access_locked?)
          !NativeAccountLock.locked_data?(data)
        elsif user.respond_to?(:access_locked?)
          !user.access_locked?
        else
          true
        end
      rescue ActiveRecord::ActiveRecordError
        raise AuthenticationAttempt::Unavailable, "Session state unavailable"
      end
    end
  end
end
