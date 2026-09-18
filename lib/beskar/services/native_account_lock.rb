module Beskar
  module Services
    # Persistent Rails-native locks and session creation serialize on one row.
    # unlock_at lives in data: merely checking/creating a session must never
    # prolong a finite lock, and manual locks must not expire through cleanup.
    class NativeAccountLock
      def self.key(user)
        raise ArgumentError, "Account must be persisted" unless user.persisted?
        "account_lock:#{user.class.base_class.name}:#{user.id}"
      end

      def self.locked_data?(data)
        data["locked"] && (!data["unlock_at"] || data["unlock_at"] > Time.current.to_f)
      end

      def self.locked?(user)
        SecurityState.uncached { !!locked_data?(SecurityState.read(key(user))) }
      end

      def self.lock!(user, duration:, metadata: {})
        return false unless RequestContext.enforce?(metadata[:ip_address] || metadata["ip_address"])
        raise ArgumentError, "Unlock duration must be positive or nil" if duration && !duration.to_f.positive?
        cleanup_error = nil
        result = SecurityState.mutate(key(user), ttl: nil) do |state|
          cleanup_error = nil
          data = state.fetch(key(user))
          next false if locked_data?(data)
          data.replace("locked" => true, "locked_at" => Time.current.iso8601,
            "unlock_at" => duration && Time.current.to_f + duration.to_f, "context" => AuditData.metadata(metadata))
          SessionRevocation.rotate!(data)
          # Every database session, including the current one, is revoked.
          begin
            user.class.transaction(requires_new: true) { revoke_sessions!(user) }
          rescue => error
            # A host callback must not prevent the authoritative lock. Session
            # readers deny access until cleanup succeeds during explicit unlock;
            # automatic expiry must never reactivate unrevoked old sessions.
            cleanup_error = error
            data.merge!("session_cleanup_pending" => true, "unlock_at" => nil)
          end
          true
        end
        Beskar::Logger.error("Locked account; session cleanup failed (#{cleanup_error.class})") if cleanup_error
        result
      end

      def self.require_manual_unlock!(user)
        SecurityState.mutate(key(user), ttl: nil) do |state|
          state.fetch(key(user)).merge!("locked" => true, "unlock_at" => nil, "locked_at" => Time.current.iso8601)
        end
      end

      def self.unlock!(user)
        SecurityState.mutate(key(user), ttl: nil) do |state|
          data = state.fetch(key(user))
          revoke_sessions!(user) if data["session_cleanup_pending"]
          data.replace(data.slice("generation"))
        end
        true
      end

      def self.revoke_sessions!(user)
        sessions = user.sessions
        # Bypass both a loaded association and MySQL's earlier transaction
        # snapshot. Keep association removal and model destruction callbacks.
        sessions.destroy(sessions.lock.to_a)
        sessions.reset
        # A host callback can abort removal. Verify against a current read too.
        raise ActiveRecord::RecordNotDestroyed, "Account sessions could not be revoked" if sessions.lock.exists?
      end

      def self.with_session(user, request, generation: nil)
        SecurityState.mutate(key(user), ttl: nil) do |state|
          next false if generation && generation != state.fetch(key(user)).fetch("generation", "0")
          next false if RequestContext.enforce?(RequestContext.ip(request)) && locked_data?(state.fetch(key(user)))
          yield
          true
        end
      end
    end
  end
end
