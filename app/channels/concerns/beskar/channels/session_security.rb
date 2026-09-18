module Beskar
  module Channels
    # Prepend to ApplicationCable::Channel to cover every subscription and inbound
    # action. The connection resolves identity and the credential's signed epoch.
    # Standard outbound channel transmissions are checked too. No polling of idle
    # connections is needed; direct connection.transmit bypasses channel policy.
    module SessionSecurity
      def subscribe_to_channel
        unless beskar_session_allowed?
          reject
          reject_subscription
          return
        end
        super
      end

      def perform_action(data)
        unless beskar_session_allowed?
          stop_all_streams
          connection.close(reason: "authentication_revoked", reconnect: false)
          return
        end
        super
      end

      private

      def transmit(data, via: nil)
        unless beskar_session_allowed?
          stop_all_streams
          connection.close(reason: "authentication_revoked", reconnect: false)
          return
        end
        super
      end

      def beskar_session_allowed?
        return false unless connection.respond_to?(:beskar_authenticated_user) && connection.respond_to?(:beskar_authenticated_generation)
        Services::SessionRevocation.allowed?(connection.beskar_authenticated_user,
          request: connection.request, token: connection.beskar_authenticated_generation)
      rescue Services::AuthenticationAttempt::Unavailable
        false
      end
    end
  end
end
