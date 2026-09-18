module Beskar
  module Controllers
    # Include in the host API base controller, after host credential resolution.
    # The two readers are host methods; the generation must come from a verified
    # credential, not a freshly queried value or an unsigned request parameter.
    module SessionSecurity
      extend ActiveSupport::Concern

      included do
        before_action :require_beskar_session!
      end

      private

      def require_beskar_session!
        unless respond_to?(:beskar_authenticated_user, true) && respond_to?(:beskar_authenticated_generation, true)
          raise Services::AuthenticationAttempt::Unavailable, "Session adapter is not configured"
        end
        unless Services::SessionRevocation.allowed?(beskar_authenticated_user, request: request, token: beskar_authenticated_generation)
          response.headers["Cache-Control"] = "no-store"
          head :unauthorized
        end
      rescue Services::AuthenticationAttempt::Unavailable
        response.headers["Cache-Control"] = "no-store"
        head :service_unavailable
      end
    end
  end
end
