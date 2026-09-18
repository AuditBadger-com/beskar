module Beskar
  module Services
    # Framework-neutral admission for token issuance, OAuth and custom APIs.
    # The host verifies credentials in the block and returns the authenticated
    # model (or nil). This method never issues a credential or grants access.
    class Authentication
      def self.authenticate(request, model:, scope:, credentials: {})
        user = model.find_by(credentials) unless credentials.empty?
        attempt = AuthenticationAttempt.reserve(request, model: model, scope: scope,
          user: user, credentials: credentials)
        unless attempt.allowed?
          model.track_failed_authentication(request, scope, attempt: attempt)
          return attempt
        end
        resource = yield
        if resource
          raise AuthenticationAttempt::Unavailable, "Authentication identity mismatch" unless resource.is_a?(model) && resource.persisted?
          resource.track_authentication_event(request, :success, attempt: attempt, persist: false)
          attempt.verify_generation!
          attempt.persist_outcome!
        else
          model.track_failed_authentication(request, scope, attempt: attempt)
          attempt.deny!(:invalid_credentials)
        end
        attempt
      rescue ActiveRecord::ActiveRecordError
        raise AuthenticationAttempt::Unavailable, "Authentication temporarily unavailable"
      end
    end
  end
end
