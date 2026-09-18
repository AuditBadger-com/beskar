module Beskar
  # Only the password strategy is intercepted. Warden's before_failure callback
  # also runs for protected-page visits without credentials, so it cannot safely
  # serve as an admission hook.
  module DeviseAuthentication
    def authenticate!
      model = mapping.to
      return super unless model.respond_to?(:track_failed_authentication)

      resource = model.find_for_database_authentication(authentication_hash)
      attempt = Services::AuthenticationAttempt.reserve(request, model: model, scope: scope,
        user: resource, credentials: authentication_hash, cache: true)
      resource ? attempt.bind_user!(resource) : attempt.bind_identity!(model, authentication_hash)
      unless attempt.allowed?
        model.track_failed_authentication(request, scope, attempt: attempt)
        return custom!(attempt.response)
      end
      super
    rescue Services::AuthenticationAttempt::Unavailable, ActiveRecord::ActiveRecordError => error
      Beskar::Logger.error("Authentication admission unavailable (#{error.class})")
      custom!(Services::AuthenticationAttempt.unavailable_response)
    end
  end
end
