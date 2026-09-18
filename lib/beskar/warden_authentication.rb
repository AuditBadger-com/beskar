module Beskar
  # Wrap strategy execution, not before_failure (which also runs on anonymous
  # page visits). Database passwords retain their identity-aware admission hook.
  module WardenStrategyAdmission
    def _run!
      return super if defined?(Devise::Strategies::DatabaseAuthenticatable) && is_a?(Devise::Strategies::DatabaseAuthenticatable)
      model = Beskar.configuration.model_class_for_scope(scope)
      return super unless model&.respond_to?(:track_failed_authentication)

      request = ActionDispatch::Request.new(env)
      attempt = Services::AuthenticationAttempt.reserve(request, model: model, scope: scope, cache: true)
      unless attempt.allowed?
        model.track_failed_authentication(request, scope, attempt: attempt)
        custom!(attempt.response)
        return self
      end
      super
    rescue Services::AuthenticationAttempt::Unavailable, ActiveRecord::ActiveRecordError
      custom!(Services::AuthenticationAttempt.unavailable_response)
      self
    end
  end

  # Enforce even if a host uses set_user(..., run_callbacks: false). Includes
  # OAuth sign_in, non-password strategies, stateless Warden and session fetch.
  module WardenSessionAdmission
    def set_user(user, opts = {})
      return super unless user.respond_to?(:track_authentication_event)
      scope = opts[:scope] || config.default_scope
      request = ActionDispatch::Request.new(env)
      if opts[:event] == :fetch
        allowed = Services::SessionRevocation.allowed?(user, request: request,
          token: Services::SessionRevocation.token(user))
      else
        attempt = Services::AuthenticationAttempt.current(request, scope)
        attempt ||= Services::AuthenticationAttempt.reserve(request, model: user.class,
          scope: scope, user: user, cache: true)
        user.track_authentication_event(request, :success, attempt: attempt, persist: false)
        attempt.verify_generation!
        attempt.persist_outcome!
        allowed = attempt.allowed?
      end
      unless allowed
        logout(scope)
        throw :warden, scope: scope, message: :authentication_denied
      end
      super
    rescue Services::AuthenticationAttempt::Unavailable, ActiveRecord::ActiveRecordError
      logout(scope)
      raise Services::AuthenticationAttempt::Unavailable, "Authentication temporarily unavailable"
    end
  end
end
