module Beskar
  class Engine < ::Rails::Engine
    isolate_namespace Beskar

    initializer "beskar.middleware" do |app|
      app.config.middleware.use ::Beskar::Middleware::RequestAnalyzer
    end

    initializer "beskar.warden_callbacks", after: :load_config_initializers do
      if defined?(Devise)
        require "devise/strategies/database_authenticatable"
        Devise::Strategies::DatabaseAuthenticatable.prepend(Beskar::DeviseAuthentication)
      end

      if defined?(Warden)
        Warden::Strategies::Base.prepend(Beskar::WardenStrategyAdmission)
        Warden::Proxy.prepend(Beskar::WardenSessionAdmission)

        Warden::Manager.before_failure do |env, opts|
          next unless env
          request = ActionDispatch::Request.new(env)
          attempt = Services::AuthenticationAttempt.current(request, opts[:scope])
          next unless attempt && !attempt.completed
          model = Beskar.configuration.model_class_for_scope(opts[:scope])
          model.track_failed_authentication(request, opts[:scope], attempt: attempt) if model&.respond_to?(:track_failed_authentication)
        end
      end
    end

    initializer "beskar.register_configuration_validation", after: :load_config_initializers do |app|
      # Register after host configuration files, so their after_initialize hooks
      # precede this one. Resolve app/jobs only after the main autoloader is ready.
      app.config.after_initialize { Beskar.configuration.validate!.seal! }
    end

    # Compatibility helper: only the current attempt's actual lock qualifies.
    def self.user_was_just_locked?(user, security_event)
      return false unless Beskar.configuration.risk_based_locking_enabled?
      attempt = security_event&.beskar_attempt
      !!(attempt && attempt.user == user && attempt.locked_now)
    end
  end
end
