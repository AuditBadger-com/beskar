module Beskar
  class ApplicationController < ActionController::Base
    # Use the main app's CSRF protection settings
    protect_from_forgery with: :exception, prepend: true

    layout "beskar/application"

    # Ensure CSRF token is available for forms
    before_action :ensure_csrf_token

    before_action :authenticate_admin!
    before_action :authorize_admin_action!

    private

    def authorize_admin_action!
      permission = if controller_name == "administrative_actions"
        :read_audit
      elsif action_name == "export"
        :export
      elsif controller_name == "banned_ips" && %w[new create edit update destroy extend review bulk_action].include?(action_name)
        :manage_bans
      else
        :read
      end
      callback = Beskar.configuration.authorize_admin
      allowed = callback && instance_exec(request, permission, &callback) == true
      head :forbidden unless performed? || allowed
    rescue => error
      Beskar::Logger.warn("Administrative authorization unavailable (#{error.class})")
      head :service_unavailable unless performed?
    end

    def administrative_actor!
      callback = Beskar.configuration.audit_actor
      actor = instance_exec(request, &callback) if callback
      raise Services::AdministrativeAudit::Unavailable unless Services::AdministrativeBans.valid_actor?(actor)
      actor
    rescue => error
      Beskar::Logger.warn("Administrative actor unavailable (#{error.class})")
      raise Services::AdministrativeAudit::Unavailable, "Administrative identity unavailable"
    end

    # Override this method in your application to implement authentication
    # For example, you might want to use Devise's authenticate_admin! or
    # a custom authentication method
    def authenticate_admin!
      unless Beskar.configuration.authenticate_admin.present?
        handle_missing_authentication_configuration
        return false
      end

      handle_custom_authentication
    end

    def handle_custom_authentication
      # Execute the authentication block in the controller's context
      # This gives the block access to controller methods like cookies, session,
      # authenticate_or_request_with_http_basic, etc.
      result = instance_exec(request, &Beskar.configuration.authenticate_admin)
      return false if performed?
      return true if result

      handle_authentication_failure
      false
    rescue => e
      Rails.logger.error "Beskar authentication error: #{e.class}"
      handle_authentication_failure
      false
    end

    def handle_missing_authentication_configuration
      # Log the configuration error for debugging, but return 404 to avoid revealing Beskar is installed
      error_message = <<~'MSG'
        Beskar authentication not configured!

        Configure Beskar.configuration.authenticate_admin in your initializer:

        # config/initializers/beskar.rb
        Beskar.configuration.authenticate_admin = ->(request) do
          # The block is executed in the controller context, giving you access
          # to controller methods like cookies, session, authenticate_or_request_with_http_basic, etc.

          # Example 1: Check for admin user with Devise
          # user = request.env['warden']&.authenticate(scope: :user)
          # user&.admin?

          # Example 2: HTTP Basic Auth (uses controller method)
          # authenticate_or_request_with_http_basic do |username, password|
          #   Beskar::Services::RequestContext.secure_match?(username, ENV['BESKAR_USERNAME']) &&
          #     Beskar::Services::RequestContext.secure_match?(password, ENV['BESKAR_PASSWORD'])
          # end

          # Example 3: Cookie-based auth (uses controller cookies)
          # Beskar::Services::RequestContext.secure_match?(cookies.signed[:admin_token], ENV['BESKAR_ADMIN_TOKEN'])

          # Example 4: Simple token-based auth
          # token = ENV['BESKAR_ADMIN_TOKEN']
          # token.present? && Beskar::Services::RequestContext.secure_match?(request.headers['Authorization'], "Bearer #{token}")

          # Example 5: For development/testing (NOT for production!)
          # Rails.env.development? || Rails.env.test?
        end
      MSG

      Rails.logger.error error_message
      render_404
    end

    def handle_authentication_failure
      # Return 404 to avoid revealing that Beskar is installed
      render_404 unless performed?
    end

    def render_404
      respond_to do |format|
        format.html { render file: "#{Rails.public_path}/404.html", status: :not_found, layout: false }
        format.json { render json: {error: "Not found"}, status: :not_found }
        format.any { head :not_found }
      end
    end

    # Helper method to format timestamps
    def format_timestamp(time)
      return "-" unless time
      time.in_time_zone.strftime("%Y-%m-%d %H:%M:%S %Z")
    end
    helper_method :format_timestamp

    def ban_expiry_input_value(time)
      time&.utc&.iso8601(3)&.delete_suffix("Z")
    end
    helper_method :ban_expiry_input_value

    # Helper method to format IP addresses with location if available
    def format_ip_with_location(ip, metadata = {})
      return ip unless metadata.present?

      location_parts = []
      if metadata["geolocation"].present?
        geo = metadata["geolocation"]
        location_parts << geo["city"] if geo["city"].present?
        location_parts << geo["country"] if geo["country"].present?
      end

      return ip if location_parts.empty?
      "#{ip} (#{location_parts.join(", ")})"
    end
    helper_method :format_ip_with_location

    # Helper to determine risk level badge color
    def risk_level_class(risk_score)
      RiskLevel::BADGES.fetch(RiskLevel.for(risk_score), "neutral")
    end
    helper_method :risk_level_class

    def risk_level_color(risk_score)
      RiskLevel::COLORS.fetch(RiskLevel.for(risk_score), "#697386")
    end
    helper_method :risk_level_color

    def risk_level_label(risk_score)
      level = RiskLevel.for(risk_score)
      level ? "#{level.to_s.capitalize} Risk" : "Unknown Risk"
    end
    helper_method :risk_level_label

    def audit_user_label(event)
      attempted = event.attempted_email
      Services::AuditData.user_email(event.user) || (Services::AuditData.field(:email, attempted, limit: 320) if attempted.present?) ||
        (event.user_id ? "User ##{event.user_id}" : "-")
    end
    helper_method :audit_user_label

    # Helper to format event type for display
    def format_event_type(event_type)
      event_type.to_s.humanize.titleize
    end
    helper_method :format_event_type

    # Pagination helper
    def paginate(collection, per_page: 25)
      # Handle per_page from params if provided
      if params[:per_page].present?
        per_page = params[:per_page].to_i
        per_page = 25 if per_page <= 0  # Default if invalid
        per_page = 100 if per_page > 100  # Max limit
      end

      page = (params[:page] || 1).to_i
      page = 1 if page < 1

      total_count = collection.count
      total_pages = (total_count > 0) ? (total_count.to_f / per_page).ceil : 0

      offset = (page - 1) * per_page
      records = collection.limit(per_page).offset(offset)

      {
        records: records,
        current_page: page,
        total_pages: total_pages,
        total_count: total_count,
        per_page: per_page,
        has_previous: page > 1,
        has_next: page < total_pages,
        previous_page: (page > 1) ? page - 1 : nil,
        next_page: (page < total_pages) ? page + 1 : nil
      }
    end

    # Ensure CSRF token is properly set for forms in the engine
    def ensure_csrf_token
      # Force generation of CSRF token if not present
      form_authenticity_token
    end
  end
end
