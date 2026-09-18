require "csv"

module Beskar
  class BannedIpsController < ApplicationController
    include Controllers::AuditExport

    class ActorUnavailable < StandardError; end
    before_action :set_banned_ip, only: [:show, :edit, :update, :destroy, :extend, :review]
    before_action :prepare_administration, only: [:create, :update, :destroy, :extend, :bulk_action]
    rescue_from ActorUnavailable, with: :administration_unavailable
    rescue_from Services::AdministrativeBans::InvalidInput, Services::BanExpiry::InvalidInput do |error|
      render plain: error.message, status: :unprocessable_content
    end
    rescue_from ActiveRecord::ActiveRecordError, with: :administration_unavailable

    def index
      @banned_ips = Beskar::BannedIp.order(banned_at: :desc)

      # Apply filters
      apply_filters!

      # Paginate results
      @pagination = paginate(@banned_ips, per_page: params[:per_page]&.to_i || 25)
      @banned_ips = @pagination[:records]

      # Get filter options
      @ban_reasons = Beskar::BannedIp.distinct.pluck(:reason).compact.sort
      @ban_statuses = ["active", "expired", "permanent", "temporary"]
    end

    def show
      # Get related security events for this IP
      events = Beskar::SecurityEvent.where(ip_address: @banned_ip.ip_address)
      @related_events = events.preload(:user).order(created_at: :desc, id: :desc).limit(20)

      # Calculate statistics
      @stats = {
        total_events: events.count,
        avg_risk_score: events.average(:risk_score)&.round(1) || 0,
        max_risk_score: events.maximum(:risk_score) || 0,
        first_seen: events.minimum(:created_at),
        last_seen: events.maximum(:created_at)
      }
    end

    def new
      @banned_ip = Beskar::BannedIp.new
      @suggested_ip = params[:ip_address]
      @suggested_reason = params[:reason]
    end

    def create
      manager = BannedIpManager.new(create_params)
      @banned_ip = @administration.create!(manager.build)
      redirect_to banned_ip_path(@banned_ip), notice: "IP address #{@banned_ip.ip_address} has been banned successfully."
    rescue ActiveRecord::RecordInvalid => error
      render_invalid_ban(error, :new)
    end

    def edit
    end

    def update
      attributes = banned_ip_params.to_h
      if attributes.key?("expires_at")
        attributes["expires_at"] = if ActiveModel::Type::Boolean.new.cast(attributes.fetch("permanent", @banned_ip.permanent?))
          nil
        else
          Services::BanExpiry.parse(attributes["expires_at"])
        end
        # HTML datetime-local only represents milliseconds. Preserve the stored
        # microseconds when the displayed value was submitted without a change.
        current_expiry = @banned_ip.expires_at
        if params[:expiry_precision] == "milliseconds" && current_expiry &&
            attributes["expires_at"] == current_expiry.change(usec: current_expiry.usec / 1000 * 1000)
          attributes["expires_at"] = current_expiry
        end
      end
      count = @administration.change!([@banned_ip.id], action: "update", attributes: attributes)
      message = count.positive? ? "Ban for IP #{@banned_ip.ip_address} has been updated." : "No ban changes were necessary."
      redirect_to banned_ip_path(@banned_ip), notice: message
    rescue ActiveRecord::RecordInvalid => error
      render_invalid_ban(error, :edit)
    end

    def destroy
      ip_address = @banned_ip.ip_address
      @administration.change!([@banned_ip.id], action: "unban")

      redirect_to banned_ips_path,
        notice: "IP address #{ip_address} has been unbanned."
    end

    def extend
      action = (params[:duration] == "permanent") ? "make_permanent" : "extend"
      @administration.change!([@banned_ip.id], action: action, duration: params[:duration] || "24h")
      redirect_to banned_ip_path(@banned_ip), notice: "Ban updated and administrative action recorded."
    end

    def review
      @operation = params[:operation]
      head :bad_request unless %w[unban extend].include?(@operation)
    end

    def bulk_action
      action = params[:bulk_action]
      raise Services::AdministrativeBans::InvalidInput, "Unknown bulk action" unless %w[unban extend make_permanent].include?(action)
      count = @administration.change!(params[:ip_ids], action: action, duration: params[:duration])
      description = {"unban" => "unbanned", "make_permanent" => "made permanent", "extend" => "extended"}.fetch(action)
      redirect_to banned_ips_path, notice: "#{count} ban(s) #{description}; administrative actions recorded."
    end

    def export
      @banned_ips = Beskar::BannedIp.all
      apply_filters!
      records = export_records(@banned_ips)
      return if performed?

      respond_to do |format|
        format.csv do
          send_data generate_csv(records),
            filename: "banned-ips-#{Date.current}.csv",
            type: "text/csv"
        end
        format.json do
          render json: records.map { |ban|
            ban.attributes.slice("id", "ip_address", "reason", "details",
              "permanent", "banned_at", "expires_at", "violation_count", "metadata", "created_at")
          }
        end
      end
    end

    private

    def ban_reason_options
      options = [["Rate Limit Abuse", "rate_limit_abuse"], ["Authentication Abuse", "authentication_abuse"],
        ["WAF Violation", "waf_violation"], ["Brute Force Attack", "brute_force_attack"],
        ["Suspicious Activity", "suspicious_activity"], ["Manual Ban", "manual_ban"], ["Other", "other"]]
      reason = @suggested_reason || @banned_ip.reason
      options << [reason, reason] if reason.present? && options.none? { |_, value| value == reason }
      options
    end
    helper_method :ban_reason_options

    def prepare_administration
      begin
        callback = Beskar.configuration.audit_actor
        actor = instance_exec(request, &callback) if callback
        raise ActorUnavailable unless Services::AdministrativeBans.valid_actor?(actor)
      rescue => error
        Beskar::Logger.warn("Administrative actor unavailable (#{error.class})")
        raise ActorUnavailable, "Administrative identity unavailable"
      end
      @administration = Services::AdministrativeBans.new(actor: actor, reason: params[:audit_reason], request_id: request.request_id)
    end

    def administration_unavailable(error)
      return head :not_found if error.is_a?(ActiveRecord::RecordNotFound)
      Beskar::Logger.warn("Administrative operation unavailable (#{error.class})")
      render plain: "Administrative changes are unavailable. Reload state before retrying.", status: :service_unavailable
    end

    def render_invalid_ban(error, template)
      return administration_unavailable(error) unless error.record.is_a?(BannedIp)
      @banned_ip = error.record
      render template, status: :unprocessable_content
    end

    def set_banned_ip
      @banned_ip = Beskar::BannedIp.find(params[:id])
    end

    def banned_ip_params
      input = params.require(:banned_ip)
      if input.key?(:expires_at) && !input[:expires_at].nil? && !input[:expires_at].is_a?(String)
        raise Services::BanExpiry::InvalidInput, "Expiry must be a date and time string"
      end
      input.permit(
        :ip_address, :reason, :details, :permanent,
        :expires_at, :violation_count, metadata: {}
      )
    end

    def create_params
      banned_ip_params.to_h.merge(
        ban_type: params[:ban_type],
        duration: params[:duration]
      ).symbolize_keys
    end

    def apply_filters!
      # Filter by status
      case params[:status]
      when "active"
        @banned_ips = @banned_ips.active
      when "expired"
        @banned_ips = @banned_ips.expired
      when "permanent"
        @banned_ips = @banned_ips.permanent
      when "temporary"
        @banned_ips = @banned_ips.temporary
      end

      # Filter by reason
      if params[:reason].present?
        @banned_ips = @banned_ips.by_reason(params[:reason])
      end

      # Filter by IP address (partial match)
      if params[:ip_search].present?
        @banned_ips = @banned_ips.where("ip_address LIKE ?", "%#{params[:ip_search]}%")
      end

      # Filter by date range
      if params[:banned_after].present?
        begin
          date = Date.parse(params[:banned_after])
          @banned_ips = @banned_ips.where("banned_at >= ?", date.beginning_of_day)
        rescue ArgumentError
          # Invalid date, ignore
        end
      end

      if params[:banned_before].present?
        begin
          date = Date.parse(params[:banned_before])
          @banned_ips = @banned_ips.where("banned_at <= ?", date.end_of_day)
        rescue ArgumentError
          # Invalid date, ignore
        end
      end
    end

    def generate_csv(banned_ips)
      require "csv"

      CSV.generate(headers: true, force_quotes: true) do |csv|
        csv << ["IP Address", "Reason", "Banned At", "Expires At", "Status", "Violation Count", "Details"]

        banned_ips.each do |ban|
          csv << [
            ban.ip_address,
            ban.reason,
            ban.banned_at.strftime("%Y-%m-%d %H:%M:%S"),
            ban.expires_at&.strftime("%Y-%m-%d %H:%M:%S") || (ban.permanent? ? "Never (Permanent)" : "-"),
            ban.active? ? "Active" : "Expired",
            ban.violation_count,
            ban.details || "-"
          ].map { |value| Services::AuditData.csv_cell(value) }
        end
      end
    end
  end
end
