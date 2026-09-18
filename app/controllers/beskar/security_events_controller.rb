require "csv"

module Beskar
  class SecurityEventsController < ApplicationController
    include Controllers::AuditExport

    def index
      @events = Beskar::SecurityEvent.preload(:user).order(created_at: :desc, id: :desc)

      # Apply filters
      apply_filters!

      # Paginate results
      @pagination = paginate(@events, per_page: params[:per_page]&.to_i || 25)
      @events = @pagination[:records]

      # Get filter options for dropdowns
      @event_types = Beskar::SecurityEvent.distinct.pluck(:event_type).sort
      @risk_levels = RiskLevel.filter_options
    end

    def show
      @event = Beskar::SecurityEvent.find(params[:id])

      # Find related events
      @related_events = Beskar::SecurityEvent
        .preload(:user)
        .where.not(id: @event.id)
        .where(ip_address: @event.ip_address)
        .order(created_at: :desc, id: :desc)
        .limit(10)

      # Get user's recent events if user exists
      if @event.user.present?
        @user_events = @event.user.security_events
          .where.not(id: @event.id)
          .order(created_at: :desc)
          .limit(10)
      end

      # Check if IP is banned
      @ip_ban = Beskar::BannedIp.find_by(ip_address: @event.ip_address)
    end

    def export
      @events = Beskar::SecurityEvent.preload(:user)

      # Apply same filters as index
      apply_filters!
      records = export_records(@events)
      return if performed?

      respond_to do |format|
        format.csv do
          send_data generate_csv(records),
            filename: "security-events-#{Date.current}.csv",
            type: "text/csv"
        end
        format.json do
          render json: records.map { |event| export_event(event) }
        end
      end
    end

    private

    def export_event(event)
      attributes = event.attributes.slice("id", "event_type", "ip_address", "user_id", "user_type",
        "user_agent", "attempted_email", "risk_score", "metadata", "created_at")
      if event.user
        attributes["user"] = {id: event.user.id, email: Services::AuditData.user_email(event.user)}
      end
      attributes
    end

    def apply_filters!
      # Filter by event type
      if params[:event_type].present?
        @events = @events.where(event_type: params[:event_type])
      end

      # Filter by risk level
      if params[:risk_level].present?
        @events = @events.with_risk_level(params[:risk_level])
      end

      # Filter by IP address
      if params[:ip_address].present?
        @events = @events.where("ip_address LIKE ?", "%#{params[:ip_address]}%")
      end

      # Filter by user email (if attempted_email is stored)
      if params[:email].present?
        @events = Services::EventSearch.new(@events).email(params[:email])
      end

      # Filter by date range
      if params[:start_date].present?
        begin
          start_date = Date.parse(params[:start_date])
          @events = @events.where("created_at >= ?", start_date.beginning_of_day)
        rescue ArgumentError
          # Invalid date, ignore filter
        end
      end

      if params[:end_date].present?
        begin
          end_date = Date.parse(params[:end_date])
          @events = @events.where("created_at <= ?", end_date.end_of_day)
        rescue ArgumentError
          # Invalid date, ignore filter
        end
      end

      # Quick time range filters
      if params[:time_range].present?
        start_time = case params[:time_range]
        when "last_hour"
          1.hour.ago
        when "last_24h"
          24.hours.ago
        when "last_7d"
          7.days.ago
        when "last_30d"
          30.days.ago
        end

        @events = @events.where("created_at >= ?", start_time) if start_time
      end

      # Filter by threat level
      if params[:threats_only] == "true"
        @events = @events.high_risk
      end

      # Search in metadata
      if params[:search].present?
        @events = Services::EventSearch.new(@events).search(params[:search])
      end
    end

    def generate_csv(events)
      require "csv"

      CSV.generate(headers: true, force_quotes: true) do |csv|
        csv << ["ID", "Date/Time", "Event Type", "IP Address", "User", "Risk Score", "User Agent", "Details"]

        events.each do |event|
          csv << [
            event.id,
            event.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            event.event_type,
            event.ip_address,
            audit_user_label(event),
            event.risk_score,
            event.user_agent,
            event.details || event.metadata&.dig("message") || "-"
          ].map { |value| Services::AuditData.csv_cell(value) }
        end
      end
    end
  end
end
