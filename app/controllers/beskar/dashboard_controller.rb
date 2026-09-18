module Beskar
  class DashboardController < ApplicationController
    def index
      # Time ranges for statistics
      @time_range = params[:time_range] || "24h"
      @start_time = calculate_start_time(@time_range)

      # Overview statistics
      events = Beskar::SecurityEvent.where(created_at: @start_time..Time.current)
      @event_distribution = events.group(:event_type).count.sort_by { |_, count| -count }
      score_counts = events.group(:risk_score).count
      @risk_distribution = RiskLevel::RANGES.keys.to_h { |level| [level, 0] }
      score_counts.each do |score, count|
        level = RiskLevel.for(score)
        @risk_distribution[level] += count if level
      end
      @stats = {
        total_events: @event_distribution.sum(&:last),
        failed_logins: @event_distribution.to_h.fetch("login_failure", 0),
        blocked_ips: Beskar::BannedIp.active.count,
        high_risk_events: @risk_distribution[:high] + @risk_distribution[:critical],
        critical_threats: @risk_distribution[:critical]
      }

      # Recent activity
      @recent_events = Beskar::SecurityEvent
        .includes(:user)
        .order(created_at: :desc, id: :desc)
        .limit(10)

      # Top threat IPs
      @top_threat_ips = events
        .group(:ip_address)
        .select("ip_address, COUNT(*) as event_count, AVG(risk_score) as avg_risk_score, MAX(risk_score) as max_risk_score")
        .having("COUNT(*) > 1")
        .order("event_count DESC, avg_risk_score DESC")
        .limit(5)

      # Currently active bans
      @active_bans = Beskar::BannedIp.active.order(banned_at: :desc).limit(5)
    end

    private

    def calculate_start_time(range)
      case range
      when "1h"
        1.hour.ago
      when "6h"
        6.hours.ago
      when "24h"
        24.hours.ago
      when "7d"
        7.days.ago
      when "30d"
        30.days.ago
      else
        24.hours.ago
      end
    end
  end
end
