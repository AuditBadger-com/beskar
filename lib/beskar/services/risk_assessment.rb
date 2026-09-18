module Beskar
  module Services
    # A single snapshot supplies both the numeric decision and its audit evidence.
    # IP repetition and lock/unlock records are not verified device/recovery trust.
    class RiskAssessment
      HISTORY_LIMIT = 20
      attr_reader :score, :metadata

      def self.observations(user, at: Time.current, mode: "enforce")
        return [] unless user
        user.security_events.where(event_type: "login_success", created_at: (at - 4.hours)...at)
          .order(created_at: :desc, id: :desc).limit(HISTORY_LIMIT).pluck(:id, :created_at, :metadata)
          .filter_map do |id, created_at, metadata|
            next unless metadata.is_a?(Hash)
            admission = metadata["authentication"]
            next unless admission.is_a?(Hash) && admission["allowed"] == true && admission["locked_now"] != true
            next unless usable_history?(metadata, mode)
            {event_id: id, occurred_at: created_at, location: metadata["geolocation"]}
          end
      end

      def self.usable_history?(metadata, mode)
        return false unless metadata.is_a?(Hash)
        assessment = metadata["risk_assessment"]
        return false if assessment && !assessment.is_a?(Hash)
        mode != "enforce" || assessment&.fetch("mode", nil) != "observe"
      end

      def initialize(request, user: nil, result: :success, at: Time.current)
        ip = RequestContext.ip(request)
        mode = RequestContext.enforce?(ip) ? "enforce" : "observe"
        device = DeviceDetector.new.assess(request.user_agent)
        geography = GeolocationService.new.assess_location(ip, observations: self.class.observations(user, at: at, mode: mode), at: at)
        factors = [{name: (result == :success) ? "credential_success" : "credential_failure", points: (result == :success) ? 1 : 10, evidence: {}}]
        factors.concat(device[:factors]).concat(geography[:factors])
        if device[:device_info][:mobile] && (at.hour >= 22 || at.hour < 6)
          factors << {name: "mobile_late_hours", points: 5, evidence: {hour: at.hour, timezone: at.zone}}
        end
        failures = if user
          user.security_events.where(event_type: "login_failure", created_at: (at - 10.minutes)..at)
            .order(created_at: :desc, id: :desc).limit(HISTORY_LIMIT).pluck(:metadata)
            .count { |metadata| self.class.usable_history?(metadata, mode) }
        else
          0
        end
        factors << {name: "recent_failures", points: 20, evidence: {at_least: 2, window_seconds: 600}} if failures >= 2
        total = factors.sum { |factor| factor[:points] }
        factors << {name: "total_cap", points: 100 - total, evidence: {cap: 100}} if total > 100
        @score = [total, 100].min
        @metadata = {
          device_info: device[:device_info], geolocation: geography[:location],
          risk_assessment: {version: 1, assessed_at: at.iso8601(6), mode: mode, score: score,
                            factors: factors, trust_discount: 0, history_limit: HISTORY_LIMIT}
        }
      end
    end
  end
end
