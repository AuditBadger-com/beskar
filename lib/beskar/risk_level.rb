module Beskar
  # Reporting bands, not configurable authentication-lock thresholds.
  module RiskLevel
    RANGES = {low: 0...30, medium: 30...70, high: 70...90, critical: 90..100}.freeze
    BADGES = {low: "success", medium: "warning", high: "danger", critical: "critical"}.freeze
    COLORS = {low: "#4CAF50", medium: "#FF9800", high: "#E91E63", critical: "#D32F2F"}.freeze

    module_function

    def for(score)
      return unless score.is_a?(Numeric) && score.real? && score.finite?
      RANGES.find { |_, range| range.cover?(score) }&.first
    end

    def filter_options
      RANGES.map do |level, range|
        last = range.exclude_end? ? range.end - 1 : range.end
        ["#{level.to_s.capitalize} (#{range.begin}-#{last})", level.to_s]
      end
    end
  end
end
