require "time"

module Beskar
  module Services
    # Observations pair a location with its own occurred_at and event_id. Never
    # apply one timestamp to a collection of unrelated historical locations.
    class LocationAssessment
      MAX_SPEED_KMH = 1000

      def self.normalize(location)
        location = location.is_a?(Hash) ? location.deep_symbolize_keys : {}
        lat, lon = number(location[:latitude]), number(location[:longitude])
        if lat && lon && lat.between?(-90, 90) && lon.between?(-180, 180)
          location.merge(latitude: lat, longitude: lon)
        else
          location.merge(latitude: nil, longitude: nil)
        end
      end

      def self.number(value)
        number = Float(value, exception: false)
        number if number&.finite?
      end

      def self.timestamp(value)
        value = Time.iso8601(value) if value.is_a?(String)
        value = value.to_time.to_f if value.respond_to?(:to_time)
        number(value)
      rescue ArgumentError
        nil
      end

      def self.coordinates(location)
        location = normalize(location)
        return if location[:private_ip] == true || %w[Private Unknown].include?(location[:country])
        return if location[:provider].to_s == "mock"
        lat, lon = number(location[:latitude]), number(location[:longitude])
        [lat, lon] if lat && lon && lat.between?(-90, 90) && lon.between?(-180, 180)
      end

      def initialize(location, observations: [], at: Time.current)
        @location = self.class.normalize(location)
        @at = self.class.timestamp(at)
        @observations = observations.filter_map do |observation|
          next unless observation.is_a?(Hash)
          observation = observation.symbolize_keys
          time = self.class.timestamp(observation[:occurred_at])
          next unless @at && time && time < @at
          {location: self.class.normalize(observation[:location]), occurred_at: time, event_id: observation[:event_id]}
        end.sort_by { |observation| [observation[:occurred_at], observation[:event_id].to_i] }.reverse
      end

      def call
        factors = []
        location = @location.merge(impossible_travel: false, country_change: false)
        status = if @location[:private_ip] == true || @location[:country] == "Private"
          "private"
        elsif @location[:provider].to_s == "mock"
          "synthetic"
        elsif self.class.coordinates(@location) || known_country?(@location)
          "available"
        else
          "unknown"
        end
        if %w[private unknown].include?(status)
          factors << {name: "location_unavailable", points: 10, evidence: {status: status}}
        elsif status == "available"
          previous = @observations.find { |entry| self.class.coordinates(entry[:location]) }
          if previous && (current_coordinates = self.class.coordinates(@location))
            elapsed = @at - previous[:occurred_at]
            distance = GeolocationService.calculate_distance(*current_coordinates, *self.class.coordinates(previous[:location]))
            evidence = {previous_event_id: previous[:event_id], previous_at: Time.at(previous[:occurred_at]).utc.iso8601(6),
                        elapsed_seconds: elapsed, distance_km: distance.round(3), max_speed_kmh: MAX_SPEED_KMH}
            location[:travel] = evidence
            if distance > MAX_SPEED_KMH * elapsed / 3600.0
              location[:impossible_travel] = true
              factors << {name: "impossible_travel", points: 25, evidence: evidence}
            end
          end
          previous_country = @observations.find { |entry| known_country?(entry[:location]) }
          if known_country?(@location) && previous_country && country_changed?(previous_country[:location])
            location[:country_change] = true
            factors << {name: "country_change", points: 10,
                        evidence: {previous_event_id: previous_country[:event_id], previous_country: previous_country[:location][:country],
                                   current_country: @location[:country]}}
          end
        end
        total = factors.sum { |factor| factor[:points] }
        factors << {name: "geolocation_cap", points: 30 - total, evidence: {cap: 30}} if total > 30
        {location: location.merge(assessment_status: status), score: [total, 30].min, factors: factors}
      end

      private

      def known_country?(location)
        location[:provider].to_s != "mock" && location[:private_ip] != true &&
          location[:country].present? && !%w[Unknown Private].include?(location[:country])
      end

      def country_changed?(previous)
        if previous[:country_code].present? && @location[:country_code].present?
          previous[:country_code].to_s.upcase != @location[:country_code].to_s.upcase
        else
          previous[:country].to_s.downcase != @location[:country].to_s.downcase
        end
      end
    end
  end
end
