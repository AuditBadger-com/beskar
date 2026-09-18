require "time"
require "date"

module Beskar
  module Services
    # datetime-local has no timezone. Dashboard wall-clock input is explicitly
    # UTC; scripted callers may instead supply an ISO 8601 numeric offset.
    module BanExpiry
      class InvalidInput < ArgumentError; end
      FORMAT = /\A(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d{1,6})?)?(Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)?\z/

      def self.parse(value)
        return nil if value.nil? || value == ""
        match = FORMAT.match(value) if value.is_a?(String) && value.bytesize <= 40
        unless match && match[1].to_i.positive? && Date.valid_date?(*match.captures.first(3).map(&:to_i)) &&
            match[4].to_i < 24 && match[5].to_i < 60 && match[6].to_i < 60
          raise InvalidInput, "Expiry must be a valid UTC date and time or ISO 8601 timestamp with offset"
        end
        # Browsers omit seconds when zero; Ruby's ISO parser requires them.
        timestamp = value.sub(/T(\d{2}):(\d{2})(?=Z|[+-]|\z)/, 'T\1:\2:00')
        Time.iso8601(match[7] ? timestamp : "#{timestamp}Z").utc
      rescue ArgumentError => error
        raise error if error.is_a?(InvalidInput)
        raise InvalidInput, "Expiry must be a valid UTC date and time or ISO 8601 timestamp with offset"
      end
    end
  end
end
