require "active_support/parameter_filter"

module Beskar
  module Services
    # Defense at capture and export boundaries, including legacy records. This
    # cannot identify arbitrary secrets embedded in otherwise legitimate prose.
    module AuditData
      FILTERED = "[FILTERED]"
      MAX_DEPTH = 10
      MAX_NODES = 512
      MAX_BYTES = 65_536
      SENSITIVE_KEYS = /password|secret|token|authorization|cookie|session_id|csrf|exception_message|fullpath|matched_path/i

      module_function

      def metadata(value)
        bounded = bound(value.is_a?(Hash) ? value : {}, depth: 0, budget: [MAX_NODES])
        filters = [SENSITIVE_KEYS] + Array(Rails.application.config.filter_parameters)
        filtered = ActiveSupport::ParameterFilter.new(filters).filter(bounded)
        filtered = bound(filtered, depth: 0, budget: [MAX_NODES])
        (filtered.to_json.bytesize <= MAX_BYTES) ? filtered : {"_truncated" => true}
      end

      def text(value, limit: 2048)
        RequestContext.text(value, limit: limit)
      end

      def field(name, value, limit: 2048)
        metadata(name.to_s => text(value, limit: limit))[name.to_s]
      end

      def user_email(user)
        return unless user
        if user.try(:email).present?
          field(:email, user.email, limit: 320)
        elsif user.try(:email_address).present?
          field(:email, field(:email_address, user.email_address, limit: 320), limit: 320)
        end
      end

      def bound(value, depth:, budget:)
        return "[TRUNCATED]" if depth > MAX_DEPTH || (budget[0] -= 1) < 0
        case value
        when Hash
          value.first(64).each_with_object({}) do |(key, child), result|
            next unless key.is_a?(String) || key.is_a?(Symbol)
            key = key.to_s
            next if key.bytesize > 128
            result[key] = bound(child, depth: depth + 1, budget: budget)
          end
        when Array then value.first(50).map { |child| bound(child, depth: depth + 1, budget: budget) }
        when String, Symbol then text(value)
        when Float then value.finite? ? value : nil
        when Integer, TrueClass, FalseClass, NilClass then value
        when Time, DateTime, Date then value.iso8601
        else "[UNSUPPORTED]"
        end
      end

      # CSV quoting handles delimiters, but does not neutralize spreadsheet
      # formulas. Prefix dangerous textual cells, including obscured/fullwidth
      # prefixes. JSON exports preserve text without this spreadsheet marker.
      def csv_cell(value)
        return value if value.is_a?(Numeric) || value.nil?
        string = text(value)
        probe = string.unicode_normalize(:nfkc)
        dangerous = probe.match?(/\A[\p{Space}\p{Cf}\p{Cc}]*[=+\-@]/)
        dangerous ? "text: #{string}" : string
      end
    end
  end
end
