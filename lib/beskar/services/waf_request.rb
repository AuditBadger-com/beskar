require "uri"

module Beskar
  module Services
    # Matching input only. Never copy these raw/canonical paths or query values
    # into audit records, state, or logs; those contain rule identifiers instead.
    class WafRequest
      MAX_BYTES = 8192
      attr_reader :path, :problem, :method, :decoding_passes

      def initialize(request)
        @request = request
        @method = request.respond_to?(:request_method) ? request.request_method.to_s.upcase : "GET"
        @method = "OTHER" unless %w[GET HEAD POST PUT PATCH DELETE OPTIONS CONNECT TRACE].include?(@method)
        raw = request.path.to_s
        @decoding_passes = 0
        if raw.bytesize > MAX_BYTES
          @path, @problem = "", :oversized_path
          return
        end
        @path = raw.b
        @problem = :invalid_encoding if @path.match?(/%(?![0-9a-f]{2})/i)
        2.times do
          break unless @path.match?(/%[0-9a-f]{2}/i)
          @path = @path.gsub(/%([0-9a-f]{2})/i) { [$1.to_i(16)].pack("C") }
          @decoding_passes += 1
        end
        @problem ||= :excessive_encoding if @path.match?(/%[0-9a-f]{2}/i)
        @path = @path.tr("\\", "/").force_encoding(Encoding::UTF_8)
        if !@path.valid_encoding? || @path.match?(/[[:cntrl:]]/)
          @problem = :invalid_encoding
          @path = ""
        end
      end

      def suspicious_format?
        return false unless @request.respond_to?(:query_string)
        query = @request.query_string.to_s
        return false if query.bytesize > MAX_BYTES
        URI.decode_www_form(query).any? do |key, value|
          key == "format" && value.match?(/\A(?:exe|bat|cmd|com|scr|vbs|jar|asp|aspx|jsp|php)\z/i)
        end
      rescue ArgumentError
        false
      end

      def excluded?(category)
        Array((Beskar.configuration.waf || {})[:request_exclusions]).any? do |rule|
          next false unless rule.is_a?(Hash)
          rule = rule.symbolize_keys
          next false unless rule[:path].is_a?(Regexp)
          methods = Array(rule[:methods]).map { |value| value.to_s.upcase }
          categories = Array(rule[:categories]).map(&:to_s)
          (methods.empty? || methods.include?(method)) &&
            (categories.empty? || categories.include?(category.to_s)) && rule[:path].match?(path)
        end
      end
    end
  end
end
