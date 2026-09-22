require "uri"

module Beskar
  module Services
    # Canonical paths are for matching only. Audit paths preserve the requested
    # encoding, are bounded and filtered, and exclude queries and fragments.
    class WafRequest
      MAX_BYTES = 8192
      attr_reader :path, :problem, :method, :decoding_passes

      def self.audit_path(value)
        return unless value.is_a?(String)
        path = value.byteslice(0, 4096).b.split(/[?#]/, 2).first.to_s.force_encoding(Encoding::UTF_8)
        AuditData.field(:request_path, path, limit: 1024)
      end

      def audit_path
        self.class.audit_path(@request.path)
      end

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
