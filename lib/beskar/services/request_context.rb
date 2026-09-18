require "ipaddr"
require "uri"

module Beskar
  module Services
    module RequestContext
      module_function

      def ip(request)
        value = if request.respond_to?(:remote_ip)
          request.remote_ip
        elsif request.respond_to?(:env) && request.env && request.env["action_dispatch.remote_ip"]
          request.env["action_dispatch.remote_ip"]
        else
          request.ip
        end
        IPAddr.new(value.to_s).to_s
      end

      def text(value, limit: 500)
        value&.to_s&.encode("UTF-8", invalid: :replace, undef: :replace)&.gsub(/[[:cntrl:]]/, " ")&.truncate(limit)
      end

      # Query strings and referrer queries may carry secrets even when their keys
      # are unknown to the host application's parameter filter.
      def path(request)
        text(request.path, limit: 2048)
      end

      def security_metadata(request, enrich: true)
        metadata = {
          timestamp: Time.current.iso8601,
          request_id: request.respond_to?(:request_id) ? request.request_id : nil,
          request_path: path(request),
          referer: safe_referer(request.referer)
        }
        if enrich
          metadata[:device_info] = DeviceDetector.detect(text(request.user_agent))
          metadata[:geolocation] = GeolocationService.locate(ip(request))
        end
        metadata
      end

      def safe_referer(value)
        return if value.blank?
        uri = URI.parse(text(value, limit: 2048))
        return unless uri.is_a?(URI::HTTP)
        uri.query = uri.fragment = nil
        uri.user = uri.password = nil
        uri.to_s
      rescue URI::Error
        nil
      end

      def secure_match?(supplied, expected)
        supplied.present? && expected.present? && ActiveSupport::SecurityUtils.secure_compare(supplied.to_s, expected.to_s)
      end

      def enforce?(ip_address = nil)
        !Beskar.configuration.monitor_only? && !IpWhitelist.whitelisted?(ip_address)
      end
    end
  end
end
