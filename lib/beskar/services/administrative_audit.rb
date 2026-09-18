module Beskar
  module Services
    class AdministrativeAudit
      class Unavailable < StandardError; end

      def self.record!(actor:, reason:, request_id:, action:, target_type:, before_state: {}, after_state: {})
        raise AdministrativeBans::InvalidInput, "Administrative actor must be an opaque identifier" unless AdministrativeBans.valid_actor?(actor)
        unless reason.is_a?(String) && reason.strip.present? && reason.length <= 1000
          raise AdministrativeBans::InvalidInput, "An administrative reason of 1 to 1000 characters is required"
        end
        AdministrativeAction.create!(actor: actor, reason: reason.strip, request_id: request_id,
          operation_id: SecureRandom.uuid, action: action, target_type: target_type,
          before_state: before_state, after_state: after_state)
      end

      def self.configuration_snapshot(config)
        values = (Configuration::SECTIONS + [:monitor_only, :ip_whitelist]).to_h { |name| [name, config.public_send(name)] }
        %i[authenticate_admin audit_actor authorize_admin authorize_configuration].each do |name|
          values[name] = config.public_send(name).present? ? "[CALLBACK]" : nil
        end
        AuditData.metadata(configuration_value(values))
      end

      def self.configuration_value(value)
        case value
        when Hash then value.transform_values { |item| configuration_value(item) }
        when Array then value.map { |item| configuration_value(item) }
        when ActiveSupport::Duration then value.to_f
        when Regexp then {pattern: value.source, options: value.options}
        when Class then value.name
        else value
        end
      end
    end
  end
end
