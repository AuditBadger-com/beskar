module Beskar
  module Controllers
    module AuditExport
      extend ActiveSupport::Concern

      LIMIT = 1000

      included do
        rescue_from Services::AdministrativeAudit::Unavailable, ActiveRecord::ActiveRecordError do |error|
          raise error unless action_name == "export"
          Beskar::Logger.warn("Audit export unavailable (#{error.class})")
          render plain: "Audit export unavailable", status: :service_unavailable
        end
        rescue_from Services::AdministrativeBans::InvalidInput do |error|
          render plain: error.message, status: :unprocessable_content
        end
      end

      private

      def export_records(relation)
        response.set_header("Cache-Control", "private, no-store")
        response.set_header("X-Content-Type-Options", "nosniff")
        unless request.format.csv? || request.format.json?
          head :not_acceptable
          return
        end
        cursor = params[:before_id]
        if cursor.present?
          unless cursor.is_a?(String) && cursor.match?(/\A[1-9]\d{0,18}\z/) && cursor.to_i <= 9_223_372_036_854_775_807
            render json: {error: "before_id must be a positive record ID"}, status: :unprocessable_content
            return
          end
          relation = relation.where(id: ...cursor.to_i)
        end
        records = relation.reorder(id: :desc).limit(LIMIT + 1).to_a
        truncated = records.length > LIMIT
        records = records.first(LIMIT)
        # Persist before disclosing any body. This records an authorized export
        # preparation, not proof the client finished receiving the response.
        Services::AdministrativeAudit.record!(actor: administrative_actor!,
          reason: request.headers["X-Beskar-Audit-Reason"] || params[:audit_reason], request_id: request.request_id,
          action: "audit_exported", target_type: relation.klass.name.demodulize,
          after_state: {format: request.format.to_s, count: records.length, highest_id: records.first&.id,
                        lowest_id: records.last&.id, before_id: cursor, truncated: truncated,
                        filters: request.query_parameters.except("audit_reason", "controller", "action", "format")})
        response.set_header("X-Beskar-Export-Limit", LIMIT.to_s)
        response.set_header("X-Beskar-Export-Truncated", truncated.to_s)
        response.set_header("X-Beskar-Next-Cursor", records.last.id.to_s) if truncated
        records
      end
    end
  end
end
