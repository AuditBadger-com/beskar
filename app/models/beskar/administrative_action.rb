module Beskar
  class AdministrativeAction < ApplicationRecord
    attribute :before_state, default: -> { {} }
    attribute :after_state, default: -> { {} }

    ACTIONS = %w[ban_created ban_updated ban_unbanned ban_extended ban_made_permanent audit_exported configuration_changed].freeze
    before_validation :sanitize_audit_fields
    after_find :sanitize_audit_fields

    validates :actor, :operation_id, :request_id, :reason, presence: true
    validates :actor, :request_id, length: {maximum: 200}
    validates :reason, length: {maximum: 1000}
    validates :action, inclusion: {in: ACTIONS}
    validates :target_type, inclusion: {in: %w[BannedIp SecurityEvent Configuration]}
    validates :target_id, numericality: {only_integer: true, greater_than: 0}, allow_nil: true
    validates :target_id, presence: true, if: -> { action&.start_with?("ban_") }

    # Reject ordinary instance saves/updates and destruction. Low-level counter,
    # bulk and SQL APIs can bypass this; this is not tamper-proof storage.
    def readonly?
      persisted? || super
    end

    # Active Record deliberately bypasses readonly? in its instance delete API.
    def delete
      raise ActiveRecord::ReadOnlyRecord, "Administrative history is append-only" if persisted?
      super
    end

    private

    def sanitize_audit_fields
      {actor: 200, request_id: 200, reason: 1000}.each do |field, limit|
        self[field] = Services::AuditData.field(field, self[field], limit: limit) if has_attribute?(field)
      end
      %i[before_state after_state].each do |field|
        self[field] = Services::AuditData.metadata(self[field]) if has_attribute?(field)
      end
    end
  end
end
