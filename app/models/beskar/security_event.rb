module Beskar
  class SecurityEvent < ApplicationRecord
    # Transient correlation; the audit row is not enforcement authority.
    attr_accessor :beskar_attempt
    belongs_to :user, polymorphic: true, optional: true
    before_validation :sanitize_audit_fields
    after_find :sanitize_audit_fields

    validates :event_type, presence: true
    validates :ip_address, presence: true
    validates :risk_score, numericality: {in: 0..100}

    scope :login_failures, -> { where(event_type: "login_failure") }
    scope :login_successes, -> { where(event_type: "login_success") }
    scope :recent, ->(time = 1.hour.ago) { where("created_at >= ?", time) }
    scope :by_ip, ->(ip) { where(ip_address: ip) }
    scope :high_risk, -> { where(risk_score: RiskLevel::RANGES[:high].begin..100) }
    scope :critical_risk, -> { where(risk_score: RiskLevel::RANGES[:critical]) }
    scope :with_risk_level, ->(level) {
      range = RiskLevel::RANGES.find { |name, _| name.to_s == level.to_s }&.last
      range ? where(risk_score: range) : all
    }

    def readonly?
      persisted? || super
    end

    def delete
      raise ActiveRecord::ReadOnlyRecord, "Security events are append-only" if persisted?
      super
    end

    def risk_level
      RiskLevel.for(risk_score)
    end

    def critical_threat?
      risk_level == :critical
    end

    def high_risk?
      [:high, :critical].include?(risk_level)
    end

    def login_failure?
      event_type == "login_failure"
    end

    def login_success?
      event_type == "login_success"
    end

    def attempted_email
      read_attribute(:attempted_email) || metadata&.dig("attempted_email")
    end

    def attempted_email=(value)
      write_attribute(:attempted_email, value)
      # Also store in metadata for backwards compatibility
      self.metadata = (metadata || {}).merge("attempted_email" => value) if value.present?
    end

    def device_info
      metadata&.dig("device_info") || {}
    end

    def geolocation
      metadata&.dig("geolocation") || {}
    end

    def details
      # Extract details from metadata if available
      # Check multiple possible fields where details might be stored
      return nil unless metadata.present?

      metadata["details"] ||
        metadata["description"] ||
        metadata["message"] ||
        metadata["reason"] ||
        metadata["error"] ||
        metadata["info"] ||
        nil
    end

    private

    def sanitize_audit_fields
      self.metadata = Services::AuditData.metadata(metadata) if has_attribute?(:metadata)
      {event_type: 100, ip_address: 64, user_agent: 500, attempted_email: 320}.each do |field, limit|
        self[field] = Services::AuditData.field(field, self[field], limit: limit) if has_attribute?(field)
      end
    end
  end
end
