require "ipaddr"

module Beskar
  class BannedIp < ApplicationRecord
    serialize :metadata, coder: JSON

    validates :ip_address, presence: true, uniqueness: true
    validates :reason, :banned_at, presence: true
    validates :expires_at, presence: true, unless: :permanent?
    validates :violation_count, numericality: {only_integer: true, greater_than: 0}
    validate :valid_ip_address

    after_initialize { self.metadata ||= {} if has_attribute?(:metadata) }
    before_validation :normalize_attributes
    before_validation :sanitize_audit_fields
    after_find :sanitize_audit_fields
    after_commit :clear_legacy_cache

    # Permanent is authoritative even for legacy rows with an expired timestamp.
    scope :active, -> { where("permanent = ? OR expires_at > ?", true, Time.current) }
    scope :permanent, -> { where(permanent: true) }
    scope :temporary, -> { where(permanent: false) }
    scope :expired, -> { temporary.where("expires_at <= ?", Time.current) }
    scope :by_reason, ->(reason) { where(reason: reason) }

    def active?
      permanent? || (expires_at.present? && expires_at > Time.current)
    end

    def sanitize_audit_fields
      self.reason = Services::AuditData.field(:reason, reason, limit: 100) if has_attribute?(:reason)
      self.details = Services::AuditData.field(:details, details) if has_attribute?(:details)
      self.metadata = Services::AuditData.metadata(metadata) if has_attribute?(:metadata)
    end
    private :sanitize_audit_fields

    def expired?
      !permanent? && expires_at.present? && expires_at <= Time.current
    end

    def extend_ban!(additional_time = nil)
      validate_duration!(additional_time)
      SecurityState.mutate("ban:#{ip_address}", ttl: 1.day) do
        reload
        apply_extension(additional_time)
        save!
      end
    end

    def unban!
      destroy!
    end

    class << self
      def ban!(ip_address, reason:, duration: nil, permanent: false, details: nil, metadata: {})
        raise ArgumentError, "Ban duration must be positive" if duration && !duration.to_f.positive?
        raise ArgumentError, "Ban requires a single IP address" if ip_address.to_s.include?("/")
        ip_address = IPAddr.new(ip_address.to_s).to_s

        SecurityState.mutate("ban:#{ip_address}", ttl: 1.day) do
          banned_ip = find_or_initialize_by(ip_address: ip_address)
          if banned_ip.persisted?
            banned_ip.permanent = true if permanent
            banned_ip.send(:apply_extension, duration)
            banned_ip.reason = reason
            banned_ip.details = details if details
            banned_ip.metadata = banned_ip.metadata.deep_stringify_keys.merge(metadata.deep_stringify_keys)
          else
            banned_ip.assign_attributes(
              reason: reason, banned_at: Time.current, permanent: permanent,
              expires_at: permanent ? nil : Time.current + (duration || 1.hour),
              details: details, metadata: metadata
            )
          end
          banned_ip.save!
          banned_ip
        end
      end

      # Cache eviction, rollback, stale values, or process-local caches cannot
      # change enforcement. All workers consult the same indexed database.
      def banned?(ip_address)
        return false if ip_address.to_s.include?("/")
        active.exists?(ip_address: IPAddr.new(ip_address.to_s).to_s)
      rescue IPAddr::InvalidAddressError
        false
      end

      def unban!(ip_address)
        banned_ip = find_by(ip_address: IPAddr.new(ip_address.to_s).to_s)
        return false unless banned_ip
        banned_ip.destroy!
        true
      end

      # Kept for compatibility; no enforcement state lives in Rails.cache.
      def preload_cache!
      end

      def cleanup_expired!
        expired.find_each do |ban|
          ban.with_lock { ban.destroy! if ban.expired? }
        end
      end
    end

    private

    def apply_extension(additional_time)
      self.violation_count += 1
      if permanent?
        self.expires_at = nil
      elsif additional_time
        self.expires_at = [expires_at || Time.current, Time.current].max + additional_time
      elsif violation_count >= 5
        self.permanent = true
        self.expires_at = nil
      else
        self.expires_at = Time.current + [1.hour, 6.hours, 24.hours, 7.days].fetch(violation_count - 1)
      end
    end

    def validate_duration!(duration)
      raise ArgumentError, "Ban duration must be positive" if duration && !duration.to_f.positive?
    end

    def normalize_attributes
      self.expires_at = nil if permanent?
      self.ip_address = IPAddr.new(ip_address.to_s).to_s if ip_address.present? && !ip_address.include?("/")
    rescue IPAddr::InvalidAddressError
      # Validation reports malformed addresses without raising.
    end

    def valid_ip_address
      raise IPAddr::InvalidAddressError if ip_address.to_s.include?("/")
      IPAddr.new(ip_address.to_s)
    rescue IPAddr::InvalidAddressError
      errors.add(:ip_address, "must be a valid individual IP address")
    end

    def clear_legacy_cache
      [ip_address, previous_changes.dig("ip_address", 0)].compact.uniq.each do |ip|
        Rails.cache.delete("beskar:banned_ip:#{ip}")
      end
    rescue => error
      Beskar::Logger.warn("Legacy ban cache invalidation failed (#{error.class})", component: :BannedIp)
    end
  end
end
