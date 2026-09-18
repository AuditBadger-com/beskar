module Beskar
  # Persistent coordination; deliberately independent of Rails.cache capabilities.
  class SecurityState < ApplicationRecord
    class ConcurrentCleanup < StandardError; end

    # Preserve defaults on unsaved records as well as database-created rows.
    attribute :data, default: -> { {} }

    validates :key, presence: true

    def self.read(key)
      row = find_by(key: key)
      return {} if row.nil? || (row.expires_at && row.expires_at <= Time.current)
      row.data.deep_dup
    end

    def self.mutate(keys, ttl:)
      keys = Array(keys).uniq.sort
      retries = 0
      begin
        mutate_once(keys, ttl: ttl) { |state| yield state }
      rescue ActiveRecord::StaleObjectError, ActiveRecord::Deadlocked, ActiveRecord::SerializationFailure, ActiveRecord::RecordNotUnique, ConcurrentCleanup
        raise if (retries += 1) > 10
        sleep(0.005 * retries)
        retry
      rescue ActiveRecord::StatementInvalid => error
        # SQLite uses database-level write locking rather than SELECT FOR UPDATE.
        raise unless error.cause&.class&.name == "SQLite3::BusyException"
        raise if (retries += 1) > 10
        sleep(0.005 * retries)
        retry
      end
    end

    # The block may be retried after a concurrency conflict. Keep its effects in
    # this database transaction; do not send notifications or write to caches.
    def self.mutate_once(keys, ttl:)
      transaction(requires_new: true) do
        keys.each { |key| find_by(key: key) || create_or_find_by!(key: key) }
        rows = where(key: keys).order(:key).lock.to_a
        raise ConcurrentCleanup unless rows.size == keys.size
        state = rows.to_h do |row|
          [row.key, (row.expires_at && row.expires_at <= Time.current) ? {} : row.data.deep_dup]
        end
        result = yield state
        rows.each do |row|
          row.update!(data: state.fetch(row.key), expires_at: ttl && Time.current + ttl)
        end
        result
      end
    end
    private_class_method :mutate_once

    def self.cleanup_expired!
      where("expires_at <= ?", Time.current).in_batches.delete_all
    end
  end
end
