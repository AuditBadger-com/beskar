module Beskar
  module Services
    # All selected changes and their required history share one writer transaction.
    # The existing ban coordination keys also serialize with automatic escalation.
    class AdministrativeBans
      class InvalidInput < ArgumentError; end
      MAX_BATCH = 100
      DURATIONS = {"1h" => 1.hour, "6h" => 6.hours, "24h" => 24.hours,
                   "7d" => 7.days, "30d" => 30.days}.freeze
      SNAPSHOT_FIELDS = %w[id ip_address reason details permanent banned_at expires_at violation_count metadata].freeze
      ACTION_NAMES = {"update" => "ban_updated", "unban" => "ban_unbanned", "extend" => "ban_extended", "make_permanent" => "ban_made_permanent"}.freeze
      UPDATE_FIELDS = %w[ip_address reason details permanent expires_at violation_count metadata].freeze

      def self.valid_actor?(actor)
        actor.is_a?(String) && actor.match?(/\A[a-zA-Z0-9][a-zA-Z0-9:_.\/-]{0,199}\z/)
      end

      def initialize(actor:, reason:, request_id:)
        unless self.class.valid_actor?(actor)
          raise InvalidInput, "Administrative actor must be an opaque identifier"
        end
        unless reason.is_a?(String) && reason.strip.present? && reason.length <= 1000
          raise InvalidInput, "An administrative reason of 1 to 1000 characters is required"
        end
        @context = {actor: actor, reason: reason.strip, request_id: AuditData.field(:request_id, request_id, limit: 200),
                    operation_id: SecureRandom.uuid}
      end

      def create!(ban)
        raise InvalidInput, "Create requires a new ban" unless ban.new_record?
        raise ActiveRecord::RecordInvalid, ban unless ban.valid?
        SecurityState.mutate("ban:#{ban.ip_address}", ttl: 1.day) do
          ban.save!
          record!(ban, "ban_created", {})
        end
        ban
      end

      def change!(ids, action:, attributes: {}, duration: nil)
        unless %w[update unban extend make_permanent].include?(action)
          raise InvalidInput, "Unknown administrative action"
        end
        unless attributes.is_a?(Hash) && (attributes.keys.map(&:to_s) - UPDATE_FIELDS).empty?
          raise InvalidInput, "Unsupported ban attributes"
        end
        extension = DURATIONS[duration] if action == "extend"
        raise InvalidInput, "Unsupported extension duration" if action == "extend" && !extension
        ids = normalize_ids(ids)
        targets = BannedIp.where(id: ids).order(:id).pluck(:id, :ip_address)
        raise ActiveRecord::RecordNotFound unless targets.size == ids.size

        changed = 0
        SecurityState.mutate(targets.map { |_, ip| "ban:#{ip}" }, ttl: 1.day) do
          changed = 0 # The block can be retried after an optimistic conflict.
          bans = BannedIp.where(id: ids).order(:id).lock.to_a
          raise ActiveRecord::RecordNotFound unless bans.size == ids.size
          raise InvalidInput, "Ban identity changed; reload before retrying" unless bans.map { |ban| [ban.id, ban.ip_address] } == targets
          bans.each do |ban|
            before = snapshot(ban)
            case action
            when "unban" then ban.destroy!
            when "make_permanent" then ban.update!(permanent: true, expires_at: nil)
            when "extend"
              raise InvalidInput, "Cannot extend a permanent ban" if ban.permanent?
              ban.update!(expires_at: [ban.expires_at || Time.current, Time.current].max + extension)
            when "update"
              ban.assign_attributes(attributes)
              if ban.ip_address_changed?
                ban.errors.add(:ip_address, "cannot be changed")
                raise ActiveRecord::RecordInvalid, ban
              end
              ban.save!
            end
            after = ban.destroyed? ? {} : snapshot(ban)
            # Filtered/bounded snapshots can look identical even when stored
            # fields changed (for example subsecond deadlines or redacted data).
            next unless ban.destroyed? || ban.saved_changes.except("updated_at").present?
            record!(ban, ACTION_NAMES.fetch(action), before, after)
            changed += 1
          end
        end
        changed
      end

      private

      def normalize_ids(ids)
        values = Array(ids)
        unless values.size.between?(1, MAX_BATCH) && values.all? { |id| id.to_s.match?(/\A[1-9]\d{0,18}\z/) && id.to_s.to_i <= 9_223_372_036_854_775_807 }
          raise InvalidInput, "Select 1 to 100 valid ban IDs"
        end
        values.map(&:to_i).uniq.sort
      end

      def snapshot(ban)
        AuditData.metadata(ban.attributes.slice(*SNAPSHOT_FIELDS))
      end

      def record!(ban, action, before, after = snapshot(ban))
        AdministrativeAction.create!(@context.merge(action: action, target_id: ban.id, before_state: before, after_state: after))
      end
    end
  end
end
