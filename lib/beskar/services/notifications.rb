module Beskar
  module Services
    # Optional delivery, separate from the synchronous security decision. No
    # password, token, email address, request metadata, or model is serialized.
    class Notifications
      class DeliveryError < StandardError; end

      def self.enabled?(kind)
        case kind
        when "account_locked" then Beskar.configuration.notify_user_on_lock?
        when "emergency_password_reset" then Beskar.configuration.emergency_password_reset[:send_notification] == true
        when "security_team_reset" then Beskar.configuration.emergency_password_reset[:notify_security_team] == true
        else raise Configuration::Error, "Unsupported notification kind"
        end
      end

      def self.enqueue(user, kind)
        return unless enabled?(kind)
        raise ArgumentError, "Notification account must be persisted" unless user.persisted?
        arguments = {user_type: user.class.base_class.name, user_id: user.id, kind: kind}
        after_commit do
          ConfigurationValidator.new(Beskar.configuration).validate_notifications!
          # Indices keep addresses out of queue arguments. A separate job per
          # recipient prevents one failed address from retrying all recipients.
          indices = (kind == "security_team_reset") ? Beskar.configuration.notifications[:security_team_recipients].each_index.to_a : [nil]
          indices.each do |index|
            job = Beskar::NotificationJob.perform_later(**arguments, recipient_index: index)
            Beskar::Logger.warn("Security notification was not enqueued") unless job
          rescue => error
            Beskar::Logger.warn("Security notification enqueue failed (#{error.class})")
          end
        end
      rescue => error
        Beskar::Logger.warn("Security notification preparation failed (#{error.class})")
      end

      def self.after_commit(&block)
        ActiveRecord.after_all_transactions_commit do
          block.call
        rescue => error
          Beskar::Logger.warn("Security notification dispatch failed (#{error.class})")
        end
      end
    end
  end
end
