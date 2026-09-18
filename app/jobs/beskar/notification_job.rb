module Beskar
  class NotificationJob < ApplicationJob
    self.log_arguments = false
    queue_as :beskar_notifications

    retry_on Services::Notifications::DeliveryError, wait: :polynomially_longer, attempts: 5

    def perform(user_type:, user_id:, kind:, recipient_index: nil)
      return unless Services::Notifications.enabled?(kind)
      ConfigurationValidator.new(Beskar.configuration).validate_notifications!
      delivery = SecurityMailer.notification(user_type, user_id, kind, recipient_index)
      message = delivery.message
      # A deleted account or removed recipient has no message to deliver.
      return unless message.to.present?
      unless message.perform_deliveries && message.raise_delivery_errors
        raise Services::Notifications::DeliveryError, "Security mail requires enabled deliveries and delivery errors"
      end
      raise Services::Notifications::DeliveryError, "Security mail delivery was aborted" unless delivery.deliver_now
    rescue => error
      # Prevent Active Job's failure/retry logs from dumping transport credentials
      # or arbitrary host callback exception messages (including exception causes).
      raise Services::Notifications::DeliveryError, "Security notification delivery failed (#{error.class})", cause: nil
    end

    def retry_job(options = {})
      result = super
      raise Services::Notifications::DeliveryError, "Security notification retry was not enqueued" unless result
      result
    rescue => error
      raise Services::Notifications::DeliveryError, "Security notification retry failed (#{error.class})", cause: nil
    end
  end
end
