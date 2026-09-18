module Beskar
  class SecurityMailer < ApplicationMailer
    layout false

    # Only scalar identity fields enter Action Mailer's process instrumentation.
    def notification(user_type, user_id, kind, recipient_index = nil)
      return unless Services::Notifications.enabled?(kind)
      ConfigurationValidator.new(Beskar.configuration).validate_notifications!
      model = user_type.safe_constantize if user_type.is_a?(String)
      unless model.is_a?(Class) && model < ActiveRecord::Base && model.reflect_on_association(:security_events)
        raise Configuration::Error, "Notification account model is unsupported"
      end
      user = model.find_by(id: user_id)
      return unless user

      settings = Beskar.configuration.notifications
      if kind == "security_team_reset"
        return unless recipient_index.is_a?(Integer) && recipient_index >= 0
        recipient = settings[:security_team_recipients][recipient_index]
        return unless recipient
        subject = "Security notice: account password invalidated"
        body = "A precautionary emergency password reset was performed for #{user.class.base_class.name} ID #{user.id}.\n" \
          "Review the authenticated security dashboard and follow your incident response policy.\n" \
          "This notification is not proof that the account was compromised.\n"
      else
        recipient = user.respond_to?(:email_address) ? user.email_address : user.email
        unless ConfigurationValidator.mailbox?(recipient)
          raise Configuration::Error, "Notification account requires one valid email address"
        end
        subject, explanation = if kind == "account_locked"
          ["Security notice: account locked", "Your account was locked as a security precaution."]
        else
          ["Security notice: password reset required", "Your password was invalidated as a security precaution. Your previous password no longer works."]
        end
        body = "#{explanation}\n\nVisit the application's recovery page for help:\n#{settings[:recovery_url]}\n\n" \
          "A password reset does not necessarily unlock your account. Contact your administrator if it remains locked.\n" \
          "This notice does not contain a password or a sign-in link.\n"
      end
      mail(from: settings[:from], to: recipient, subject: subject, body: body, content_type: "text/plain")
    rescue => error
      raise Services::Notifications::DeliveryError, "Security mail preparation failed (#{error.class})", cause: nil
    end

    # Keep this mailer's delivery instrumentation free of addresses, message
    # bodies, and raw transport errors. Do not change logging for host mailers.
    def self.deliver_mail(message)
      ActiveSupport::Notifications.instrument("deliver.beskar_notification", mailer: name) do
        # Recheck after host interceptors; Mail otherwise silently skips delivery
        # or swallows transport errors when these flags are disabled.
        unless message.perform_deliveries && message.raise_delivery_errors
          raise Services::Notifications::DeliveryError, "Security mail delivery is disabled"
        end
        yield
      rescue => error
        raise Services::Notifications::DeliveryError, "Security mail transport failed (#{error.class})", cause: nil
      end
    end
  end
end
