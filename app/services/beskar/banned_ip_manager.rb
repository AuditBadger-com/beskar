module Beskar
  class BannedIpManager
    attr_reader :banned_ip, :errors

    def initialize(params)
      @params = params
      @errors = []
      @banned_ip = nil
    end

    def create
      build.save
    end

    def build
      @banned_ip = BannedIp.new(base_attributes)
      unless [nil, "", "temporary", "permanent"].include?(@params[:ban_type])
        raise Services::AdministrativeBans::InvalidInput, "Select a valid ban type"
      end
      configure_ban_duration
      @banned_ip
    end

    def success?
      @banned_ip&.persisted?
    end

    private

    def base_attributes
      {
        ip_address: @params[:ip_address],
        reason: @params[:reason],
        details: @params[:details],
        violation_count: @params[:violation_count] || 1,
        metadata: @params[:metadata] || {},
        banned_at: Time.current
      }
    end

    def configure_ban_duration
      return set_permanent_ban if permanent_ban?

      set_temporary_ban
    end

    def permanent_ban?
      @params[:ban_type] == "permanent"
    end

    def set_permanent_ban
      @banned_ip.permanent = true
      @banned_ip.expires_at = nil
    end

    def set_temporary_ban
      @banned_ip.permanent = false
      @banned_ip.expires_at = calculate_expiry_time
    end

    def calculate_expiry_time
      custom_expiry = custom_expiry_time
      return custom_expiry if custom_expiry
      return preset_duration_expiry unless [nil, ""].include?(preset_duration)

      default_expiry_time
    end

    def custom_expiry_time
      Services::BanExpiry.parse(@params[:expires_at])
    end

    def preset_duration
      @params[:duration]
    end

    def preset_duration_expiry
      unless preset_duration.to_s.match?(/\A[1-9]\d{0,6}\z/) && preset_duration.to_i <= 90.days.to_i
        raise Services::AdministrativeBans::InvalidInput, "Duration must be a positive number of seconds, at most 90 days"
      end
      Time.current + preset_duration.to_i.seconds
    end

    def default_expiry_time
      24.hours.from_now
    end
  end
end
