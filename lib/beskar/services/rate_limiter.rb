module Beskar
  module Services
    class RateLimiter
      DEFAULT_CONFIG = {
        ip_attempts: {
          limit: 10,
          period: 1.hour,
          exponential_backoff: true
        },
        account_attempts: {
          limit: 5,
          period: 15.minutes,
          exponential_backoff: true
        },
        global_attempts: {
          enabled: false,
          limit: 100,
          period: 1.minute
        }
      }.freeze

      BACKOFF_DELAYS = [60, 300, 900, 3600, 14400, 86400].freeze

      class << self
        # Atomically reserve capacity across every applicable tier. :check is a
        # read-only preview: it never counts an attempt or escalates backoff.
        def check_authentication_attempt(request, result, user = nil, account_key: nil)
          keys = keys_for(RequestContext.ip(request), user, account_key: account_key)
          return preview(keys) if result == :check

          reserve(keys)
        end

        def check_ip_rate_limit(ip_address)
          preview(keys_for(ip_address).slice(:ip_attempts))
        end

        def check_account_rate_limit(user)
          preview(keys_for(nil, user).slice(:account_attempts))
        end

        def reserve_account(user, ip_address: nil, account_key: nil)
          reserve(keys_for(ip_address, user, account_key: account_key).slice(:account_attempts))
        end

        def check_global_rate_limit
          preview(keys_for(nil).slice(:global_attempts))
        end

        def is_rate_limited?(request, user = nil)
          !check_authentication_attempt(request, :check, user)[:allowed]
        end

        def time_until_allowed(request, user = nil)
          check_authentication_attempt(request, :check, user)[:retry_after] || 0
        end

        def reset_rate_limit(ip_address: nil, user: nil, global: false)
          keys = keys_for(ip_address, user)
          keys.delete(:global_attempts) unless global
          if ip_address
            mode = Beskar.configuration.monitor_only? ? "observe" : "enforce"
            keys[:denials] = "rate_denials:#{mode}:#{IPAddr.new(ip_address.to_s)}"
          end
          return if keys.empty?

          SecurityState.mutate(keys.values, ttl: 1.second) { |state| state.each_value(&:clear) }
        end

        private

        def keys_for(ip_address, user = nil, account_key: nil)
          keys = {}
          mode = (Beskar.configuration.monitor_only? || IpWhitelist.whitelisted?(ip_address)) ? "observe" : "enforce"
          keys[:ip_attempts] = "rate:#{mode}:ip:#{IPAddr.new(ip_address.to_s)}" if ip_address
          keys[:account_attempts] = "rate:#{mode}:account:#{user.class.name}:#{user.id}" if user
          keys[:account_attempts] ||= "rate:#{mode}:account:#{account_key}" if account_key
          keys[:global_attempts] = "rate:#{mode}:global" if config_for(:global_attempts)[:enabled]
          keys
        end

        def config_for(tier)
          config = DEFAULT_CONFIG.fetch(tier).merge(Beskar.configuration.rate_limiting&.dig(tier) || {})
          unless config[:limit].is_a?(Integer) && config[:limit].positive? && config[:period].to_f.positive?
            raise ArgumentError, "Rate limits require a positive integer limit and positive period (#{tier})"
          end
          config
        end

        def preview(keys)
          now = Time.current.to_f
          most_restrictive_result(keys.map do |tier, key|
            evaluate(SecurityState.read(key), config_for(tier), now).merge(tier: tier)
          end)
        end

        def reserve(keys)
          configs = keys.to_h { |tier, _| [tier, config_for(tier)] }
          ttl = [configs.values.map { |config| config[:period].to_f }.max, BACKOFF_DELAYS.last].max + 60
          SecurityState.mutate(keys.values, ttl: ttl) do |state|
            now = Time.current.to_f
            results = keys.map do |tier, key|
              config = configs.fetch(tier)
              data = state.fetch(key)
              data["attempts"] = recent_attempts(data, config, now)
              result = evaluate(data, config, now)
              if result[:allowed]
                data.delete("denials")
                data.delete("blocked_until")
                # Bounded to the configured limit: denied traffic never grows the
                # sliding window indefinitely or resets its expiration.
                data["attempts"] << now
              elsif config[:exponential_backoff]
                index = [data.fetch("denials", 0), BACKOFF_DELAYS.length - 1].min
                data["denials"] = [index + 1, BACKOFF_DELAYS.length].min
                data["blocked_until"] = [data.fetch("blocked_until", 0), now + BACKOFF_DELAYS[index]].max
                result = evaluate(data, config, now)
              end
              result.merge(tier: tier)
            end
            most_restrictive_result(results)
          end
        end

        def recent_attempts(data, config, now)
          Array(data["attempts"]).select { |timestamp| timestamp > now - config[:period].to_f }
        end

        def evaluate(data, config, now)
          attempts = recent_attempts(data, config, now)
          count = attempts.size
          deadline = data.fetch("blocked_until", 0)
          if count >= config[:limit]
            # Enough entries must expire to bring the count below the limit.
            deadline = [deadline, attempts.sort[count - config[:limit]] + config[:period].to_f].max
          end
          if deadline > now
            {allowed: false, count: count, limit: config[:limit], remaining: 0,
             reset_time: Time.at(deadline), retry_after: (deadline - now).ceil, reason: "rate_limit_exceeded"}
          else
            {allowed: true, count: count, limit: config[:limit], remaining: config[:limit] - count}
          end
        end

        # Compatibility for callers that record an outcome directly.
        def record_attempt(ip_address, result, user)
          reserve(keys_for(ip_address, user)) unless result == :check
        end

        def most_restrictive_result(results)
          return {allowed: true, count: 0, remaining: Float::INFINITY, disabled: true} if results.empty?
          denied = results.reject { |result| result[:allowed] }
          return denied.max_by { |result| result[:retry_after] } if denied.any?

          results.min_by { |result| result[:remaining] }
        end
      end

      # Instance methods for more complex scenarios
      def initialize(ip_address, user = nil)
        @ip_address = ip_address
        @user = user
      end

      def allowed?
        self.class.check_ip_rate_limit(@ip_address)[:allowed] &&
          (@user.nil? || self.class.check_account_rate_limit(@user)[:allowed]) &&
          self.class.check_global_rate_limit[:allowed]
      end

      def attempts_remaining
        ip_result = self.class.check_ip_rate_limit(@ip_address)
        account_result = @user ? self.class.check_account_rate_limit(@user) : {remaining: Float::INFINITY}

        global_result = self.class.check_global_rate_limit
        [ip_result[:remaining] || 0, account_result[:remaining] || 0, global_result[:remaining] || 0].min
      end

      def time_until_reset
        ip_result = self.class.check_ip_rate_limit(@ip_address)
        account_result = @user ? self.class.check_account_rate_limit(@user) : {retry_after: 0}

        global_result = self.class.check_global_rate_limit
        [ip_result[:retry_after] || 0, account_result[:retry_after] || 0, global_result[:retry_after] || 0].max
      end

      def reset!
        self.class.reset_rate_limit(ip_address: @ip_address, user: @user)
      end

      # Sliding window analysis for pattern detection
      def suspicious_pattern?
        return false unless @user

        # Check for rapid-fire attempts
        recent_events = @user.security_events
          .login_failures
          .recent(5.minutes.ago)
          .order(:created_at)

        return true if recent_events.count >= 3

        # Check for distributed attack (same user, different IPs)
        if recent_events.count >= 2
          unique_ips = recent_events.pluck(:ip_address).uniq
          return true if unique_ips.length >= 2
        end

        false
      end

      def attack_pattern_type
        return :none unless suspicious_pattern?

        recent_events = @user.security_events.login_failures.recent(5.minutes.ago)
        unique_ips = recent_events.pluck(:ip_address).uniq
        unique_emails = recent_events.map(&:attempted_email).compact.uniq

        if unique_ips.length >= 2 && unique_emails.length == 1
          :distributed_single_account
        elsif unique_ips.length == 1 && unique_emails.length >= 3
          :single_ip_multiple_accounts
        elsif unique_ips.length == 1 && unique_emails.length == 1
          :brute_force_single_account
        else
          :mixed_attack_pattern
        end
      end
    end
  end
end
