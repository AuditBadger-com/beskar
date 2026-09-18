# frozen_string_literal: true

module Beskar
  module Services
    # Service for detecting device information from User-Agent strings
    #
    # This service provides comprehensive device, browser, and platform detection
    # capabilities for security analysis and fingerprinting purposes.
    #
    # @example Basic usage
    #   detector = Beskar::Services::DeviceDetector.new
    #   info = detector.detect("Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)")
    #   # => {
    #   #   browser: "Safari 15",
    #   #   platform: "iOS 15.0",
    #   #   mobile: true,
    #   #   bot: false
    #   # }
    #
    class DeviceDetector
      # Known bot patterns for security analysis
      BOT_PATTERNS = %r{
        bot|crawler|spider|scraper|fetcher|
        googlebot|bingbot|slurp|duckduckgo|
        facebookexternalhit|twitterbot|linkedinbot|
        whatsapp|telegram|discord|
        curl|wget|postman|httpie|
        python-requests|ruby|php|java|
        headless|phantom|selenium|playwright
      }ix

      # Mobile device patterns
      MOBILE_PATTERNS = %r{
        Mobile|Android|iPhone|iPad|iPod|
        BlackBerry|IEMobile|Opera\s*Mini|
        Windows\s*Phone|webOS|Kindle
      }ix

      # Browser patterns with version extraction
      BROWSER_PATTERNS = {
        chrome: /Chrome\/(\d+(?:\.\d+)*)/i,
        firefox: /Firefox\/(\d+(?:\.\d+)*)/i,
        safari: /Version\/(\d+(?:\.\d+)*).+Safari/i,
        edge: /Edg(?:e|A|iOS)?\/(\d+(?:\.\d+)*)/i,
        opera: /(?:Opera|OPR)\/(\d+(?:\.\d+)*)/i,
        internet_explorer: /(?:MSIE\s+|Trident.*rv:)(\d+(?:\.\d+)*)/i
      }.freeze

      # Platform patterns with version extraction
      PLATFORM_PATTERNS = {
        windows: /Windows NT (\d+\.\d+)/i,
        macos: /Mac OS X (\d+[._]\d+(?:[._]\d+)?)/i,
        ios: /(?:iPhone|iPad).*OS (\d+[._]\d+(?:[._]\d+)?)/i,
        android: /Android (\d+(?:\.\d+)*)/i,
        linux: /Linux/i,
        chromeos: /CrOS/i
      }.freeze

      class << self
        # Convenience method for one-off detection
        #
        # @param user_agent [String] The User-Agent string to analyze
        # @return [Hash] Device information
        def detect(user_agent)
          new.detect(user_agent)
        end

        # Check if a User-Agent represents a mobile device
        #
        # @param user_agent [String] The User-Agent string to check
        # @return [Boolean] true if mobile device
        def mobile?(user_agent)
          return false if user_agent.blank?
          user_agent.match?(MOBILE_PATTERNS)
        end

        # Check if a User-Agent represents a bot/crawler
        #
        # @param user_agent [String] The User-Agent string to check
        # @return [Boolean] true if bot/crawler
        def bot?(user_agent)
          return false if user_agent.blank?
          user_agent.match?(BOT_PATTERNS)
        end
      end

      # Detect comprehensive device information from User-Agent
      #
      # @param user_agent [String] The User-Agent string to analyze
      # @return [Hash] Hash containing browser, platform, mobile, and bot information
      def detect(user_agent)
        return empty_result if user_agent.blank?

        {
          browser: detect_browser(user_agent),
          platform: detect_platform(user_agent),
          mobile: mobile?(user_agent),
          bot: bot?(user_agent),
          raw_user_agent: truncate_user_agent(user_agent)
        }.compact
      end

      # Extract browser information with version
      #
      # @param user_agent [String] The User-Agent string
      # @return [String] Browser name and version, or "Unknown"
      def detect_browser(user_agent)
        return "Unknown" if user_agent.blank?

        # Special case: Safari must be detected after Chrome check
        # because Chrome user agents contain "Safari"
        # Also check for Opera (OPR) before Chrome since it also contains Chrome
        if user_agent.match?(/OPR|Opera/i)
          if (match = user_agent.match(BROWSER_PATTERNS[:opera]))
            return "Opera #{match[1]}"
          end
        elsif user_agent.match?(/Chrome/i) && !user_agent.match?(/Edg/i)
          if (match = user_agent.match(BROWSER_PATTERNS[:chrome]))
            return "Chrome #{match[1]}"
          end
        end

        BROWSER_PATTERNS.each do |browser, pattern|
          next if browser == :chrome # Already handled above

          if (match = user_agent.match(pattern))
            return "#{browser.to_s.titleize} #{match[1]}"
          end
        end

        "Unknown"
      end

      # Extract platform/operating system information with version
      #
      # @param user_agent [String] The User-Agent string
      # @return [String] Platform name and version, or "Unknown"
      def detect_platform(user_agent)
        return "Unknown" if user_agent.blank?

        PLATFORM_PATTERNS.each do |platform, pattern|
          if (match = user_agent.match(pattern))
            version = match[1]&.tr("_", ".")

            case platform
            when :windows
              return "Windows #{version}"
            when :macos
              return "macOS #{version}"
            when :ios
              return "iOS #{version}"
            when :android
              return "Android #{version}"
            when :linux
              return "Linux"
            when :chromeos
              return "Chrome OS"
            end
          end
        end

        "Unknown"
      end

      # Check if User-Agent represents a mobile device
      #
      # @param user_agent [String] The User-Agent string
      # @return [Boolean] true if mobile device detected
      def mobile?(user_agent)
        self.class.mobile?(user_agent)
      end

      # Check if User-Agent represents a bot or crawler
      #
      # @param user_agent [String] The User-Agent string
      # @return [Boolean] true if bot/crawler detected
      def bot?(user_agent)
        self.class.bot?(user_agent)
      end

      # Calculate a risk score based on User-Agent characteristics
      #
      # @param user_agent [String] The User-Agent string
      # @return [Integer] Risk score from 0 to 50
      def calculate_user_agent_risk(user_agent)
        assess(user_agent)[:score]
      end

      # Evidence describes unverified User-Agent claims, never device identity.
      # Do not log the raw header, which can contain attacker-controlled secrets.
      def assess(user_agent)
        original_length = user_agent.to_s.length
        user_agent = RequestContext.text(user_agent)
        info = detect(user_agent)
        factors = []
        if user_agent.blank?
          factors << {name: "user_agent_missing", points: 20, evidence: {}}
        else
          factors << {name: "user_agent_bot", points: 30, evidence: {bot: true}} if info[:bot]
          if original_length < 20 || original_length > 500
            factors << {name: "user_agent_length", points: 15, evidence: {length: original_length}}
          end
          if user_agent.match?(/test|debug|script/i)
            factors << {name: "user_agent_suspicious_pattern", points: 10, evidence: {}}
          end
          factors << {name: "user_agent_parentheses", points: 5, evidence: {count: user_agent.count("()")}} if user_agent.count("()") > 3
          if (match = info[:browser].match(/\A(?:Chrome|Firefox) (\d+)/)) && match[1].to_i < 90
            factors << {name: "old_browser", points: 5, evidence: {browser: info[:browser], legacy_major_cutoff: 90}}
          end
        end
        total = factors.sum { |factor| factor[:points] }
        factors << {name: "user_agent_cap", points: 50 - total, evidence: {cap: 50}} if total > 50
        info[:suspicious] = factors.any? { |factor| %w[user_agent_bot user_agent_suspicious_pattern].include?(factor[:name]) }
        {score: [total, 50].min, device_info: info, factors: factors}
      end

      private

      # Return empty result structure
      #
      # @return [Hash] Empty device information
      def empty_result
        {
          browser: "Unknown",
          platform: "Unknown",
          mobile: false,
          bot: false
        }
      end

      # Truncate user agent for storage (prevent DoS via long strings)
      #
      # @param user_agent [String] The User-Agent string
      # @return [String] Truncated user agent (max 500 chars)
      def truncate_user_agent(user_agent)
        return user_agent if user_agent.length <= 500
        "#{user_agent[0..496]}..."
      end
    end
  end
end
