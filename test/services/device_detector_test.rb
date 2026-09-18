require "test_helper"

module Beskar
  module Services
    class DeviceDetectorTest < ActiveSupport::TestCase
      def setup
        @detector = Beskar::Services::DeviceDetector.new
      end

      # Test browser detection
      test "detects Chrome browser correctly" do
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        result = @detector.detect(user_agent)

        assert_equal "Chrome 91.0.4472.124", result[:browser]
        assert_equal "Windows 10.0", result[:platform]
        assert_equal false, result[:mobile]
        assert_equal false, result[:bot]
      end

      test "detects Firefox browser correctly" do
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
        result = @detector.detect(user_agent)

        assert_equal "Firefox 89.0", result[:browser]
        assert_equal "Windows 10.0", result[:platform]
        assert_equal false, result[:mobile]
        assert_equal false, result[:bot]
      end

      test "detects Safari browser correctly" do
        user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
        result = @detector.detect(user_agent)

        assert_equal "Safari 14.1.1", result[:browser]
        assert_equal "macOS 10.15.7", result[:platform]
        assert_equal false, result[:mobile]
        assert_equal false, result[:bot]
      end

      test "detects Edge browser correctly" do
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59"
        result = @detector.detect(user_agent)

        assert_equal "Edge 91.0.864.59", result[:browser]
        assert_equal "Windows 10.0", result[:platform]
        assert_equal false, result[:mobile]
        assert_equal false, result[:bot]
      end

      test "detects Opera browser correctly" do
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36 OPR/77.0.4054.172"
        result = @detector.detect(user_agent)

        assert_equal "Opera 77.0.4054.172", result[:browser]
        assert_equal "Windows 10.0", result[:platform]
        assert_equal false, result[:mobile]
        assert_equal false, result[:bot]
      end

      # Test mobile device detection
      test "detects iPhone correctly" do
        user_agent = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1"
        result = @detector.detect(user_agent)

        assert_equal "Safari 14.1.2", result[:browser]
        assert_equal "iOS 14.7.1", result[:platform]
        assert_equal true, result[:mobile]
        assert_equal false, result[:bot]
      end

      test "detects Android device correctly" do
        user_agent = "Mozilla/5.0 (Linux; Android 11; SM-G991U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36"
        result = @detector.detect(user_agent)

        assert_equal "Chrome 91.0.4472.120", result[:browser]
        assert_equal "Android 11", result[:platform]
        assert_equal true, result[:mobile]
        assert_equal false, result[:bot]
      end

      test "detects iPad correctly" do
        user_agent = "Mozilla/5.0 (iPad; CPU OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1"
        result = @detector.detect(user_agent)

        assert_equal "Safari 14.1.2", result[:browser]
        assert_equal "iOS 14.7.1", result[:platform]
        assert_equal true, result[:mobile]
        assert_equal false, result[:bot]
      end

      # Test bot detection
      test "detects Googlebot as bot" do
        user_agent = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        result = @detector.detect(user_agent)

        assert_equal "Unknown", result[:browser]
        assert_equal "Unknown", result[:platform]
        assert_equal false, result[:mobile]
        assert_equal true, result[:bot]
      end

      test "detects curl as bot" do
        user_agent = "curl/7.68.0"
        result = @detector.detect(user_agent)

        assert_equal "Unknown", result[:browser]
        assert_equal "Unknown", result[:platform]
        assert_equal false, result[:mobile]
        assert_equal true, result[:bot]
      end

      test "detects Python requests as bot" do
        user_agent = "python-requests/2.25.1"
        result = @detector.detect(user_agent)

        assert_equal "Unknown", result[:browser]
        assert_equal "Unknown", result[:platform]
        assert_equal false, result[:mobile]
        assert_equal true, result[:bot]
      end

      test "detects headless Chrome as bot" do
        user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/91.0.4472.101 Safari/537.36"
        result = @detector.detect(user_agent)

        assert_equal "Chrome 91.0.4472.101", result[:browser]
        assert_equal "Linux", result[:platform]
        assert_equal false, result[:mobile]
        assert_equal true, result[:bot]
      end

      # Test platform detection
      test "detects Linux platform correctly" do
        user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        result = @detector.detect(user_agent)

        assert_equal "Chrome 91.0.4472.124", result[:browser]
        assert_equal "Linux", result[:platform]
        assert_equal false, result[:mobile]
        assert_equal false, result[:bot]
      end

      test "detects Chrome OS platform correctly" do
        user_agent = "Mozilla/5.0 (X11; CrOS x86_64 13904.97.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.167 Safari/537.36"
        result = @detector.detect(user_agent)

        assert_equal "Chrome 91.0.4472.167", result[:browser]
        assert_equal "Chrome OS", result[:platform]
        assert_equal false, result[:mobile]
        assert_equal false, result[:bot]
      end

      # Test edge cases
      test "handles blank user agent" do
        result = @detector.detect("")

        assert_equal "Unknown", result[:browser]
        assert_equal "Unknown", result[:platform]
        assert_equal false, result[:mobile]
        assert_equal false, result[:bot]
      end

      test "handles nil user agent" do
        result = @detector.detect(nil)

        assert_equal "Unknown", result[:browser]
        assert_equal "Unknown", result[:platform]
        assert_equal false, result[:mobile]
        assert_equal false, result[:bot]
      end

      test "handles unknown user agent" do
        user_agent = "SomeUnknownBrowser/1.0"
        result = @detector.detect(user_agent)

        assert_equal "Unknown", result[:browser]
        assert_equal "Unknown", result[:platform]
        assert_equal false, result[:mobile]
        assert_equal false, result[:bot]
      end

      test "truncates very long user agents" do
        long_user_agent = "Mozilla/5.0 " + ("A" * 600)
        result = @detector.detect(long_user_agent)

        assert result[:raw_user_agent].length <= 500
        assert result[:raw_user_agent].ends_with?("...")
      end

      # Test class methods
      test "mobile? class method works correctly" do
        mobile_ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X)"
        desktop_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

        assert_equal true, Beskar::Services::DeviceDetector.mobile?(mobile_ua)
        assert_equal false, Beskar::Services::DeviceDetector.mobile?(desktop_ua)
        assert_equal false, Beskar::Services::DeviceDetector.mobile?(nil)
        assert_equal false, Beskar::Services::DeviceDetector.mobile?("")
      end

      test "bot? class method works correctly" do
        bot_ua = "Googlebot/2.1 (+http://www.google.com/bot.html)"
        normal_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0"

        assert_equal true, Beskar::Services::DeviceDetector.bot?(bot_ua)
        assert_equal false, Beskar::Services::DeviceDetector.bot?(normal_ua)
        assert_equal false, Beskar::Services::DeviceDetector.bot?(nil)
        assert_equal false, Beskar::Services::DeviceDetector.bot?("")
      end

      test "detect class method works as convenience method" do
        user_agent = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X)"
        result = Beskar::Services::DeviceDetector.detect(user_agent)

        assert result.is_a?(Hash)
        assert result.key?(:browser)
        assert result.key?(:platform)
        assert result.key?(:mobile)
        assert result.key?(:bot)
      end

      # Test risk calculation
      test "calculate_user_agent_risk returns appropriate scores" do
        # Blank user agent should have high risk
        assert_equal 20, @detector.calculate_user_agent_risk("")
        assert_equal 20, @detector.calculate_user_agent_risk(nil)

        # Bot user agent should have high risk
        bot_ua = "Googlebot/2.1"
        assert @detector.calculate_user_agent_risk(bot_ua) >= 30

        # Normal user agent should have low risk
        normal_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124 Safari/537.36"
        assert @detector.calculate_user_agent_risk(normal_ua) < 10

        # Very short user agent should add risk
        short_ua = "Test/1.0"
        assert @detector.calculate_user_agent_risk(short_ua) > 10

        # Very long user agent should add risk
        long_ua = "A" * 600
        assert @detector.calculate_user_agent_risk(long_ua) > 10

        # Risk should be capped at 50
        super_suspicious_ua = "bot crawler spider test debug script " + ("(" * 10)
        assert @detector.calculate_user_agent_risk(super_suspicious_ua) <= 50
      end

      # Test specific browser version extraction
      test "modern browser versions never inherit stale regex captures as old browser risk" do
        /Chrome (\d+)/ =~ "Chrome 1"
        ["Chrome/120.0", "Firefox/130.0"].each do |browser|
          assessment = @detector.assess("Mozilla/5.0 (Windows NT 10.0) #{browser}")
          refute assessment[:factors].any? { |factor| factor[:name] == "old_browser" }
        end
        assessment = @detector.assess("Mozilla/5.0 (Windows NT 10.0) Chrome/89.0")
        assert assessment[:factors].any? { |factor| factor[:name] == "old_browser" && factor[:points] == 5 }
      end

      test "risk factors sum to capped score without logging the supplied header" do
        Rails.logger.expects(:info).never
        assessment = @detector.assess("curl debug secret-header-value " + "(" * 600)
        assert_equal 50, assessment[:score]
        assert_equal assessment[:score], assessment[:factors].sum { |factor| factor[:points] }
      end

      test "late mobile scoring spans midnight but excludes six in the morning" do
        request = ActionDispatch::TestRequest.create("REMOTE_ADDR" => "127.0.0.1",
          "HTTP_USER_AGENT" => "Mozilla/5.0 (iPhone) Version/17.0 Mobile Safari/600")
        {21 => false, 22 => true, 23 => true, 0 => true, 5 => true, 6 => false}.each do |hour, expected|
          assessment = RiskAssessment.new(request, at: Time.zone.local(2026, 9, 11, hour))
          present = assessment.metadata[:risk_assessment][:factors].any? { |factor| factor[:name] == "mobile_late_hours" }
          assert_equal expected, present, "Wrong late-hour result at #{hour}"
        end
      end

      test "extracts Chrome version correctly with different formats" do
        user_agents = [
          "Mozilla/5.0 (Windows NT 10.0) Chrome/91.0.4472.124",
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/91.0",
          "Chrome/91.0.4472.124 Safari/537.36"
        ]

        user_agents.each do |ua|
          result = @detector.detect(ua)
          assert result[:browser].start_with?("Chrome"), "Failed for: #{ua}"
        end
      end

      test "handles Safari detection when Chrome is also mentioned" do
        # This is the tricky case where Chrome UAs contain "Safari"
        chrome_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        safari_ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"

        chrome_result = @detector.detect(chrome_ua)
        safari_result = @detector.detect(safari_ua)

        assert chrome_result[:browser].start_with?("Chrome")
        assert safari_result[:browser].start_with?("Safari")
      end

      # Test Internet Explorer detection
      test "detects Internet Explorer correctly" do
        ie_user_agents = [
          "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko",
          "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)"
        ]

        ie_user_agents.each do |ua|
          result = @detector.detect(ua)
          assert result[:browser].start_with?("Internet Explorer"), "Failed for: #{ua}"
        end
      end

      # Test that device info is properly structured
      test "returns consistent hash structure" do
        result = @detector.detect("Mozilla/5.0 (iPhone) Safari/604.1")

        expected_keys = [:browser, :platform, :mobile, :bot, :raw_user_agent]
        expected_keys.each do |key|
          assert result.key?(key), "Missing key: #{key}"
        end

        # Values should be of expected types
        assert result[:browser].is_a?(String)
        assert result[:platform].is_a?(String)
        assert [true, false].include?(result[:mobile])
        assert [true, false].include?(result[:bot])
      end

      # Test mobile patterns comprehensively
      test "detects various mobile patterns" do
        mobile_patterns = [
          "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X)",
          "Mozilla/5.0 (Linux; Android 11; SM-G991U)",
          "Mozilla/5.0 (iPad; CPU OS 14_7_1 like Mac OS X)",
          "Mozilla/5.0 (iPod touch; CPU iPhone OS 14_7_1 like Mac OS X)",
          "BlackBerry9700/5.0.0.862 Profile/MIDP-2.1",
          "Mozilla/5.0 (compatible; MSIE 10.0; Windows Phone 8.0)",
          "Opera Mini/7.0.73345/191 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X)"
        ]

        mobile_patterns.each do |ua|
          result = @detector.detect(ua)
          assert_equal true, result[:mobile], "Should detect mobile for: #{ua}"
        end
      end

      # Test desktop patterns
      test "correctly identifies desktop browsers as non-mobile" do
        desktop_patterns = [
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124",
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
          "Mozilla/5.0 (X11; Linux x86_64) Firefox/89.0",
          "Mozilla/5.0 (Windows NT 10.0) Edge/91.0.864.59"
        ]

        desktop_patterns.each do |ua|
          result = @detector.detect(ua)
          assert_equal false, result[:mobile], "Should not detect mobile for: #{ua}"
        end
      end
    end
  end
end
