require "test_helper"

class BeskarTest < ActiveSupport::TestCase
  test "it has a version number" do
    assert Beskar::VERSION
  end

  test "has default configuration" do
    config = Beskar.configuration

    assert_not config.waf_enabled?
    assert config.security_tracking[:enabled]
    assert config.security_tracking[:track_successful_logins]
    assert config.security_tracking[:track_failed_logins]
    assert_not config.security_tracking[:auto_analyze_patterns]
    assert_not_nil config.rate_limiting
  end

  test "can configure security tracking" do
    original_config = Beskar.configuration.security_tracking

    Beskar.configure do |config|
      config.security_tracking = {
        enabled: false,
        track_successful_logins: false,
        track_failed_logins: true,
        auto_analyze_patterns: false
      }
    end

    config = Beskar.configuration
    assert_not config.security_tracking[:enabled]
    assert_not config.security_tracking[:track_successful_logins]
    assert config.security_tracking[:track_failed_logins]
    assert_not config.security_tracking[:auto_analyze_patterns]

    # Restore original config
    Beskar.configuration.security_tracking = original_config
  end

  test "can configure WAF settings" do
    original_waf = Beskar.configuration.waf.dup

    Beskar.configure do |config|
      config.monitor_only = false
      config.waf[:enabled] = true
      config.waf[:auto_block] = true
      config.waf[:score_threshold] = 200
    end

    config = Beskar.configuration
    assert config.waf_enabled?
    assert config.waf_auto_block?
    assert_not config.monitor_only?
    assert_equal 200, config.waf[:score_threshold]

    # Restore original config
    Beskar.configuration.waf = original_waf
  end

  test "can configure rate limiting" do
    original_config = Beskar.configuration.rate_limiting

    Beskar.configure do |config|
      config.rate_limiting = {
        ip_attempts: {
          limit: 20,
          period: 2.hours,
          exponential_backoff: false
        }
      }
    end

    config = Beskar.configuration.rate_limiting
    assert_equal 20, config[:ip_attempts][:limit]
    assert_equal 2.hours, config[:ip_attempts][:period]
    assert_not config[:ip_attempts][:exponential_backoff]

    # Restore original config
    Beskar.configuration.rate_limiting = original_config
  end
end
