require "test_helper"
require "ostruct"

class WafExceptionTest < ActiveSupport::TestCase
  def setup
    Rails.cache.clear
    Beskar.configuration.waf = {
      enabled: true,
      exception_detection: :all, # Broad exception scoring is now explicit opt-in.
      auto_block: true,
      score_threshold: 150,
      violation_window: 1.hour,
      create_security_events: true,
      record_not_found_exclusions: [
        %r{/posts/.*},
        %r{/articles/\d+}
      ]
    }
    Beskar.configuration.monitor_only = false
  end

  def teardown
    Rails.cache.clear
    Beskar.configuration.waf = {enabled: false}
    Beskar::SecurityEvent.delete_all
    Beskar::BannedIp.destroy_all
  end

  test "detects ActionController::UnknownFormat exception as security threat" do
    request = mock_request("/users/123.exe", "192.168.1.100")
    exception = ActionController::UnknownFormat.new("Unknown format requested")

    analysis = Beskar::Services::Waf.analyze_exception(exception, request)

    assert_not_nil analysis
    assert analysis[:threat_detected]
    assert_equal :unknown_format, analysis[:patterns].first[:category]
    assert_equal :medium, analysis[:highest_severity]
    assert_equal "Unknown format requested - potential scanner", analysis[:patterns].first[:description]
    assert_equal "192.168.1.100", analysis[:ip_address]
    assert_equal "ActionController::UnknownFormat", analysis[:exception_class]
  end

  test "detects ActionDispatch::RemoteIp::IpSpoofAttackError as critical threat" do
    request = mock_request("/admin", "192.168.1.100")
    exception = ActionDispatch::RemoteIp::IpSpoofAttackError.new("IP spoofing attack?!")

    analysis = Beskar::Services::Waf.analyze_exception(exception, request)

    assert_not_nil analysis
    assert analysis[:threat_detected]
    assert_equal :ip_spoof, analysis[:patterns].first[:category]
    assert_equal :critical, analysis[:highest_severity]
    assert_equal "IP spoofing attack detected", analysis[:patterns].first[:description]
    assert_equal "ActionDispatch::RemoteIp::IpSpoofAttackError", analysis[:exception_class]
  end

  test "detects ActiveRecord::RecordNotFound as low severity threat" do
    request = mock_request("/users/999999", "192.168.1.100")
    exception = ActiveRecord::RecordNotFound.new("Couldn't find User with 'id'=999999")

    analysis = Beskar::Services::Waf.analyze_exception(exception, request)

    assert_not_nil analysis
    assert analysis[:threat_detected]
    assert_equal :record_not_found, analysis[:patterns].first[:category]
    assert_equal :low, analysis[:highest_severity]
    assert_equal "Record not found - potential enumeration scan", analysis[:patterns].first[:description]
    assert_equal "ActiveRecord::RecordNotFound", analysis[:exception_class]
  end

  test "detects ActionDispatch::Http::MimeNegotiation::InvalidType as medium severity threat" do
    request = mock_request("/api/data", "192.168.1.100")
    exception = ActionDispatch::Http::MimeNegotiation::InvalidType.new('GET "../../../../../../../../etc/passwd{{" is not a valid MIME type')

    analysis = Beskar::Services::Waf.analyze_exception(exception, request)

    assert_not_nil analysis
    assert analysis[:threat_detected]
    assert_equal :invalid_mime_type, analysis[:patterns].first[:category]
    assert_equal :medium, analysis[:highest_severity]
    assert_equal "Invalid MIME type requested - potential scanner", analysis[:patterns].first[:description]
    assert_equal "192.168.1.100", analysis[:ip_address]
    assert_equal "ActionDispatch::Http::MimeNegotiation::InvalidType", analysis[:exception_class]
    refute analysis.key?(:exception_message)
  end

  test "excludes RecordNotFound for configured patterns" do
    # Test excluded path - should not detect threat
    request = mock_request("/posts/non-existent-slug", "192.168.1.100")
    exception = ActiveRecord::RecordNotFound.new("Couldn't find Post")

    analysis = Beskar::Services::Waf.analyze_exception(exception, request)
    assert_nil analysis

    # Test another excluded path
    request = mock_request("/articles/999999", "192.168.1.100")
    analysis = Beskar::Services::Waf.analyze_exception(exception, request)
    assert_nil analysis

    # Test non-excluded path - should detect threat
    request = mock_request("/admin/users/999999", "192.168.1.100")
    analysis = Beskar::Services::Waf.analyze_exception(exception, request)
    assert_not_nil analysis
    assert analysis[:threat_detected]
  end

  test "records violations for InvalidType exception" do
    request = mock_request("/api/data", "192.168.1.100")
    exception = ActionDispatch::Http::MimeNegotiation::InvalidType.new('GET "../../../../etc/passwd{{" is not a valid MIME type')

    analysis = Beskar::Services::Waf.analyze_exception(exception, request)

    # Record the violation
    assert_difference "Beskar::SecurityEvent.count", 1 do
      current_score = Beskar::Services::Waf.record_violation("192.168.1.100", analysis)
      assert_equal 60, current_score.round # medium severity = 60 points
    end

    # Check the security event was created correctly
    event = Beskar::SecurityEvent.last
    assert_equal "waf_violation", event.event_type
    assert_equal "192.168.1.100", event.ip_address
    assert_equal 60, event.risk_score # medium severity = 60
    assert_includes event.metadata["patterns_matched"], "Invalid MIME type requested - potential scanner"
    assert_equal "ActionDispatch::Http::MimeNegotiation::InvalidType", event.metadata["waf_analysis"]["exception_class"]
  end

  test "auto-blocks IP after threshold violations from InvalidType exceptions" do
    request = mock_request("/api/data", "192.168.1.100")
    exception = ActionDispatch::Http::MimeNegotiation::InvalidType.new("Invalid MIME type")

    # Create violations up to threshold
    3.times do |i|
      analysis = Beskar::Services::Waf.analyze_exception(exception, request)
      Beskar::Services::Waf.record_violation("192.168.1.100", analysis)
    end

    # IP should now be banned
    assert Beskar::BannedIp.banned?("192.168.1.100")

    banned_ip = Beskar::BannedIp.find_by(ip_address: "192.168.1.100")
    assert_equal "waf_violation", banned_ip.reason
    assert_includes banned_ip.details, "Invalid MIME type requested - potential scanner"
  end

  test "records violations for exception-based threats" do
    request = mock_request("/users/123.exe", "192.168.1.100")
    exception = ActionController::UnknownFormat.new("Unknown format")

    analysis = Beskar::Services::Waf.analyze_exception(exception, request)

    # Record the violation
    assert_difference "Beskar::SecurityEvent.count", 1 do
      current_score = Beskar::Services::Waf.record_violation("192.168.1.100", analysis)
      assert_equal 60, current_score.round # medium severity = 60 points
    end

    # Check the security event was created correctly
    event = Beskar::SecurityEvent.last
    assert_equal "waf_violation", event.event_type
    assert_equal "192.168.1.100", event.ip_address
    assert_equal 60, event.risk_score # medium severity = 60
    assert_includes event.metadata["patterns_matched"], "Unknown format requested - potential scanner"
    assert_equal "ActionController::UnknownFormat", event.metadata["waf_analysis"]["exception_class"]
  end

  test "auto-blocks IP after threshold violations from exceptions" do
    request = mock_request("/users/123.exe", "192.168.1.100")
    exception = ActionController::UnknownFormat.new("Unknown format")

    # Create violations up to threshold
    3.times do |i|
      analysis = Beskar::Services::Waf.analyze_exception(exception, request)
      Beskar::Services::Waf.record_violation("192.168.1.100", analysis)
    end

    # IP should now be banned
    assert Beskar::BannedIp.banned?("192.168.1.100")

    banned_ip = Beskar::BannedIp.find_by(ip_address: "192.168.1.100")
    assert_equal "waf_violation", banned_ip.reason
    assert_includes banned_ip.details, "Unknown format requested - potential scanner"
  end

  test "critical severity exceptions contribute higher to blocking" do
    request = mock_request("/admin", "192.168.1.100")
    ip_spoof_exception = ActionDispatch::RemoteIp::IpSpoofAttackError.new("IP spoofing")

    # Record IP spoofing violation
    analysis = Beskar::Services::Waf.analyze_exception(ip_spoof_exception, request)
    Beskar::Services::Waf.record_violation("192.168.1.100", analysis)

    # Check the risk score is higher for critical severity
    event = Beskar::SecurityEvent.last
    assert_equal 95, event.risk_score # critical severity = 95
  end

  test "respects monitor_only mode for exception-based threats" do
    Beskar.configuration.monitor_only = true

    request = mock_request("/users/123.exe", "192.168.1.100")
    exception = ActionController::UnknownFormat.new("Unknown format")

    # Record violations up to threshold
    3.times do
      analysis = Beskar::Services::Waf.analyze_exception(exception, request)
      Beskar::Services::Waf.record_violation("192.168.1.100", analysis)
    end

    # Monitor mode records evidence without creating an active ban.
    assert_not Beskar::BannedIp.banned?("192.168.1.100")

    # But the ban should indicate it's in monitor mode via the logs
    # (actual blocking behavior is handled by middleware)
  end

  test "should_exclude_record_not_found checks configured patterns" do
    # Test with configured exclusions
    assert Beskar::Services::Waf.should_exclude_record_not_found?("/posts/my-post")
    assert Beskar::Services::Waf.should_exclude_record_not_found?("/posts/another-post/comments")
    assert Beskar::Services::Waf.should_exclude_record_not_found?("/articles/123")
    assert Beskar::Services::Waf.should_exclude_record_not_found?("/articles/999999")

    # Test paths that should NOT be excluded
    refute Beskar::Services::Waf.should_exclude_record_not_found?("/users/999999")
    refute Beskar::Services::Waf.should_exclude_record_not_found?("/admin/settings")
    refute Beskar::Services::Waf.should_exclude_record_not_found?("/api/v1/accounts/fake")
  end

  test "combines exception detection with regular WAF patterns" do
    # First, trigger a regular WAF pattern
    request = mock_request("/wp-admin", "192.168.1.100")
    waf_analysis = Beskar::Services::Waf.analyze_request(request)
    Beskar::Services::Waf.record_violation("192.168.1.100", waf_analysis)

    # Then trigger an exception-based pattern
    request = mock_request("/users/123.exe", "192.168.1.100")
    exception = ActionController::UnknownFormat.new("Unknown format")
    exception_analysis = Beskar::Services::Waf.analyze_exception(exception, request)
    Beskar::Services::Waf.record_violation("192.168.1.100", exception_analysis)

    # Then one more regular pattern - should trigger ban (3 total)
    request = mock_request("/phpmyadmin", "192.168.1.100")
    waf_analysis = Beskar::Services::Waf.analyze_request(request)
    Beskar::Services::Waf.record_violation("192.168.1.100", waf_analysis)

    # Should be banned after combined violations
    assert Beskar::BannedIp.banned?("192.168.1.100")

    # Check that we have different types of violations recorded
    events = Beskar::SecurityEvent.where(ip_address: "192.168.1.100")
    assert_equal 3, events.count

    patterns = events.map { |e| e.metadata["patterns_matched"] }.flatten
    assert_includes patterns, "WordPress vulnerability scan"
    assert_includes patterns, "Unknown format requested - potential scanner"
    assert_includes patterns, "PHP admin panel scan"
  end

  test "handles nil exception gracefully" do
    request = mock_request("/", "192.168.1.100")
    analysis = Beskar::Services::Waf.analyze_exception(nil, request)
    assert_nil analysis
  end

  test "handles unknown exception types" do
    request = mock_request("/", "192.168.1.100")
    exception = StandardError.new("Some other error")
    analysis = Beskar::Services::Waf.analyze_exception(exception, request)
    assert_nil analysis
  end

  private

  def mock_request(path, ip, user_agent = "Mozilla/5.0")
    request = OpenStruct.new
    request.fullpath = path
    request.path = path.split("?").first
    request.ip = ip
    request.user_agent = user_agent
    request
  end
end
