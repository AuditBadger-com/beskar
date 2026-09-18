require "test_helper"
require_relative "../../beskar_test_base"

module Beskar
  class SecurityEventTest < BeskarTestBase
    test "should create security event with valid attributes" do
      event = build(:security_event)
      assert event.valid?
      assert event.save
    end

    test "should validate presence of event_type" do
      event = build(:security_event, event_type: nil)
      assert_not event.valid?
      assert_includes event.errors[:event_type], "can't be blank"
    end

    test "should validate presence of ip_address" do
      event = build(:security_event, ip_address: nil)
      assert_not event.valid?
      assert_includes event.errors[:ip_address], "can't be blank"
    end

    test "should validate risk_score is a number between 0 and 100" do
      # Test valid risk score
      event = build(:security_event, risk_score: 50)
      assert event.valid?

      # Test risk score below 0
      event = build(:security_event, risk_score: -1)
      assert_not event.valid?
      assert_includes event.errors[:risk_score], "must be in 0..100"

      # Test risk score above 100
      event = build(:security_event, risk_score: 101)
      assert_not event.valid?
      assert_includes event.errors[:risk_score], "must be in 0..100"
    end

    test "should allow nil user for anonymous events" do
      event = build(:security_event, :anonymous)
      assert event.valid?
      assert event.save
    end

    test "login_successes scope should return only successful logins" do
      success_event = create(:security_event, :login_success)
      create(:security_event, :login_failure)

      successes = Beskar::SecurityEvent.login_successes
      assert_equal 1, successes.count
      assert_equal success_event.id, successes.first.id
      assert_equal "login_success", successes.first.event_type
    end

    test "login_failures scope should return only failed logins" do
      create(:security_event, :login_success)
      failure_event = create(:security_event, :login_failure)

      failures = Beskar::SecurityEvent.login_failures
      assert_equal 1, failures.count
      assert_equal failure_event.id, failures.first.id
      assert_equal "login_failure", failures.first.event_type
    end

    test "recent scope should return events after specified time" do
      create(:security_event, :old)
      recent_event = create(:security_event, :recent)

      recent_events = Beskar::SecurityEvent.recent(1.hour.ago)
      assert_equal 1, recent_events.count
      assert_equal recent_event.id, recent_events.first.id
    end

    test "by_ip scope should return events from specific IP" do
      event_ip1 = create(:security_event, ip_address: "192.168.1.1")
      create(:security_event, ip_address: "192.168.1.2")

      ip1_events = Beskar::SecurityEvent.by_ip("192.168.1.1")
      assert_equal 1, ip1_events.count
      assert_equal event_ip1.id, ip1_events.first.id
      assert_equal "192.168.1.1", ip1_events.first.ip_address
    end

    test "high_risk scope should return events with risk score >= 70" do
      create(:security_event, risk_score: 10)
      high_risk_event = create(:security_event, :high_risk)

      high_risk_events = Beskar::SecurityEvent.high_risk
      assert_equal 1, high_risk_events.count
      assert_equal high_risk_event.id, high_risk_events.first.id
      assert high_risk_events.first.risk_score >= 70
    end

    test "critical_risk scope should return events with risk score >= 90" do
      create(:security_event, :high_risk)
      critical_event = create(:security_event, :critical_risk)

      critical_events = Beskar::SecurityEvent.critical_risk
      assert_equal 1, critical_events.count
      assert_equal critical_event.id, critical_events.first.id
      assert critical_events.first.risk_score >= 90
    end

    test "critical_threat? should return true for risk score >= 90" do
      event = build(:security_event, :critical_risk)
      assert event.critical_threat?

      event = build(:security_event, :high_risk)
      assert_not event.critical_threat?
    end

    test "high_risk? should return true for risk score >= 70" do
      event = build(:security_event, :high_risk)
      assert event.high_risk?

      event = build(:security_event, risk_score: 60)
      assert_not event.high_risk?
    end

    test "login_failure? should return true for login_failure events" do
      event = build(:security_event, :login_failure)
      assert event.login_failure?

      event = build(:security_event, :login_success)
      assert_not event.login_failure?
    end

    test "login_success? should return true for login_success events" do
      event = build(:security_event, :login_success)
      assert event.login_success?

      event = build(:security_event, :login_failure)
      assert_not event.login_success?
    end

    test "attempted_email should return email from metadata" do
      event = build(:security_event, :login_failure,
        metadata: {"attempted_email" => "test@example.com"})
      assert_equal "test@example.com", event.attempted_email
    end

    test "device_info should return device info from metadata" do
      device_data = {"browser" => "Chrome", "platform" => "Windows"}
      event = build(:security_event, metadata: {"device_info" => device_data})
      assert_equal device_data, event.device_info
    end

    test "device_info should return empty hash if no device info" do
      event = build(:security_event, metadata: {})
      assert_equal({}, event.device_info)

      event = build(:security_event, metadata: nil)
      assert_equal({}, event.device_info)
    end

    test "geolocation should return geolocation from metadata" do
      event = build(:security_event, :with_geolocation)
      geo_data = event.geolocation
      assert_equal "US", geo_data["country"]
      assert_equal "New York", geo_data["city"]
      assert_equal 40.7128, geo_data["latitude"]
      assert_equal(-74.0060, geo_data["longitude"])
    end

    test "geolocation should return empty hash if no geolocation" do
      event = build(:security_event, metadata: {})
      assert_equal({}, event.geolocation)

      event = build(:security_event, metadata: nil)
      assert_equal({}, event.geolocation)
    end

    test "should store metadata as JSON" do
      metadata = {
        "session_id" => "test_session",
        "user_agent_parsed" => {"browser" => "Chrome"},
        "timestamp" => "2023-01-01T10:00:00Z"
      }

      event = create(:security_event, metadata: metadata)
      event.reload
      assert_equal metadata.merge("session_id" => "[FILTERED]"), event.metadata
    end
  end
end
