require "test_helper"

class AdaptiveRiskScoringTest < ActiveSupport::TestCase
  setup do
    @user = create(:devise_user)
    @request = ActionDispatch::TestRequest.create("REMOTE_ADDR" => "198.51.100.10",
      "HTTP_USER_AGENT" => "curl/8.0")
  end

  test "repeated IP use cannot reduce risk or create location trust" do
    baseline = @user.send(:calculate_risk_score, @request, :success)
    3.times do |i|
      @user.security_events.create!(event_type: "login_success", ip_address: @request.remote_ip,
        risk_score: 1, created_at: (i + 1).days.ago,
        metadata: {authentication: {allowed: true, locked_now: false}})
    end
    assert_equal baseline, @user.send(:calculate_risk_score, @request, :success)
    refute @user.send(:established_pattern?, @request)
    refute @user.send(:location_established?, @request.remote_ip)
  end

  test "lock attempts and unlock records do not prove recovery or reduce risk" do
    baseline = @user.send(:calculate_risk_score, @request, :success)
    %w[account_locked lock_attempted account_unlocked login_success].each do |type|
      @user.security_events.create!(event_type: type, ip_address: @request.remote_ip,
        risk_score: 1, created_at: 1.day.ago)
    end
    assert_equal baseline, @user.send(:calculate_risk_score, @request, :success)
    refute @user.send(:established_pattern?, @request)
  end

  test "denied legacy and observed successes cannot supply enforced travel history" do
    [
      ["authentication_blocked", {authentication: {allowed: false}}],
      ["login_success", {}],
      ["login_success", {authentication: {allowed: false}}],
      ["login_success", {authentication: {allowed: true, locked_now: true}}],
      ["login_success", {authentication: {allowed: true}, risk_assessment: "invalid"}],
      ["login_success", {authentication: {allowed: true}, risk_assessment: {mode: "observe"}}]
    ].each do |type, metadata|
      @user.security_events.create!(event_type: type, ip_address: @request.remote_ip,
        risk_score: 1, created_at: 1.minute.ago, metadata: metadata)
    end
    assert_empty Beskar::Services::RiskAssessment.observations(@user)
    assert_equal 1, Beskar::Services::RiskAssessment.observations(@user, mode: "observe").size
  end

  test "travel history is explicitly ordered and bounded" do
    24.times do |i|
      @user.security_events.create!(event_type: "login_success", ip_address: @request.remote_ip,
        risk_score: 1, created_at: (24 - i).minutes.ago,
        metadata: {authentication: {allowed: true, locked_now: false}})
    end
    history = Beskar::Services::RiskAssessment.observations(@user)
    assert_equal 20, history.size
    assert_equal history.map { |entry| entry[:occurred_at] }.sort.reverse, history.map { |entry| entry[:occurred_at] }
  end

  test "future failed events do not inflate the recent failure factor" do
    2.times do
      @user.security_events.create!(event_type: "login_failure", ip_address: @request.remote_ip,
        risk_score: 1, created_at: 1.hour.from_now)
    end
    assessment = Beskar::Services::RiskAssessment.new(@request, user: @user)
    refute assessment.metadata[:risk_assessment][:factors].any? { |factor| factor[:name] == "recent_failures" }
    assert_equal 0, assessment.metadata[:risk_assessment][:trust_discount]
  end

  test "monitor failures do not raise enforced authentication risk" do
    2.times do
      @user.security_events.create!(event_type: "login_failure", ip_address: @request.remote_ip,
        risk_score: 1, created_at: 1.minute.ago, metadata: {risk_assessment: {mode: "observe"}})
    end
    assessment = Beskar::Services::RiskAssessment.new(@request, user: @user)
    refute assessment.metadata[:risk_assessment][:factors].any? { |factor| factor[:name] == "recent_failures" }
  end
end
