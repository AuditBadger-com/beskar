require "test_helper"

class WardenSignoutTest < ActiveSupport::TestCase
  setup do
    @user = create(:devise_user)
    Beskar.configuration.risk_based_locking.merge!(enabled: true, immediate_signout: true)
    request = ActionDispatch::TestRequest.create("REMOTE_ADDR" => "203.0.113.1")
    @attempt = Beskar::Services::AuthenticationAttempt.reserve(request, model: DeviseUser, scope: :devise_user, user: @user)
    @event = Beskar::SecurityEvent.new(user: @user, event_type: "login_success", risk_score: 90, ip_address: "203.0.113.1")
    @event.beskar_attempt = @attempt
  end

  test "helper recognizes only a lock confirmed by the current attempt" do
    refute Beskar::Engine.user_was_just_locked?(@user, @event)
    @attempt.locked_now = true
    assert Beskar::Engine.user_was_just_locked?(@user, @event)
  end

  test "recent unrelated lock and attempted lock records cannot trigger signout" do
    %w[account_locked lock_attempted].each do |type|
      @user.security_events.create!(event_type: type, ip_address: "203.0.113.1", risk_score: 90)
    end
    refute Beskar::Engine.user_was_just_locked?(@user, @event)
    auth = mock("warden")
    auth.expects(:logout).never
    @user.check_high_risk_lock_and_signout(auth, scope: :devise_user, attempt: @attempt)
  end

  test "nil event and different user cannot trigger detection" do
    @attempt.locked_now = true
    refute Beskar::Engine.user_was_just_locked?(@user, nil)
    refute Beskar::Engine.user_was_just_locked?(create(:devise_user), @event)
  end

  test "helper honors disabled risk locking" do
    @attempt.locked_now = true
    Beskar.configuration.risk_based_locking[:enabled] = false
    refute Beskar::Engine.user_was_just_locked?(@user, @event)
  end

  test "signout affects only the explicitly correlated scope" do
    @attempt.locked_now = true
    auth = mock("warden")
    auth.expects(:logout).with(:devise_user).once
    result = catch(:warden) { @user.check_high_risk_lock_and_signout(auth, scope: :devise_user, attempt: @attempt) }
    assert_equal :devise_user, result[:scope]
  end

  test "signout requires the matching scope" do
    @attempt.locked_now = true
    auth = mock("warden")
    auth.expects(:logout).never
    @user.check_high_risk_lock_and_signout(auth, scope: :other, attempt: @attempt)
    @user.check_high_risk_lock_and_signout(auth, attempt: @attempt)
  end

  test "legacy false setting cannot bypass a confirmed lock" do
    @attempt.locked_now = true
    Beskar.configuration.risk_based_locking[:immediate_signout] = false
    auth = mock("warden")
    auth.expects(:logout).with(:devise_user).once
    result = catch(:warden) { @user.check_high_risk_lock_and_signout(auth, scope: :devise_user, attempt: @attempt) }
    assert_equal :devise_user, result[:scope]
  end

  test "signout respects monitor and whitelist policy" do
    @attempt.locked_now = true
    auth = mock("warden")
    auth.expects(:logout).never
    Beskar.configuration.monitor_only = true
    @user.check_high_risk_lock_and_signout(auth, scope: :devise_user, attempt: @attempt)
    Beskar.configuration.monitor_only = false
    Beskar.configuration.ip_whitelist = [@attempt.ip_address]
    @user.check_high_risk_lock_and_signout(auth, scope: :devise_user, attempt: @attempt)
  end
end
