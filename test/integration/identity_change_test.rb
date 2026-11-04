require "test_helper"

# A request can set a second user on one scope, for example when a remember-me
# cookie signs in one user and the controller then signs in another.
class IdentityChangeTest < ActionDispatch::IntegrationTest
  include Warden::Test::Helpers

  IP = "198.51.100.70"

  setup do
    @first = create(:devise_user, email: "first@example.com", password: "password123")
    @second = create(:devise_user, email: "second@example.com", password: "password123")
    Beskar.configuration.risk_based_locking.merge!(enabled: false, notify_user: false)
    Beskar.configuration.ip_whitelist = []
  end

  teardown do
    Warden.test_reset!
    Beskar.configuration.monitor_only = false
    Beskar.configuration.ip_whitelist = []
  end

  test "monitor mode signs in the second user and records each login" do
    Beskar.configuration.monitor_only = true

    sign_in_both_users_in_one_request

    assert_response :success
    assert_equal 1, @first.security_events.login_successes.count
    assert_equal 1, @second.security_events.login_successes.count
    assert_equal 0, Beskar::SecurityEvent.where(event_type: "authentication_blocked").count
  end

  test "a whitelisted address signs in the second user" do
    Beskar.configuration.ip_whitelist = [IP]

    sign_in_both_users_in_one_request

    assert_response :success
    assert_equal 1, @second.security_events.login_successes.count
  end

  test "enforcement denies the second user" do
    sign_in_both_users_in_one_request

    assert_response :redirect
    assert_equal 0, @second.security_events.login_successes.count
  end

  private

  def sign_in_both_users_in_one_request
    login_as(@first, scope: :devise_user)
    login_as(@second, scope: :devise_user)
    get "/devise_restricted", headers: {"X-Forwarded-For" => IP}
  end
end
