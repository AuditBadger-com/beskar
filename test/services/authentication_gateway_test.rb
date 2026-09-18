require "test_helper"

class AuthenticationGatewayTest < ActiveSupport::TestCase
  setup do
    @user = create(:user)
    @request = ActionDispatch::TestRequest.create("REMOTE_ADDR" => "198.51.100.53")
  end

  test "custom credential verification is preceded by admission" do
    Beskar.configuration.rate_limiting[:ip_attempts][:limit] = 1
    failed = authenticate { nil }
    refute failed.allowed?
    denied = authenticate { flunk "Verification must not execute" }
    refute denied.allowed?
    assert_equal 429, denied.response.first
  end

  test "issued token generation remains invalid after lock and unlock" do
    attempt = authenticate { @user }
    assert attempt.allowed?
    assert @user.beskar_session_valid?(@request, token: attempt.session_token)
    Beskar::Services::NativeAccountLock.lock!(@user, duration: 1.hour)
    Beskar::Services::NativeAccountLock.unlock!(@user)
    refute @user.beskar_session_valid?(@request, token: attempt.session_token)
    refute @user.beskar_session_valid?(@request, token: nil)
  end

  test "identity substitution and generation changes during verification deny access" do
    other = create(:user)
    refute authenticate { other }.allowed?
    refute authenticate {
      @user.revoke_beskar_sessions!
      @user
    }.allowed?
  end

  private

  def authenticate(&block)
    Beskar::Services::Authentication.authenticate(@request, model: User, scope: :api,
      credentials: {email_address: @user.email_address}, &block)
  end
end
