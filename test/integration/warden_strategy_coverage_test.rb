require "test_helper"

Warden::Strategies.add(:beskar_test_token) do
  def valid?
    env["test.credentials_present"]
  end

  def authenticate!
    env["test.verified"] = true
    env["test.user"] ? success!(env["test.user"]) : fail!("invalid")
  end
end

class WardenStrategyCoverageTest < ActiveSupport::TestCase
  setup do
    @user = create(:devise_user)
    @manager = Warden::Manager.new(->(env) {
      env["warden"].authenticate!(:beskar_test_token, scope: :devise_user)
      [200, {}, ["protected"]]
    }) { |config| config.failure_app = ->(_) { [401, {}, ["denied"]] } }
  end

  test "invalid custom tokens are limited before the next verification" do
    Beskar.configuration.rate_limiting[:ip_attempts][:limit] = 1
    first = environment
    assert_equal 401, @manager.call(first).first
    assert first["test.verified"]
    second = environment
    assert_equal 429, @manager.call(second).first
    refute second["test.verified"]
  end

  test "a credential-free request does not consume admission" do
    env = environment.merge("test.credentials_present" => false)
    assert_no_difference "Beskar::SecurityState.count" do
      assert_equal 401, @manager.call(env).first
    end
  end

  test "custom strategy success binds and limits the account exactly once" do
    Beskar.configuration.rate_limiting[:account_attempts][:limit] = 1
    assert_equal 200, @manager.call(environment.merge("test.user" => @user)).first
    assert_equal 1, Beskar::Services::RateLimiter.check_account_rate_limit(@user)[:count]
    assert_equal 401, @manager.call(environment.merge("test.user" => @user, "REMOTE_ADDR" => "198.51.100.25")).first
    assert_equal 1, @user.security_events.login_successes.count
  end

  test "OAuth style manual sign in cannot bypass a lock by disabling Warden callbacks" do
    @user.lock_access!(send_instructions: false)
    proxy = Warden::Proxy.new(environment, @manager)
    result = catch(:warden) { proxy.set_user(@user, scope: :devise_user, run_callbacks: false) }
    assert_equal :devise_user, result[:scope]
    assert_nil proxy.user(:devise_user)
  end

  test "state failure prevents custom credential verification" do
    Beskar::SecurityState.stubs(:mutate).raises(ActiveRecord::ConnectionNotEstablished)
    env = environment
    assert_equal 503, @manager.call(env).first
    refute env["test.verified"]
  end

  test "a completed admission cannot be reused for a different account in the same scope" do
    proxy = Warden::Proxy.new(environment, @manager)
    assert_equal @user, proxy.set_user(@user, scope: :devise_user)
    other = create(:devise_user)
    result = catch(:warden) { proxy.set_user(other, scope: :devise_user, run_callbacks: false) }
    assert_equal :devise_user, result[:scope]
    assert_nil proxy.user(:devise_user)
  end

  test "whitelisted opaque strategies cannot consume another request's enforced account quota" do
    Beskar.configuration.ip_whitelist = ["198.51.100.24"]
    assert_equal 200, @manager.call(environment.merge("test.user" => @user)).first
    assert_equal 0, Beskar::Services::RateLimiter.check_account_rate_limit(@user)[:count]
  end

  private

  def environment
    Rack::MockRequest.env_for("/token", "rack.session" => {}, "REMOTE_ADDR" => "198.51.100.24",
      "test.credentials_present" => true)
  end
end
