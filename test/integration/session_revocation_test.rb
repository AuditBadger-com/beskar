require "test_helper"

class SessionRevocationTest < ActionDispatch::IntegrationTest
  setup do
    @user = create(:devise_user, password: "password123")
    Beskar.configuration.rate_limiting[:account_attempts][:limit] = 100
    Beskar.configuration.rate_limiting[:ip_attempts][:limit] = 100
  end

  test "a lock revokes every browser and unlocking cannot resurrect either cookie" do
    clients = 2.times.map do
      open_session.tap do |client|
        client.post "/devise_users/sign_in", params: {devise_user: {email: @user.email, password: "password123"}}
        client.get "/devise_restricted"
        assert_equal 200, client.response.status
      end
    end
    old_token = @user.beskar_session_token
    @user.lock_access!(send_instructions: false)
    refute_equal old_token, @user.beskar_session_token
    @user.unlock_access!
    clients.each do |client|
      client.get "/devise_restricted"
      assert_equal 302, client.response.status
    end
    post "/devise_users/sign_in", params: {devise_user: {email: @user.email, password: "password123"}}
    get "/devise_restricted"
    assert_response :success
  end

  test "remember cookies and serialized sessions are invalid after explicit revocation" do
    @user.remember_me!
    remember = DeviseUser.serialize_into_cookie(@user)
    session = DeviseUser.serialize_into_session(@user)
    assert DeviseUser.serialize_from_cookie(*remember)
    assert DeviseUser.serialize_from_session(*session)
    @user.revoke_beskar_sessions!
    assert_nil DeviseUser.serialize_from_cookie(*remember)
    assert_nil DeviseUser.serialize_from_session(*session)
  end

  test "ordinary locked_at writes rotate generations and roll back with the user update" do
    original = @user.beskar_session_token
    @user.class.transaction(requires_new: true) do
      @user.update!(locked_at: Time.current)
      refute_equal original, @user.beskar_session_token
      raise ActiveRecord::Rollback
    end
    assert_nil @user.reload.locked_at
    assert_equal original, @user.beskar_session_token
  end

  test "revocation failure rolls back the lock and does not report success" do
    Beskar::SecurityState.stubs(:mutate).raises(ActiveRecord::ConnectionNotEstablished)
    assert_raises(Beskar::Services::AuthenticationAttempt::Unavailable) { @user.lock_access!(send_instructions: false) }
    assert_nil @user.reload.locked_at
  end

  test "a high risk login is denied with default signout and with legacy false" do
    [true, false].each do |legacy_setting|
      @user.unlock_access!
      Beskar.configuration.risk_based_locking.merge!(enabled: true, risk_threshold: 1, immediate_signout: legacy_setting)
      post "/devise_users/sign_in", params: {devise_user: {email: @user.email, password: "password123"}}
      assert @user.reload.access_locked?
      get "/devise_restricted"
      assert_response :redirect
    end
  end

  test "revocation during password verification denies an otherwise valid credential" do
    DeviseUser.any_instance.stubs(:valid_password?).with("password123").returns(true)
    DeviseUser.any_instance.stubs(:after_database_authentication).with do
      @user.revoke_beskar_sessions!
      true
    end
    post "/devise_users/sign_in", params: {devise_user: {email: @user.email, password: "password123"}}
    get "/devise_restricted"
    assert_response :redirect
  end

  test "native revocation rejects stale database session objects even after unlock" do
    user = create(:user)
    record = user.sessions.create!
    stale = record.class.find(record.id)
    request = ActionDispatch::TestRequest.create("REMOTE_ADDR" => "198.51.100.24")
    token = user.beskar_session_token
    assert Beskar::Services::SessionRevocation.native_session_allowed?(stale, request: request)
    user.revoke_beskar_sessions!
    refute user.beskar_session_valid?(request, token: token)
    refute Beskar::Services::SessionRevocation.native_session_allowed?(stale, request: request)
    assert_empty user.sessions.reload
  end

  test "native lock generations survive unlock and expired-state cleanup" do
    user = create(:user)
    request = ActionDispatch::TestRequest.create("REMOTE_ADDR" => "198.51.100.24")
    token = user.beskar_session_token
    Beskar::Services::NativeAccountLock.lock!(user, duration: 1.second)
    Beskar::Services::NativeAccountLock.unlock!(user)
    Beskar::SecurityState.cleanup_expired!
    refute user.beskar_session_valid?(request, token: token)
    refute user.with_beskar_session(request, generation: token) { flunk "Old credential issued a session" }
  end
end
