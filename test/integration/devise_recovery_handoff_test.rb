require "test_helper"

class DeviseRecoveryHandoffTest < ActionDispatch::IntegrationTest
  test "Devise email recovery honors its unlock policy without restoring old sessions" do
    user = create(:devise_user, password: "password123")
    old_client = open_session
    old_client.post "/devise_users/sign_in", params: {devise_user: {email: user.email, password: "password123"}}
    old_client.get "/devise_restricted"
    assert_equal 200, old_client.response.status
    generation = user.beskar_session_token
    user.lock_access!(send_instructions: false)
    ActionMailer::Base.deliveries.clear

    post "/devise_users/password", params: {devise_user: {email: user.email}}
    assert_response :redirect
    mail = ActionMailer::Base.deliveries.last
    assert_equal [user.email], mail.to
    token = mail.body.decoded[/reset_password_token=([^"&\s<]+)/, 1]
    assert token.present?
    put "/devise_users/password", params: {devise_user: {reset_password_token: token,
                                                         password: "recovered-password123", password_confirmation: "recovered-password123"}}
    assert_response :redirect
    refute user.reload.access_locked?
    assert user.valid_password?("recovered-password123")
    assert_nil user.reset_password_token
    refute_equal generation, user.beskar_session_token
    get "/devise_restricted"
    assert_response :success
    old_client.get "/devise_restricted"
    assert_equal 302, old_client.response.status
    replay = open_session
    replay.put "/devise_users/password", params: {devise_user: {reset_password_token: token,
                                                                password: "replayed-password123", password_confirmation: "replayed-password123"}}
    assert_equal 422, replay.response.status
    assert user.reload.valid_password?("recovered-password123")
  ensure
    ActionMailer::Base.deliveries.clear
  end
end
