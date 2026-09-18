require "test_helper"
require "stringio"

class NotificationDeliveryTest < ActionDispatch::IntegrationTest
  self.use_transactional_tests = false

  setup do
    @user = create(:user, email_address: "notification-native-#{SecureRandom.hex(8)}@example.com", password: "password123")
    @lock_state_key = Beskar::Services::NativeAccountLock.key(@user)
    @devise_user = create(:devise_user, email: "notification-devise-#{SecureRandom.hex(8)}@example.com", password: "password123")
    @job = Beskar::NotificationJob
    @original_adapter = @job.queue_adapter
    @job.queue_adapter = :test
    @original_deliveries = ActionMailer::Base.deliveries.dup
    ActionMailer::Base.deliveries.clear
    Beskar.configure do |config|
      config.notifications = {from: "security@example.com", recovery_url: "https://example.com/passwords/new",
                              security_team_recipients: ["team-one@example.com", "team-two@example.com"]}
      config.risk_based_locking.merge!(enabled: true, risk_threshold: 1, immediate_signout: true, notify_user: true)
      config.emergency_password_reset.merge!(enabled: true, send_notification: true, notify_security_team: true,
        require_manual_unlock: true)
    end
  end

  teardown do
    @job.queue_adapter = @original_adapter if @job
    ActionMailer::Base.deliveries.replace(@original_deliveries) if @original_deliveries
    # Product retention preserves these rows after account deletion. Explicitly
    # remove only this nontransactional test's events, even for deleted users.
    [@user, @devise_user].compact.each do |user|
      Beskar::SecurityEvent.where(user_type: user.class.polymorphic_name, user_id: user.id).delete_all
    end
    if @user
      Beskar::SecurityState.where(key: @lock_state_key).delete_all
      @user.destroy! unless @user.destroyed?
    end
    @devise_user&.destroy!
    # Request tests create rate-limit state; restrict cleanup to this test's IPs
    # and accounts, including the shared global keys used by the two requests.
    @created_state_keys&.each { |key| Beskar::SecurityState.where(key: key).delete_all }
  end

  test "both real authentication paths deliver lock notices without admitting the locked session" do
    previous_keys = Beskar::SecurityState.pluck(:key)
    begin
      post "/session", params: {email_address: @user.email_address, password: "password123"},
        headers: {"X-Forwarded-For" => "198.51.100.210"}
      assert_response :forbidden
      assert_empty @user.sessions
      post "/devise_users/sign_in", params: {devise_user: {email: @devise_user.email, password: "password123"}},
        headers: {"X-Forwarded-For" => "198.51.100.211"}
      assert @devise_user.reload.access_locked?
      get "/devise_restricted"
      assert_response :redirect
      assert_equal 2, jobs.size
      run_jobs
      assert_equal [@devise_user.email, @user.email_address].sort, deliveries.map { |mail| mail.to.first }.sort
      assert deliveries.all? { |mail| mail.subject == "Security notice: account locked" }
    ensure
      @created_state_keys = Beskar::SecurityState.pluck(:key) - previous_keys
    end
  end

  test "native lock notice waits for the outer commit and contains no private request evidence" do
    User.transaction do
      User.transaction(requires_new: true) { assert locker(@user).lock! }
      assert_empty jobs
      assert_empty deliveries
    end
    assert_equal 1, jobs.size
    args = ActiveJob::Arguments.deserialize(jobs.first[:args]).first
    assert_equal({user_type: "User", user_id: @user.id, kind: "account_locked", recipient_index: nil}, args)
    refute_includes args.to_json, @user.email_address
    refute_includes args.to_json, @user.password_digest
    run_jobs
    mail = deliveries.fetch(0)
    assert_equal [@user.email_address], mail.to
    assert_equal ["security@example.com"], mail.from
    assert_equal "text/plain", mail.mime_type
    assert_includes mail.body.decoded, "https://example.com/passwords/new"
    refute_includes mail.body.decoded, "SECRET_REQUEST"
    refute_includes mail.body.decoded, "198.51.100.210"
    assert @user.beskar_access_locked?
  end

  test "outer and savepoint rollbacks cancel lock notifications for both adapters" do
    [@user, @devise_user].each do |user|
      user.class.transaction do
        assert locker(user).lock!
        raise ActiveRecord::Rollback
      end
      assert_empty jobs
      refute locker(user.reload).locked?
      user.class.transaction do
        user.class.transaction(requires_new: true) do
          assert locker(user).lock!
          raise ActiveRecord::Rollback
        end
      end
      assert_empty jobs
      refute locker(user.reload).locked?
    end
  end

  test "emergency reset commits before independently sending user and team recovery instructions" do
    session = @user.sessions.create!
    token = @user.password_reset_token
    User.transaction do
      assert reset_password
      assert_empty jobs
    end
    refute @user.reload.authenticate("password123")
    refute Session.exists?(session.id)
    assert @user.beskar_access_locked?
    assert_raises(ActiveSupport::MessageVerifier::InvalidSignature) { User.find_by_password_reset_token!(token) }
    assert_equal 3, jobs.size
    assert_equal 1, @user.security_events.where(event_type: "emergency_password_reset").count
    run_jobs
    assert_equal 3, deliveries.size
    user_notice = deliveries.find { |mail| mail.to == [@user.email_address] }
    assert_includes user_notice.body.decoded, "Your previous password no longer works"
    assert_includes user_notice.body.decoded, "does not necessarily unlock"
    team_notices = deliveries.reject { |mail| mail == user_notice }
    assert_equal [["team-one@example.com"], ["team-two@example.com"]], team_notices.map(&:to)
    team_notices.each do |mail|
      assert_includes mail.body.decoded, "User ID #{@user.id}"
      refute_includes mail.body.decoded, @user.email_address
    end
    deliveries.each do |mail|
      refute_includes mail.encoded, token
      refute_includes mail.encoded, @user.password_digest
    end
  end

  test "rolled back and failed emergency resets enqueue nothing" do
    digest = @user.password_digest
    User.transaction do
      assert reset_password
      raise ActiveRecord::Rollback
    end
    assert_empty jobs
    assert_equal digest, @user.reload.password_digest
    Beskar::SecurityEvent.any_instance.stubs(:save!).raises(ActiveRecord::StatementInvalid, "SECRET_AUDIT")
    refute reset_password
    assert_empty jobs
    assert_equal digest, @user.reload.password_digest
  end

  test "failed user extension hook does not suppress team delivery or roll back the password" do
    @user.stubs(:send_emergency_reset_notification).raises(RuntimeError, "SECRET_HOOK")
    Beskar::Logger.expects(:warn).with("Security notification dispatch failed (RuntimeError)")
    assert reset_password
    refute @user.reload.authenticate("password123")
    assert_equal 2, jobs.size
    run_jobs
    assert_equal [["team-one@example.com"], ["team-two@example.com"]], deliveries.map(&:to)
  end

  test "queue failure preserves the lock and does not suppress separate team attempts" do
    @job.stubs(:perform_later).raises(RuntimeError, "SECRET_QUEUE")
    Beskar::Logger.expects(:warn).with("Security notification enqueue failed (RuntimeError)").times(4)
    assert locker(@user).lock!
    assert @user.beskar_access_locked?
    assert reset_password
    assert_empty jobs
    refute @user.reload.authenticate("password123")
  end

  test "aborted enqueue is reported" do
    @job.stubs(:perform_later).returns(false)
    Beskar::Logger.expects(:warn).with("Security notification was not enqueued")
    assert locker(@user).lock!
    assert @user.beskar_access_locked?
  end

  test "disabled flags suppress dispatch and already queued mail" do
    assert locker(@user).lock!
    Beskar.configure do |config|
      config.risk_based_locking[:notify_user] = false
      config.emergency_password_reset.merge!(send_notification: false, notify_security_team: false)
    end
    run_jobs
    assert_empty deliveries
    assert reset_password
    assert_empty jobs
  end

  test "monitor and whitelist suppress automatic notifications with the security action" do
    Beskar.configuration.monitor_only = true
    refute locker(@user).lock!
    refute reset_password
    Beskar.configuration.monitor_only = false
    Beskar.configuration.ip_whitelist = ["198.51.100.210"]
    refute locker(@user).lock!
    refute reset_password
    assert_empty jobs
    assert_empty deliveries
  end

  test "deleted users are skipped" do
    assert reset_password
    Beskar.configure { |config| config.notifications[:security_team_recipients] = ["team-one@example.com"] }
    @user.destroy!
    run_jobs
    assert_empty deliveries
    assert_empty jobs
  end

  test "removed team recipient index is skipped without retrying other recipients" do
    assert reset_password
    Beskar.configure { |config| config.notifications[:security_team_recipients] = ["team-one@example.com"] }
    run_jobs
    assert_equal [@user.email_address, "team-one@example.com"].sort, deliveries.map { |mail| mail.to.first }.sort
    assert_empty jobs
  end

  test "malformed current recipient is rejected without header injection" do
    assert locker(@user).lock!
    @user.update_column(:email_address, "victim@example.com\r\nBcc: attacker@example.com")
    run_jobs
    assert_empty deliveries
    assert_equal 1, jobs.size, "Invalid recipient must fail visibly through the bounded retry path"
  end

  test "transport failure retries without leaking payload or raw exception messages" do
    buffer = StringIO.new
    logger = ActiveSupport::Logger.new(buffer)
    @job.stubs(:logger).returns(logger)
    ActiveJob::Base.stubs(:logger).returns(logger)
    ActionMailer::Base.stubs(:logger).returns(logger)
    Beskar::Logger.stubs(:logger).returns(logger)
    Mail::TestMailer.any_instance.stubs(:deliver!).raises(RuntimeError, "SECRET_SMTP_PASSWORD")
    assert locker(@user).lock!
    run_jobs
    assert_empty deliveries
    assert_equal 1, jobs.size
    assert jobs.first[:at] > Time.current.to_f
    assert @user.beskar_access_locked?
    refute_includes buffer.string, "SECRET_SMTP_PASSWORD"
    refute_includes buffer.string, @user.email_address
    refute_includes buffer.string, "SECRET_REQUEST"
    refute_includes buffer.string, @user.password_digest
    assert_includes buffer.string, "Retrying"
  end

  test "final delivery failure remains visible after five attempts with no secret exception cause" do
    Mail::TestMailer.any_instance.stubs(:deliver!).raises(RuntimeError, "SECRET_SMTP_PASSWORD")
    assert locker(@user).lock!
    4.times do
      run_jobs
      assert_equal 1, jobs.size
    end
    error = assert_raises(Beskar::Services::Notifications::DeliveryError) { run_jobs }
    assert_nil error.cause
    refute_includes error.full_message, "SECRET_SMTP_PASSWORD"
    assert_empty jobs
    assert_empty deliveries
  end

  test "disabled transport is not reported as successful delivery" do
    Beskar::SecurityMailer.stubs(:perform_deliveries).returns(false)
    assert locker(@user).lock!
    run_jobs
    assert_empty deliveries
    assert_equal 1, jobs.size
  end

  test "failed retry enqueue is visible instead of silently discarding the notification" do
    Mail::TestMailer.any_instance.stubs(:deliver!).raises(RuntimeError, "SECRET_SMTP_PASSWORD")
    assert locker(@user).lock!
    @job.any_instance.stubs(:enqueue).returns(false)
    error = assert_raises(Beskar::Services::Notifications::DeliveryError) { run_jobs }
    assert_includes error.message, "retry failed"
    assert_nil error.cause
    assert_empty deliveries
  end

  test "recovery instructions lead through host password recovery without bypassing manual unlock" do
    previous_keys = Beskar::SecurityState.pluck(:key)
    begin
      assert reset_password
      run_jobs
      notice = deliveries.find { |mail| mail.to == [@user.email_address] }
      recovery_uri = URI.parse(URI.extract(notice.body.decoded, ["https"]).first)
      get recovery_uri.request_uri
      assert_response :success
      perform_enqueued_jobs(only: ActionMailer::MailDeliveryJob) do
        post "/passwords", params: {email_address: @user.email_address}
        assert_response :redirect
      end
      reset_mail = deliveries.find { |mail| mail.subject == "Reset your password" }
      assert reset_mail
      reset_uri = URI.parse(URI.extract(reset_mail.text_part.body.decoded, %w[http https]).last)
      get reset_uri.request_uri
      assert_response :success
      token = reset_uri.path.split("/")[-2]
      patch "/passwords/#{token}", params: {password: "recovered-password123", password_confirmation: "recovered-password123"}
      assert_response :redirect
      assert @user.reload.authenticate("recovered-password123")
      assert_raises(ActiveSupport::MessageVerifier::InvalidSignature) { User.find_by_password_reset_token!(token) }
      assert @user.beskar_access_locked?, "Password recovery must not bypass the manual lock"
      assert Beskar::Services::AccountLocker.new(@user, risk_score: 0).unlock!
      Beskar.configure { |config| config.risk_based_locking[:enabled] = false }
      post "/session", params: {email_address: @user.email_address, password: "recovered-password123"}
      assert_response :redirect
      get "/user_restricted"
      assert_response :success
    ensure
      @created_state_keys = Beskar::SecurityState.pluck(:key) - previous_keys
    end
  end

  private

  def locker(user)
    Beskar::Services::AccountLocker.new(user, risk_score: 100,
      metadata: {ip_address: "198.51.100.210", user_agent: "SECRET_REQUEST"})
  end

  def reset_password
    event = Beskar::SecurityEvent.new(user: @user, event_type: "account_locked",
      ip_address: "198.51.100.210", user_agent: "SECRET_REQUEST", risk_score: 100)
    @user.perform_emergency_password_reset(event, :high_risk_authentication)
  end

  def jobs
    @job.queue_adapter.enqueued_jobs
  end

  def run_jobs
    pending = jobs.dup
    jobs.clear
    pending.each { |payload| @job.execute(payload) }
  end

  def deliveries
    ActionMailer::Base.deliveries
  end
end
