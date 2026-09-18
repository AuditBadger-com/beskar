require "test_helper"

class BackgroundAnalysisTest < ActiveSupport::TestCase
  # Exercise real outer commits/rollbacks, not the fixture transaction.
  self.use_transactional_tests = false

  setup do
    @user = create(:user)
    @job = BeskarAnalysisTestJob
    @job.queue_adapter.enqueued_jobs.clear
    Beskar.configure do |config|
      config.security_tracking.merge!(auto_analyze_patterns: true, analysis_job: "BeskarAnalysisTestJob")
    end
  end

  teardown do
    @user&.destroy!
    @job&.queue_adapter&.enqueued_jobs&.clear
  end

  test "enqueues a minimal polymorphic identity outside a transaction" do
    @user.analyze_suspicious_patterns_async
    assert_equal 1, jobs.length
    args = ActiveJob::Arguments.deserialize(jobs.first[:args]).first
    assert_equal({user_type: "User", user_id: @user.id, event_type: "login_success"}, args)
    refute_includes args.to_json, @user.email_address
    refute_includes args.to_json, @user.password_digest
  end

  test "nested commits enqueue only after the outermost transaction commits" do
    User.transaction do
      @user.update!(email_address: "committed-#{@user.id}@example.com")
      User.transaction(requires_new: true) { @user.analyze_suspicious_patterns_async }
      assert_empty jobs
    end
    assert_equal 1, jobs.length
    assert_equal "committed-#{@user.id}@example.com", @user.reload.email_address
  end

  test "outer rollback cancels analysis" do
    original = @user.email_address
    User.transaction do
      @user.update!(email_address: "rolled-back-#{@user.id}@example.com")
      @user.analyze_suspicious_patterns_async
      raise ActiveRecord::Rollback
    end
    assert_empty jobs
    assert_equal original, @user.reload.email_address
  end

  test "rolled-back savepoint does not enqueue after an outer commit" do
    User.transaction do
      User.transaction(requires_new: true) do
        @user.analyze_suspicious_patterns_async
        raise ActiveRecord::Rollback
      end
    end
    assert_empty jobs
  end

  test "queue exceptions preserve committed work and do not log secret exception messages" do
    @job.stubs(:perform_later).raises(RuntimeError, "SECRET_QUEUE_CREDENTIALS")
    Beskar::Logger.expects(:warn).with("Failed to queue security analysis (RuntimeError)")
    User.transaction do
      @user.update!(email_address: "queue-failed-#{@user.id}@example.com")
      @user.analyze_suspicious_patterns_async
    end
    assert_equal "queue-failed-#{@user.id}@example.com", @user.reload.email_address
    assert_empty jobs
  end

  test "an aborted enqueue is reported rather than silently treated as successful" do
    @job.stubs(:perform_later).returns(false)
    Beskar::Logger.expects(:warn).with("Security analysis job was not enqueued")
    @user.analyze_suspicious_patterns_async
    assert_empty jobs
  end

  test "disabled analysis and disabled tracking never enqueue" do
    Beskar.configure { |config| config.security_tracking[:auto_analyze_patterns] = false }
    @user.analyze_suspicious_patterns_async
    assert_empty jobs
    Beskar.configure { |config| config.security_tracking.merge!(auto_analyze_patterns: true, enabled: false) }
    @user.analyze_suspicious_patterns_async
    assert_empty jobs
  end

  private

  def jobs
    @job.queue_adapter.enqueued_jobs
  end
end
