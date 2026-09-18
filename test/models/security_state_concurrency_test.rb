require "test_helper"

# Transactional fixtures share a connection across threads, which can conceal
# races. These tests deliberately use committed rows and separate connections.
class SecurityStateConcurrencyTest < ActiveSupport::TestCase
  self.use_transactional_tests = false

  setup do
    @key = "concurrency-test:#{SecureRandom.hex(12)}"
    @ip = "198.51.100.240"
  end

  teardown do
    if @native_user
      Beskar::SecurityState.where(key: Beskar::Services::NativeAccountLock.key(@native_user)).delete_all
      @native_user.destroy!
    end
    Beskar::SecurityState.where(key: @key).delete_all
    Beskar::AdministrativeAction.where(actor: @key).delete_all
    Beskar::SecurityState.where(key: ["ban:#{@ip}", "waf:enforce:#{@ip}", "rate:enforce:ip:#{@ip}", "rate:enforce:global"]).delete_all
    Beskar::BannedIp.where(ip_address: @ip).delete_all
  end

  test "concurrent increments do not lose updates on independently leased connections" do
    concurrently do
      10.times do
        Beskar::SecurityState.mutate(@key, ttl: 1.hour) do |state|
          state[@key]["count"] = state[@key].fetch("count", 0) + 1
        end
      end
    end
    assert_equal 40, Beskar::SecurityState.read(@key)["count"]
  end

  test "concurrent requests cannot over admit the configured IP limit" do
    Beskar.configuration.rate_limiting[:global_attempts][:enabled] = true
    Beskar.configuration.rate_limiting[:ip_attempts] = {limit: 20, period: 1.hour, exponential_backoff: false}
    results = concurrently do
      request = ActionDispatch::TestRequest.create("REMOTE_ADDR" => @ip)
      10.times.count { Beskar::Services::RateLimiter.check_authentication_attempt(request, :failure)[:allowed] }
    end
    assert_equal 20, results.sum
    assert_equal 20, Beskar::Services::RateLimiter.check_ip_rate_limit(@ip)[:count]
    assert_equal 40, Beskar::Services::RateLimiter.check_global_rate_limit[:count]
  end

  test "concurrent violations and ban extensions preserve every update" do
    Beskar.configuration.waf.merge!(enabled: true, auto_block: false, decay_enabled: false, create_security_events: false)
    analysis = {highest_severity: :critical, patterns: [{category: :test, description: "Test", matched_path: "/.env"}]}
    concurrently do
      5.times do
        Beskar::Services::Waf.record_violation(@ip, analysis)
        Beskar::BannedIp.ban!(@ip, reason: "test", duration: 1.hour)
      end
    end
    assert_equal 20, Beskar::Services::Waf.get_violation_count(@ip)
    assert_equal 1900, Beskar::Services::Waf.get_current_score(@ip)
    assert_equal 1, Beskar::BannedIp.where(ip_address: @ip).count
    assert_equal 20, Beskar::BannedIp.find_by!(ip_address: @ip).violation_count
  end

  test "native session creation racing an account lock cannot leave an active session" do
    @native_user = create(:user)
    jobs = Queue.new
    jobs << :lock
    3.times { jobs << :create }
    concurrently do
      user = User.find(@native_user.id)
      if jobs.pop == :lock
        Beskar::Services::NativeAccountLock.lock!(user, duration: 1.hour)
      else
        request = ActionDispatch::TestRequest.create("REMOTE_ADDR" => @ip)
        5.times { user.with_beskar_session(request) { user.sessions.create! } }
      end
    end
    assert @native_user.beskar_access_locked?
    assert_empty @native_user.sessions.reload
  end

  test "concurrent administrative extensions preserve deadlines and every history transition" do
    ban = Beskar::BannedIp.ban!(@ip, reason: "test", duration: 1.hour)
    original_expiry = ban.expires_at
    concurrently do
      5.times do
        Beskar::Services::AdministrativeBans.new(actor: @key, reason: "Concurrent review", request_id: SecureRandom.uuid)
          .change!([ban.id], action: "extend", duration: "1h")
      end
    end
    assert_in_delta original_expiry.to_f + 20.hours, ban.reload.expires_at.to_f, 0.001
    assert_equal 1, ban.violation_count
    entries = Beskar::AdministrativeAction.where(actor: @key).order(:id).to_a
    assert_equal 20, entries.size
    entries.each_cons(2) { |first, second| assert_equal first.after_state, second.before_state }
  end

  test "administrative and automatic ban updates share coordination without losing either change" do
    ban = Beskar::BannedIp.ban!(@ip, reason: "test", duration: 1.hour)
    original_expiry = ban.expires_at
    roles = Queue.new
    2.times {
      roles << :admin
      roles << :automatic
    }
    concurrently do
      role = roles.pop
      5.times do
        if role == :admin
          Beskar::Services::AdministrativeBans.new(actor: @key, reason: "Concurrent review", request_id: SecureRandom.uuid)
            .change!([ban.id], action: "extend", duration: "1h")
        else
          Beskar::BannedIp.ban!(@ip, reason: "test", duration: 1.hour)
        end
      end
    end
    assert_in_delta original_expiry.to_f + 20.hours, ban.reload.expires_at.to_f, 0.001
    assert_equal 11, ban.violation_count
    assert_equal 10, Beskar::AdministrativeAction.where(actor: @key).count
  end

  private

  def concurrently
    ready = Queue.new
    start = Queue.new
    connections = Queue.new
    threads = 4.times.map do
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do |connection|
          connections << connection.object_id
          ready << true
          start.pop
          yield
        end
      end
    end
    4.times { ready.pop }
    4.times { start << true }
    results = threads.map(&:value)
    assert_equal 4, 4.times.map { connections.pop }.uniq.size
    results
  ensure
    threads&.each(&:join)
  end
end
