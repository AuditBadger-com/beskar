require "test_helper"

class PersistentSecurityStateTest < ActiveSupport::TestCase
  setup do
    @limiter = Beskar::Services::RateLimiter
    @ip = "198.51.100.40"
    @request = ActionDispatch::TestRequest.create("REMOTE_ADDR" => @ip)
    Beskar.configuration.waf.merge!(enabled: true, decay_enabled: false)
    @analysis = {highest_severity: :critical, patterns: [{category: :test, description: "Test", matched_path: "/.env"}]}
  end

  test "null and unavailable caches cannot disable coordinated enforcement" do
    unavailable_cache = mock("unavailable cache")
    unavailable_cache.stubs(:delete).raises(IOError, "cache unavailable")
    [ActiveSupport::Cache::NullStore.new, unavailable_cache].each do |cache|
      Rails.stubs(:cache).returns(cache)
      @limiter.reset_rate_limit(ip_address: @ip, global: true)
      Beskar::Services::Waf.reset_violations(@ip)
      10.times { @limiter.check_authentication_attempt(@request, :failure) }
      assert_not @limiter.check_ip_rate_limit(@ip)[:allowed]
      2.times { Beskar::Services::Waf.record_violation(@ip, @analysis) }
      assert_equal 2, Beskar::Services::Waf.get_violation_count(@ip)
      assert Beskar::BannedIp.banned?(@ip)
    end
  end

  test "counters isolate IPs and accounts while sharing global capacity" do
    Beskar.configuration.rate_limiting[:global_attempts][:enabled] = true
    user = create(:devise_user)
    other = create(:devise_user)
    @limiter.check_authentication_attempt(@request, :failure, user)
    assert_equal 1, @limiter.check_ip_rate_limit(@ip)[:count]
    assert_equal 0, @limiter.check_ip_rate_limit("198.51.100.41")[:count]
    assert_equal 1, @limiter.check_account_rate_limit(user)[:count]
    assert_equal 0, @limiter.check_account_rate_limit(other)[:count]
    assert_equal 1, @limiter.check_global_rate_limit[:count]
  end

  test "read only checks do not change state or escalate retry deadlines" do
    freeze_time do
      10.times { @limiter.check_authentication_attempt(@request, :failure) }
      before = Beskar::SecurityState.order(:key).pluck(:key, :data, :updated_at, :lock_version)
      expected = @limiter.time_until_allowed(@request)
      assert_equal 1.hour, expected
      3.times do
        assert @limiter.is_rate_limited?(@request)
        assert_equal expected, @limiter.time_until_allowed(@request)
      end
      assert_equal before, Beskar::SecurityState.order(:key).pluck(:key, :data, :updated_at, :lock_version)
    end
  end

  test "global backoff has a separate deadline and survives the counting window" do
    Beskar.configuration.rate_limiting[:global_attempts] = {enabled: true, limit: 1, period: 1.second, exponential_backoff: true}
    freeze_time do
      assert @limiter.check_authentication_attempt(@request, :failure)[:allowed]
      first = @limiter.check_authentication_attempt(@request, :failure)
      second = @limiter.check_authentication_attempt(@request, :failure)
      assert_equal 60, first[:retry_after]
      assert_equal 300, second[:retry_after]
      travel 2.seconds
      assert_not @limiter.check_global_rate_limit[:allowed]
      assert_equal 298, @limiter.check_global_rate_limit[:retry_after]
      travel 299.seconds
      assert @limiter.check_global_rate_limit[:allowed]
    end
  end

  test "long configured windows survive cache eviction and use the longest denial" do
    user = create(:devise_user)
    Beskar.configuration.rate_limiting[:account_attempts] = {limit: 1, period: 2.days, exponential_backoff: false}
    freeze_time do
      @limiter.check_authentication_attempt(@request, :failure, user)
      Rails.cache.clear
      travel 2.hours
      result = @limiter.check_authentication_attempt(@request, :check, user)
      assert_not result[:allowed]
      assert_equal :account_attempts, result[:tier]
      assert_equal 46.hours, result[:retry_after]
      @limiter.reset_rate_limit(ip_address: @ip, user: user, global: true)
      assert @limiter.check_authentication_attempt(@request, :check, user)[:allowed]
    end
  end

  test "monitor observations do not become active counters or bans" do
    Beskar.configuration.monitor_only = true
    10.times { @limiter.check_authentication_attempt(@request, :failure) }
    2.times { Beskar::Services::Waf.record_violation(@ip, @analysis) }
    assert_not @limiter.check_ip_rate_limit(@ip)[:allowed]
    assert_not Beskar::BannedIp.banned?(@ip)
    assert Beskar::SecurityEvent.last.metadata["would_be_blocked"]
    Beskar.configuration.monitor_only = false
    assert @limiter.check_ip_rate_limit(@ip)[:allowed]
    assert_equal 0, Beskar::Services::Waf.get_current_score(@ip)
    assert_not Beskar::BannedIp.banned?(@ip)
  end

  test "WAF observations respect whitelist and auto block policy in audit events" do
    Beskar.configuration.waf[:score_threshold] = 1
    Beskar::Services::Waf.record_violation(@ip, @analysis, whitelisted: true)
    assert_not Beskar::SecurityEvent.last.metadata["would_be_blocked"]
    assert_not Beskar::BannedIp.banned?(@ip)
    Beskar.configuration.waf[:auto_block] = false
    Beskar::Services::Waf.record_violation(@ip, @analysis)
    assert_not Beskar::SecurityEvent.last.metadata["would_be_blocked"]
    assert_not Beskar::BannedIp.banned?(@ip)
  end

  test "WAF reads prune expired entries even when newer violations keep the row alive" do
    Beskar.configuration.waf.merge!(auto_block: false, violation_window: 1.hour)
    freeze_time do
      Beskar::Services::Waf.record_violation(@ip, @analysis)
      travel 30.minutes
      Beskar::Services::Waf.record_violation(@ip, @analysis)
      travel 31.minutes
      assert_equal 1, Beskar::Services::Waf.get_violation_count(@ip)
      assert_equal 95, Beskar::Services::Waf.get_current_score(@ip)
    end
  end

  test "ban decisions ignore stale cache values and respect transaction rollback" do
    key = "beskar:banned_ip:#{@ip}"
    Rails.cache.write(key, true)
    assert_not Beskar::BannedIp.banned?(@ip)
    Beskar::BannedIp.transaction(requires_new: true) do
      Beskar::BannedIp.ban!(@ip, reason: "test")
      assert Beskar::BannedIp.banned?(@ip)
      raise ActiveRecord::Rollback
    end
    assert_not Beskar::BannedIp.banned?(@ip)
    ban = Beskar::BannedIp.ban!(@ip, reason: "test")
    Rails.cache.write(key, false)
    assert Beskar::BannedIp.banned?(@ip)
    ban.update!(ip_address: "198.51.100.41")
    assert_not Beskar::BannedIp.banned?(@ip)
    assert Beskar::BannedIp.banned?(ban.ip_address)
    ban.update!(expires_at: 1.second.ago)
    assert_not Beskar::BannedIp.banned?(ban.ip_address)
  end

  test "permanent bans survive legacy expiry timestamps and cleanup" do
    ban = Beskar::BannedIp.ban!(@ip, reason: "test", permanent: true)
    ban.update_columns(expires_at: 1.day.ago)
    Rails.cache.clear
    assert Beskar::BannedIp.banned?(@ip)
    Beskar::BannedIp.cleanup_expired!
    assert ban.reload.permanent?
    ban.save!
    assert_nil ban.expires_at
  end

  test "temporary bans require an expiry and cannot have malformed or CIDR addresses" do
    ban = Beskar::BannedIp.new(ip_address: @ip, reason: "test", banned_at: Time.current)
    assert_not ban.valid?
    assert_includes ban.errors[:expires_at], "can't be blank"
    assert_raises(ArgumentError) { Beskar::BannedIp.ban!(@ip, reason: "test", duration: -1) }
    assert_raises(ArgumentError) { Beskar::BannedIp.ban!("198.51.100.0/24", reason: "test") }
    assert_raises(IPAddr::InvalidAddressError) { Beskar::BannedIp.ban!("garbage", reason: "test") }
  end

  test "existing temporary ban can be upgraded to permanent explicitly" do
    Beskar::BannedIp.ban!(@ip, reason: "test")
    ban = Beskar::BannedIp.ban!(@ip, reason: "escalated", permanent: true)
    assert ban.permanent?
    assert_nil ban.expires_at
  end

  test "canonical IPv6 addresses share the same ban and counter" do
    ip = "2001:0db8:0000:0000:0000:0000:0000:0040"
    Beskar::BannedIp.ban!(ip, reason: "test")
    assert Beskar::BannedIp.banned?("2001:db8::40")
    @limiter.send(:record_attempt, ip, :failure, nil)
    assert_equal 1, @limiter.check_ip_rate_limit("2001:db8::40")[:count]
  end

  test "whitelist follows runtime configuration replacement and mutation" do
    whitelist = Beskar::Services::IpWhitelist
    Beskar.configuration.ip_whitelist = [@ip]
    assert whitelist.whitelisted?(@ip)
    Beskar.configuration.ip_whitelist.clear
    assert_not whitelist.whitelisted?(@ip)
    Beskar.configuration.ip_whitelist = ["198.51.100.0/24"]
    assert whitelist.whitelisted?(@ip)
  end

  test "rate limiting and audit attribution use Rails resolved client IP" do
    @request.env["action_dispatch.remote_ip"] = "203.0.113.40"
    user = create(:devise_user)
    event = user.track_authentication_event(@request, :success)
    assert_equal "203.0.113.40", event.ip_address
    assert_equal 1, @limiter.check_ip_rate_limit("203.0.113.40")[:count]
    assert_equal 0, @limiter.check_ip_rate_limit(@ip)[:count]
  end

  test "blocked middleware responses satisfy Rack 3 and honor trusted proxy resolution" do
    require "rack/lint"
    Beskar::BannedIp.ban!("203.0.113.40", reason: "test")
    endpoint = Beskar::Middleware::RequestAnalyzer.new(->(_) { [200, {}, ["OK"]] })
    app = ActionDispatch::RemoteIp.new(endpoint, true, [IPAddr.new("198.51.100.0/24")])
    env = Rack::MockRequest.env_for("/", "REMOTE_ADDR" => @ip, "HTTP_X_FORWARDED_FOR" => "203.0.113.40")
    status, headers, body = Rack::Lint.new(app).call(env)
    assert_equal 403, status
    assert_equal "true", headers["x-beskar-blocked"]
    body.each { |chunk| assert_kind_of String, chunk }
  end

  test "middleware retry header reflects the configured counting window" do
    require "rack/lint"
    Beskar.configuration.waf[:enabled] = false
    Beskar.configuration.rate_limiting[:ip_attempts] = {block_requests: true, limit: 1, period: 90.seconds, exponential_backoff: false}
    freeze_time do
      @limiter.check_authentication_attempt(@request, :failure)
      endpoint = Beskar::Middleware::RequestAnalyzer.new(->(_) { [200, {}, ["OK"]] })
      env = Rack::MockRequest.env_for("/", "REMOTE_ADDR" => @ip)
      status, headers, body = Rack::Lint.new(endpoint).call(env)
      assert_equal 429, status
      assert_equal "90", headers["retry-after"]
      body.each { |chunk| assert_kind_of String, chunk }
    end
  end

  test "repeated monitor rate denials cannot create active bans" do
    Beskar.configuration.monitor_only = true
    10.times { @limiter.check_authentication_attempt(@request, :failure) }
    endpoint = Beskar::Middleware::RequestAnalyzer.new(->(_) { [200, {}, ["OK"]] })
    6.times do
      status, = endpoint.call(Rack::MockRequest.env_for("/", "REMOTE_ADDR" => @ip))
      assert_equal 200, status
    end
    assert_not Beskar::BannedIp.banned?(@ip)
    Beskar.configuration.monitor_only = false
    status, = endpoint.call(Rack::MockRequest.env_for("/", "REMOTE_ADDR" => @ip))
    assert_equal 200, status
  end

  test "missing or empty dashboard credentials never match" do
    matcher = Beskar::Services::RequestContext
    assert_not matcher.secure_match?(nil, nil)
    assert_not matcher.secure_match?("", "")
    assert_not matcher.secure_match?("supplied", nil)
    assert_not matcher.secure_match?(nil, "configured")
    assert_not matcher.secure_match?("wrong", "configured")
    assert matcher.secure_match?("configured", "configured")
  end

  test "expired state cleanup does not delete live state or audit evidence" do
    Beskar::SecurityState.create!(key: "expired", expires_at: 1.second.ago)
    Beskar::SecurityState.create!(key: "live", expires_at: 1.hour.from_now)
    assert_no_difference "Beskar::SecurityEvent.count" do
      assert_equal 1, Beskar::SecurityState.cleanup_expired!
    end
    assert Beskar::SecurityState.exists?(key: "live")
    assert_not Beskar::SecurityState.exists?(key: "expired")
  end

  test "a failed multi key mutation rolls back every counter" do
    assert_raises(RuntimeError) do
      Beskar::SecurityState.mutate(["first", "second"], ttl: 1.hour) do |state|
        state["first"]["count"] = 1
        state["second"]["count"] = 1
        raise "operation failed"
      end
    end
    assert_equal({}, Beskar::SecurityState.read("first"))
    assert_equal({}, Beskar::SecurityState.read("second"))
  end

  test "transient optimistic lock conflicts retry without double counting" do
    calls = 0
    Beskar::SecurityState.mutate("retry-test", ttl: 1.hour) do |state|
      calls += 1
      state["retry-test"]["count"] = state["retry-test"].fetch("count", 0) + 1
      raise ActiveRecord::StaleObjectError.new(nil, "update") if calls == 1
    end
    assert_equal 2, calls
    assert_equal 1, Beskar::SecurityState.read("retry-test")["count"]
  end

  test "instance rate limit checks include global capacity" do
    Beskar.configuration.rate_limiting[:global_attempts] = {enabled: true, limit: 1, period: 1.minute}
    @limiter.check_authentication_attempt(@request, :failure)
    instance = @limiter.new("203.0.113.50")
    assert_not instance.allowed?
    assert_equal 0, instance.attempts_remaining
    assert_operator instance.time_until_reset, :>, 0
  end

  test "resetting IP rate state also clears middleware denial counts" do
    key = "rate_denials:enforce:#{@ip}"
    Beskar::SecurityState.mutate(key, ttl: 1.hour) { |state| state[key]["count"] = 4 }
    @limiter.reset_rate_limit(ip_address: @ip)
    assert_equal({}, Beskar::SecurityState.read(key))
  end
end
