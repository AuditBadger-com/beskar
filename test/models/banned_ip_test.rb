require "test_helper"

class BannedIpTest < ActiveSupport::TestCase
  def setup
    Rails.cache.clear
    Beskar::BannedIp.destroy_all
  end

  def teardown
    Rails.cache.clear
    Beskar::BannedIp.destroy_all
  end

  # Basic model validation
  test "creates valid banned IP" do
    banned_ip = Beskar::BannedIp.create!(
      ip_address: "192.168.1.100",
      reason: "test_ban",
      banned_at: Time.current,
      expires_at: Time.current + 1.hour
    )

    assert banned_ip.persisted?
    assert_equal "192.168.1.100", banned_ip.ip_address
    assert_equal "test_ban", banned_ip.reason
  end

  test "requires ip_address" do
    banned_ip = Beskar::BannedIp.new(reason: "test", banned_at: Time.current)

    assert_not banned_ip.valid?
    assert_includes banned_ip.errors[:ip_address], "can't be blank"
  end

  test "requires reason" do
    banned_ip = Beskar::BannedIp.new(ip_address: "192.168.1.100", banned_at: Time.current)

    assert_not banned_ip.valid?
    assert_includes banned_ip.errors[:reason], "can't be blank"
  end

  test "requires unique ip_address" do
    Beskar::BannedIp.create!(
      ip_address: "192.168.1.100",
      reason: "first",
      banned_at: Time.current,
      expires_at: 1.hour.from_now
    )

    duplicate = Beskar::BannedIp.new(
      ip_address: "192.168.1.100",
      reason: "second",
      banned_at: Time.current
    )

    assert_not duplicate.valid?
    assert_includes duplicate.errors[:ip_address], "has already been taken"
  end

  # Scopes
  test "active scope returns only active bans" do
    active_ban = Beskar::BannedIp.create!(
      ip_address: "10.0.0.1",
      reason: "active",
      banned_at: Time.current,
      expires_at: Time.current + 1.hour
    )

    expired_ban = Beskar::BannedIp.create!(
      ip_address: "10.0.0.2",
      reason: "expired",
      banned_at: Time.current - 2.hours,
      expires_at: Time.current - 1.hour
    )

    permanent_ban = Beskar::BannedIp.create!(
      ip_address: "10.0.0.3",
      reason: "permanent",
      banned_at: Time.current,
      permanent: true
    )

    active_bans = Beskar::BannedIp.active

    assert_includes active_bans, active_ban
    assert_includes active_bans, permanent_ban
    assert_not_includes active_bans, expired_ban
  end

  test "permanent scope returns only permanent bans" do
    permanent = Beskar::BannedIp.create!(
      ip_address: "10.0.0.10",
      reason: "permanent",
      banned_at: Time.current,
      permanent: true
    )

    temporary = Beskar::BannedIp.create!(
      ip_address: "10.0.0.11",
      reason: "temporary",
      banned_at: Time.current,
      expires_at: Time.current + 1.hour
    )

    permanent_bans = Beskar::BannedIp.permanent

    assert_includes permanent_bans, permanent
    assert_not_includes permanent_bans, temporary
  end

  test "expired scope returns only expired bans" do
    expired = Beskar::BannedIp.create!(
      ip_address: "10.0.0.20",
      reason: "expired",
      banned_at: Time.current - 2.hours,
      expires_at: Time.current - 1.hour
    )

    active = Beskar::BannedIp.create!(
      ip_address: "10.0.0.21",
      reason: "active",
      banned_at: Time.current,
      expires_at: Time.current + 1.hour
    )

    expired_bans = Beskar::BannedIp.expired

    assert_includes expired_bans, expired
    assert_not_includes expired_bans, active
  end

  # Instance methods
  test "active? returns true for non-expired temporary ban" do
    ban = Beskar::BannedIp.create!(
      ip_address: "10.0.0.30",
      reason: "test",
      banned_at: Time.current,
      expires_at: Time.current + 1.hour
    )

    assert ban.active?
  end

  test "active? returns false for expired temporary ban" do
    ban = Beskar::BannedIp.create!(
      ip_address: "10.0.0.31",
      reason: "test",
      banned_at: Time.current - 2.hours,
      expires_at: Time.current - 1.hour
    )

    assert_not ban.active?
  end

  test "active? returns true for permanent ban" do
    ban = Beskar::BannedIp.create!(
      ip_address: "10.0.0.32",
      reason: "test",
      banned_at: Time.current,
      permanent: true
    )

    assert ban.active?
  end

  test "expired? returns true for expired ban" do
    ban = Beskar::BannedIp.create!(
      ip_address: "10.0.0.33",
      reason: "test",
      banned_at: Time.current - 2.hours,
      expires_at: Time.current - 1.hour
    )

    assert ban.expired?
  end

  test "expired? returns false for active ban" do
    ban = Beskar::BannedIp.create!(
      ip_address: "10.0.0.34",
      reason: "test",
      banned_at: Time.current,
      expires_at: Time.current + 1.hour
    )

    assert_not ban.expired?
  end

  test "expired? returns false for permanent ban" do
    ban = Beskar::BannedIp.create!(
      ip_address: "10.0.0.35",
      reason: "test",
      banned_at: Time.current,
      permanent: true
    )

    assert_not ban.expired?
  end

  # extend_ban!
  test "extend_ban! increments violation_count" do
    ban = Beskar::BannedIp.create!(
      ip_address: "10.0.0.40",
      reason: "test",
      banned_at: Time.current,
      expires_at: Time.current + 1.hour,
      violation_count: 1
    )

    assert_equal 1, ban.violation_count

    ban.extend_ban!

    assert_equal 2, ban.reload.violation_count
  end

  test "extend_ban! extends duration with custom time" do
    ban = Beskar::BannedIp.create!(
      ip_address: "10.0.0.41",
      reason: "test",
      banned_at: Time.current,
      expires_at: Time.current + 1.hour
    )

    original_expiry = ban.expires_at

    ban.extend_ban!(2.hours)

    assert ban.reload.expires_at > original_expiry
  end

  test "extend_ban! escalates to permanent after many violations" do
    ban = Beskar::BannedIp.create!(
      ip_address: "10.0.0.42",
      reason: "test",
      banned_at: Time.current,
      expires_at: Time.current + 1.hour,
      violation_count: 4
    )

    assert_not ban.permanent?

    ban.extend_ban! # This should make it permanent (violation 5)

    assert ban.reload.permanent?
  end

  # Class methods - ban!
  test "ban! creates new ban" do
    assert_difference "Beskar::BannedIp.count", 1 do
      Beskar::BannedIp.ban!(
        "10.0.0.50",
        reason: "test_reason",
        duration: 1.hour
      )
    end

    ban = Beskar::BannedIp.last
    assert_equal "10.0.0.50", ban.ip_address
    assert_equal "test_reason", ban.reason
  end

  test "ban! extends existing ban" do
    existing = Beskar::BannedIp.create!(
      ip_address: "10.0.0.51",
      reason: "original",
      banned_at: Time.current,
      expires_at: Time.current + 1.hour,
      violation_count: 1
    )

    assert_no_difference "Beskar::BannedIp.count" do
      Beskar::BannedIp.ban!(
        "10.0.0.51",
        reason: "extended",
        duration: 2.hours
      )
    end

    existing.reload
    assert_equal 2, existing.violation_count
  end

  test "ban! creates permanent ban when specified" do
    Beskar::BannedIp.ban!(
      "10.0.0.52",
      reason: "serious_violation",
      permanent: true
    )

    ban = Beskar::BannedIp.find_by(ip_address: "10.0.0.52")
    assert ban.permanent?
    assert_nil ban.expires_at
  end

  test "ban! stores metadata" do
    metadata = {user_agent: "BadBot/1.0", path: "/wp-admin"}

    Beskar::BannedIp.ban!(
      "10.0.0.53",
      reason: "waf_violation",
      duration: 1.hour,
      metadata: metadata
    )

    ban = Beskar::BannedIp.find_by(ip_address: "10.0.0.53")
    assert_equal "BadBot/1.0", ban.metadata["user_agent"]
    assert_equal "/wp-admin", ban.metadata["path"]
  end

  test "ban! enforces without populating cache" do
    ip = "10.0.0.54"

    Beskar::BannedIp.ban!(ip, reason: "test", duration: 1.hour)

    cache_key = "beskar:banned_ip:#{ip}"
    assert_nil Rails.cache.read(cache_key)
    assert Beskar::BannedIp.banned?(ip)
  end

  test "ban! handles race condition when multiple threads ban same IP simultaneously" do
    ip = "10.0.0.55"
    results = []
    errors = []

    # Simulate race condition with actual threads
    threads = 3.times.map do |i|
      Thread.new do
        result = Beskar::BannedIp.ban!(
          ip,
          reason: "thread_#{i}",
          duration: 1.hour
        )
        results << result
      rescue => e
        errors << e
      end
    end

    # Wait for all threads to complete
    threads.each(&:join)

    # All threads should succeed (no errors due to race condition)
    assert errors.empty?, "Expected no errors, but got: #{errors.map(&:message)}"
    assert_equal 3, results.size

    # Should only have one record for this IP (all threads updated the same record)
    assert_equal 1, Beskar::BannedIp.where(ip_address: ip).count

    # Violation count should be 3 (initial + 2 extensions)
    ban = Beskar::BannedIp.find_by(ip_address: ip)
    assert_equal 3, ban.violation_count
  end

  test "ban! handles concurrent bans for different IPs without issues" do
    results = []
    errors = []

    # Create concurrent bans for different IPs
    threads = 5.times.map do |i|
      Thread.new do
        ip = "10.0.0.#{60 + i}"
        result = Beskar::BannedIp.ban!(ip, reason: "concurrent_test", duration: 1.hour)
        results << result
      rescue => e
        errors << e
      end
    end

    threads.each(&:join)

    # All threads should succeed
    assert errors.empty?, "Expected no errors, but got: #{errors.map(&:message)}"
    assert_equal 5, results.size

    # Should have 5 distinct records
    assert_equal 5, Beskar::BannedIp.where("ip_address LIKE '10.0.0.6%'").count
  end

  # Class methods - banned?
  test "banned? returns true for banned IP" do
    ip = "10.0.0.60"
    Beskar::BannedIp.ban!(ip, reason: "test", duration: 1.hour)

    assert Beskar::BannedIp.banned?(ip)
  end

  test "banned? returns false for non-banned IP" do
    assert_not Beskar::BannedIp.banned?("10.0.0.61")
  end

  test "banned? returns false for expired ban" do
    ip = "10.0.0.62"
    Beskar::BannedIp.create!(
      ip_address: ip,
      reason: "test",
      banned_at: Time.current - 2.hours,
      expires_at: Time.current - 1.hour
    )

    assert_not Beskar::BannedIp.banned?(ip)
  end

  test "banned? ignores stale negative cache entries" do
    ip = "10.0.0.63"
    Beskar::BannedIp.ban!(ip, reason: "test", duration: 1.hour)

    assert Beskar::BannedIp.banned?(ip)
    Rails.cache.write("beskar:banned_ip:#{ip}", false)
    assert Beskar::BannedIp.banned?(ip)
  end

  test "banned? does not cache negative results" do
    ip = "10.0.0.64"

    assert_not Beskar::BannedIp.banned?(ip)
    cache_key = "beskar:banned_ip:#{ip}"
    assert_nil Rails.cache.read(cache_key)
  end

  # Class methods - unban!
  test "unban! removes ban and clears cache" do
    ip = "10.0.0.70"
    Beskar::BannedIp.ban!(ip, reason: "test", duration: 1.hour)

    assert Beskar::BannedIp.banned?(ip)

    assert_difference "Beskar::BannedIp.count", -1 do
      result = Beskar::BannedIp.unban!(ip)
      assert result
    end

    assert_not Beskar::BannedIp.banned?(ip)
  end

  test "unban! returns false for non-existent ban" do
    result = Beskar::BannedIp.unban!("10.0.0.71")
    assert_not result
  end

  # Class methods - preload_cache!
  test "legacy preload_cache! is optional and does not affect enforcement" do
    Rails.cache.clear

    # Create some bans
    Beskar::BannedIp.create!(
      ip_address: "10.0.0.80",
      reason: "test",
      banned_at: Time.current,
      expires_at: Time.current + 1.hour
    )

    Beskar::BannedIp.create!(
      ip_address: "10.0.0.81",
      reason: "test",
      banned_at: Time.current,
      permanent: true
    )

    Beskar::BannedIp.create!(
      ip_address: "10.0.0.82",
      reason: "test",
      banned_at: Time.current - 2.hours,
      expires_at: Time.current - 1.hour
    )

    Beskar::BannedIp.preload_cache!

    assert Beskar::BannedIp.banned?("10.0.0.80")
    assert Beskar::BannedIp.banned?("10.0.0.81")
    assert_not Beskar::BannedIp.banned?("10.0.0.82")
    assert_nil Rails.cache.read("beskar:banned_ip:10.0.0.80")
  end

  # Class methods - cleanup_expired!
  test "cleanup_expired! removes expired bans" do
    active = Beskar::BannedIp.create!(
      ip_address: "10.0.0.90",
      reason: "test",
      banned_at: Time.current,
      expires_at: Time.current + 1.hour
    )

    expired1 = Beskar::BannedIp.create!(
      ip_address: "10.0.0.91",
      reason: "test",
      banned_at: Time.current - 3.hours,
      expires_at: Time.current - 2.hours
    )

    expired2 = Beskar::BannedIp.create!(
      ip_address: "10.0.0.92",
      reason: "test",
      banned_at: Time.current - 2.hours,
      expires_at: Time.current - 1.hour
    )

    assert_difference "Beskar::BannedIp.count", -2 do
      Beskar::BannedIp.cleanup_expired!
    end

    assert Beskar::BannedIp.exists?(active.id)
    assert_not Beskar::BannedIp.exists?(expired1.id)
    assert_not Beskar::BannedIp.exists?(expired2.id)
  end

  # Metadata serialization
  test "metadata is serialized as JSON" do
    ban = Beskar::BannedIp.create!(
      ip_address: "10.0.0.100",
      reason: "test",
      banned_at: Time.current,
      expires_at: 1.hour.from_now,
      metadata: {key: "value", nested: {data: "test"}}
    )

    ban.reload
    assert_equal "value", ban.metadata["key"]
    assert_equal "test", ban.metadata["nested"]["data"]
  end

  test "metadata is initialized as empty hash" do
    ban = Beskar::BannedIp.new(
      ip_address: "10.0.0.101",
      reason: "test",
      banned_at: Time.current
    )

    assert_equal Hash, ban.metadata.class
    assert ban.metadata.empty?
  end
end
