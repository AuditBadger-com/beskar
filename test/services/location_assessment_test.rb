require "test_helper"

class LocationAssessmentTest < ActiveSupport::TestCase
  setup do
    @ny = {country: "United States", country_code: "US", latitude: 40.7128, longitude: -74.0060, provider: "maxmind"}
    @london = {country: "United Kingdom", country_code: "GB", latitude: 51.5074, longitude: -0.1278, provider: "maxmind"}
    @service = Beskar::Services::GeolocationService.new
  end

  test "JSON locations and ISO observations preserve actual elapsed travel evidence" do
    at = Time.current
    result = assess(@london.deep_stringify_keys, [{location: @ny.deep_stringify_keys, occurred_at: (at - 60).iso8601(6), event_id: 42}], at: at)
    assert_equal 30, result[:score]
    assert result[:location][:impossible_travel]
    assert result[:location][:country_change]
    assert_in_delta 60, result[:location][:travel][:elapsed_seconds], 0.001
    assert_equal 42, result[:location][:travel][:previous_event_id]
    assert_in_delta 5580, result[:location][:travel][:distance_km], 20
    assert_equal result[:score], result[:factors].sum { |factor| factor[:points] }
  end

  test "latest observation owns its timestamp regardless of insertion order" do
    at = Time.current
    result = assess(@london, [
      {location: @ny, occurred_at: at - 30, event_id: 1},
      {location: @london, occurred_at: at - 60, event_id: 9}
    ], at: at)
    assert result[:location][:impossible_travel]
    assert_equal 30, result[:location][:travel][:elapsed_seconds]
    assert_equal 1, result[:location][:travel][:previous_event_id]
  end

  test "future equal and malformed timestamps are not travel evidence" do
    at = Time.current
    [at + 60, at, nil, "not a date", Float::INFINITY].each do |time|
      result = assess(@london, [{location: @ny, occurred_at: time}], at: at)
      refute result[:location][:impossible_travel]
      refute result[:location][:country_change]
      assert_equal 0, result[:score]
    end
  end

  test "invalid coordinates and elapsed durations never invent travel" do
    [nil, "garbage", Float::NAN, Float::INFINITY, 91, -91].each do |latitude|
      refute @service.impossible_travel?(@ny.merge(latitude: latitude), @london, 60)
      normalized = Beskar::Services::LocationAssessment.normalize(@ny.merge(latitude: latitude))
      assert_nil normalized[:latitude]
      assert_nil normalized[:longitude]
      assert_nothing_raised { normalized.to_json }
    end
    [nil, "garbage", Float::INFINITY, 181, -181].each do |longitude|
      refute @service.impossible_travel?(@ny.merge(longitude: longitude), @london, 60)
    end
    [nil, -60, 0, "bad", Float::INFINITY].each do |elapsed|
      refute @service.impossible_travel?(@ny, @london, elapsed)
    end
    assert @service.impossible_travel?(@ny.deep_stringify_keys, @london.deep_stringify_keys, 60)
  end

  test "same coordinates and sufficient travel time remain benign" do
    refute @service.impossible_travel?(@ny, @ny, 60)
    refute @service.impossible_travel?(@ny, @london, 10.hours)
    assert_in_delta 20_015, @service.class.calculate_distance(90.0, 0.0, -90.0, 180.0), 1
  end

  test "unknown private and synthetic locations are not country or travel proof" do
    [@ny.merge(country: "Unknown", latitude: nil, longitude: nil),
      @ny.merge(country: "Private", private_ip: true), @ny.merge(provider: "mock")].each do |location|
      result = assess(location, [{location: @london, occurred_at: 1.minute.ago}])
      refute result[:location][:impossible_travel]
      refute result[:location][:country_change]
    end
    result = assess(@london, [{location: @ny.merge(provider: "mock"), occurred_at: 1.minute.ago}])
    assert_equal 0, result[:score]
    refute result[:location][:impossible_travel]
  end

  test "country equality uses consistent keys and case not missing symbol values" do
    result = assess(@ny, [{location: @ny.deep_stringify_keys.merge("country_code" => "us"), occurred_at: 1.minute.ago}])
    assert_equal 0, result[:score]
    refute result[:location][:country_change]
  end

  test "mock cache cannot contaminate a different provider" do
    Rails.stubs(:cache).returns(ActiveSupport::Cache::MemoryStore.new)
    mock = Beskar::Services::GeolocationService.new(provider: :mock)
    real = Beskar::Services::GeolocationService.new(provider: :maxmind)
    real.stubs(:lookup_maxmind).returns(@ny)
    mock.locate("198.51.100.10")
    assert_equal @ny, real.locate("198.51.100.10")
  end

  test "unsupported providers are rejected instead of silently fabricating or omitting geography" do
    [:typo, :ip2location].each do |provider|
      assert_raises(Beskar::Configuration::Error) { Beskar::Services::GeolocationService.new(provider: provider) }
    end
  end

  test "geolocation assessment works with null and unavailable optional caches" do
    broken = mock("unavailable cache")
    broken.stubs(:read).raises("cache unavailable")
    broken.stubs(:write).raises("cache unavailable")
    [ActiveSupport::Cache::NullStore.new, broken].each do |cache|
      Rails.stubs(:cache).returns(cache)
      service = Beskar::Services::GeolocationService.new(provider: :maxmind)
      service.stubs(:lookup_maxmind).returns(@london)
      result = service.assess_location("198.51.100.1", observations: [{location: @ny, occurred_at: 1.minute.ago}])
      assert_equal 30, result[:score]
      assert result[:location][:impossible_travel]
    end
  end

  test "default public mock locations never add geographic risk" do
    result = @service.assess_location("198.51.100.1", observations: [{location: @ny, occurred_at: 1.minute.ago}])
    assert_equal "synthetic", result[:location][:assessment_status]
    assert_equal 0, result[:score]
    refute result[:location][:impossible_travel]
    refute result[:location][:country_change]
  end

  test "reader and cache namespace follow database identity changes" do
    service = Beskar::Services::GeolocationService
    path = Rails.root.join("geo-generation-test.mmdb").to_s
    File.stubs(:file?).with(path).returns(true)
    reader1, reader2 = Object.new, Object.new
    MaxMindDB.expects(:new).with(path).twice.returns(reader1, reader2)
    assert_same reader1, service.city_reader([path, 1, 10, "v1"])
    assert_same reader1, service.city_reader([path, 1, 10, "v1"])
    assert_same reader2, service.city_reader([path, 2, 10, "v2"])
    service.stubs(:database_identity).returns([path, 1, 10, "v1"])
    first = service.new(provider: :maxmind).instance_variable_get(:@cache_key_prefix)
    service.stubs(:database_identity).returns([path, 2, 10, "v2"])
    refute_equal first, service.new(provider: :maxmind).instance_variable_get(:@cache_key_prefix)
  ensure
    service.reset_readers!
  end

  private

  def assess(location, observations, at: Time.current)
    Beskar::Services::LocationAssessment.new(location, observations: observations, at: at).call
  end
end
