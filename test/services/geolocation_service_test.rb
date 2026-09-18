require "test_helper"

module Beskar
  module Services
    class GeolocationServiceTest < ActiveSupport::TestCase
      def setup
        Rails.cache.clear
        @service = Beskar::Services::GeolocationService.new
      end

      # Test basic location detection
      test "locates public IP address" do
        ip = "203.0.113.1"
        result = @service.locate(ip)

        assert result.is_a?(Hash)
        assert_equal ip, result[:ip]
        assert result.key?(:country)
        assert result.key?(:city)
        assert result.key?(:latitude)
        assert result.key?(:longitude)
        assert_equal false, result[:private_ip]
      end

      test "handles private IP addresses" do
        private_ips = [
          "127.0.0.1",
          "192.168.1.1",
          "10.0.0.1",
          "172.16.0.1",
          "169.254.1.1"
        ]

        private_ips.each do |ip|
          result = @service.locate(ip)

          assert_equal ip, result[:ip]
          assert_equal "Private", result[:country]
          assert_equal "Local Network", result[:city]
          assert_nil result[:latitude]
          assert_nil result[:longitude]
          assert_equal true, result[:private_ip]
        end
      end

      test "handles IPv6 addresses" do
        ipv6_addresses = [
          "::1",  # Loopback
          "fe80::1",  # Link-local
          "fc00::1"   # Unique local
        ]

        ipv6_addresses.each do |ip|
          result = @service.locate(ip)
          assert_equal true, result[:private_ip], "Should treat #{ip} as private"
        end
      end

      test "handles blank IP addresses" do
        ["", nil, "   "].each do |ip|
          result = @service.locate(ip)
          assert_equal true, result[:private_ip]
        end
      end

      test "handles invalid IP addresses" do
        invalid_ips = [
          "not.an.ip",
          "999.999.999.999",
          "256.1.1.1",
          "192.168.1"
        ]

        invalid_ips.each do |ip|
          result = @service.locate(ip)
          assert_equal true, result[:private_ip], "Should treat invalid IP #{ip} as private"
        end
      end

      # Test class methods
      test "private_ip? class method works correctly" do
        assert_equal true, Beskar::Services::GeolocationService.private_ip?("127.0.0.1")
        assert_equal true, Beskar::Services::GeolocationService.private_ip?("192.168.1.1")
        assert_equal false, Beskar::Services::GeolocationService.private_ip?("203.0.113.1")
        assert_equal true, Beskar::Services::GeolocationService.private_ip?("")
        assert_equal true, Beskar::Services::GeolocationService.private_ip?(nil)
        assert_equal true, Beskar::Services::GeolocationService.private_ip?("invalid.ip")
      end

      test "locate class method works as convenience method" do
        ip = "203.0.113.1"
        result = Beskar::Services::GeolocationService.locate(ip)

        assert result.is_a?(Hash)
        assert_equal ip, result[:ip]
      end

      test "calculate_distance returns correct distance" do
        # Distance between New York and Los Angeles (approximately 3935 km)
        ny_lat, ny_lon = 40.7128, -74.0060
        la_lat, la_lon = 34.0522, -118.2437

        distance = Beskar::Services::GeolocationService.calculate_distance(ny_lat, ny_lon, la_lat, la_lon)

        # Should be approximately 3935 km
        assert distance > 3900
        assert distance < 4000
      end

      test "calculate_distance handles nil coordinates" do
        assert_equal 0.0, Beskar::Services::GeolocationService.calculate_distance(nil, nil, 40.0, -74.0)
        assert_equal 0.0, Beskar::Services::GeolocationService.calculate_distance(40.0, -74.0, nil, nil)
        assert_equal 0.0, Beskar::Services::GeolocationService.calculate_distance(nil, -74.0, 40.0, nil)
      end

      test "calculate_distance returns zero for same coordinates" do
        distance = Beskar::Services::GeolocationService.calculate_distance(40.0, -74.0, 40.0, -74.0)
        assert_equal 0.0, distance
      end

      # Test impossible travel detection
      test "impossible_travel? detects impossible travel" do
        # New York to London is about 5585 km
        ny_location = {latitude: 40.7128, longitude: -74.0060}
        london_location = {latitude: 51.5074, longitude: -0.1278}

        # 1 hour is not enough time to travel from NY to London
        one_hour = 3600
        assert_equal true, @service.impossible_travel?(ny_location, london_location, one_hour)

        # 10 hours should be enough time (commercial flight)
        ten_hours = 36000
        assert_equal false, @service.impossible_travel?(ny_location, london_location, ten_hours)
      end

      test "impossible_travel? handles nil locations" do
        location = {latitude: 40.0, longitude: -74.0}

        assert_equal false, @service.impossible_travel?(nil, location, 3600)
        assert_equal false, @service.impossible_travel?(location, nil, 3600)
        assert_equal false, @service.impossible_travel?(nil, nil, 3600)
      end

      test "impossible_travel? handles locations without coordinates" do
        location1 = {country: "US"}
        location2 = {latitude: 40.0, longitude: -74.0}

        assert_equal false, @service.impossible_travel?(location1, location2, 3600)
      end

      test "impossible_travel? allows reasonable travel" do
        # NYC to Philadelphia is about 130 km - should be possible in 2 hours
        nyc = {latitude: 40.7128, longitude: -74.0060}
        philly = {latitude: 39.9526, longitude: -75.1652}

        two_hours = 7200
        assert_equal false, @service.impossible_travel?(nyc, philly, two_hours)
      end

      # Test risk calculation
      test "calculate_location_risk handles unknown locations" do
        ip = "127.0.0.1"  # Private IP will return "Unknown" country
        risk = @service.calculate_location_risk(ip)

        assert_equal 10, risk  # Should return moderate risk for unknown locations
      end

      test "calculate_location_risk detects impossible travel from a single elapsed observation" do
        service = GeolocationService.new(provider: :maxmind)
        ny = {country: "United States", country_code: "US", latitude: 40.7128, longitude: -74.0060}
        london = {country: "United Kingdom", country_code: "GB", latitude: 51.5074, longitude: -0.1278}
        service.stubs(:locate).returns(london)
        assert_equal 30, service.calculate_location_risk("198.51.100.1", [ny.deep_stringify_keys], 3600)
      end

      test "calculate_location_risk handles timestamped country changes" do
        service = GeolocationService.new(provider: :maxmind)
        service.stubs(:locate).returns(country: "United Kingdom", country_code: "GB")
        previous = {location: {country: "United States", country_code: "US"}, occurred_at: 1.hour.ago}
        assert_equal 10, service.calculate_location_risk("198.51.100.1", [previous])
      end

      test "calculate_location_risk caps at maximum" do
        ip = "203.0.113.1"

        # Create scenario with multiple risk factors
        previous_locations = Array.new(5) { @service.locate("203.0.113.#{rand(100)}") }
        risk = @service.calculate_location_risk(ip, previous_locations, 60)  # Very short time

        assert risk <= 30  # Should be capped at 30
      end

      # Test mock data consistency
      test "mock provider returns consistent data for same IP" do
        # Use mock provider explicitly
        service = Beskar::Services::GeolocationService.new(provider: :mock)

        ip = "203.0.113.1"

        result1 = service.locate(ip)
        result2 = service.locate(ip)

        assert_equal result1[:country], result2[:country]
        assert_equal result1[:city], result2[:city]
        assert_equal result1[:latitude], result2[:latitude]
        assert_equal result1[:longitude], result2[:longitude]
      end

      test "mock provider returns different data for different IPs" do
        # Use mock provider explicitly
        service = Beskar::Services::GeolocationService.new(provider: :mock)

        ip1 = "203.0.113.1"
        ip2 = "203.0.113.50"  # Should map to different mock data

        result1 = service.locate(ip1)
        result2 = service.locate(ip2)

        # At least country or city should be different
        different = result1[:country] != result2[:country] ||
          result1[:city] != result2[:city] ||
          result1[:latitude] != result2[:latitude] ||
          result1[:longitude] != result2[:longitude]

        assert different, "Different IPs should return different mock data"
      end

      # Test caching
      test "caches geolocation results" do
        ip = "203.0.113.1"

        # Clear any existing cache
        Rails.cache.delete("beskar:geolocation:#{ip}")

        # First call should hit the provider
        result1 = @service.locate(ip)

        # Second call should hit the cache
        result2 = @service.locate(ip)

        assert_equal result1, result2
      end

      # test "handles cache failures gracefully" do
      #   ip = "203.0.113.1"

      #   # Mock cache failure
      #   Rails.cache.stubs(:read).raises(StandardError.new("Cache failure"))
      #   Rails.cache.stubs(:write).raises(StandardError.new("Cache failure"))

      #   # Should still work without cache
      #   assert_nothing_raised do
      #     result = @service.locate(ip)
      #     assert result.is_a?(Hash)
      #   end
      # end

      # Test different providers
      test "initializes with different providers" do
        providers = [:mock, :maxmind]

        providers.each do |provider|
          # Clear cache to avoid interference between providers
          Rails.cache.clear

          service = Beskar::Services::GeolocationService.new(provider: provider)
          result = service.locate("203.0.113.1")

          assert result.is_a?(Hash)
          assert_equal provider, result[:provider]
        end
      end

      # Test error handling
      # test "handles provider errors gracefully" do
      #   service = @service

      #   # Mock an error in the lookup process
      #   service.stubs(:lookup_mock).raises(StandardError.new("Provider error"))

      #   # Should return unknown location instead of crashing
      #   result = service.locate("203.0.113.1")

      #   assert_equal "203.0.113.1", result[:ip]
      #   assert_equal "Unknown", result[:country]
      # end

      # Test geographic coordinate validation
      test "mock data returns valid coordinates for public IPs" do
        # Use mock provider explicitly
        service = Beskar::Services::GeolocationService.new(provider: :mock)

        # Test with known public IPs
        public_ips = ["203.0.113.1", "203.0.113.50", "203.0.113.100"]

        public_ips.each do |ip|
          result = service.locate(ip)

          # Should not be marked as private
          assert_not result[:private_ip], "#{ip} should not be private"

          # Should have coordinates
          assert_not_nil result[:latitude], "#{ip} should have latitude"
          assert_not_nil result[:longitude], "#{ip} should have longitude"

          # Coordinates should be valid
          assert result[:latitude].between?(-90, 90),
            "Latitude #{result[:latitude]} should be between -90 and 90"
          assert result[:longitude].between?(-180, 180),
            "Longitude #{result[:longitude]} should be between -180 and 180"
        end
      end

      # Test result structure consistency
      test "always returns consistent hash structure" do
        test_ips = [
          "203.0.113.1",      # Public IP
          "127.0.0.1",        # Private IP
          "invalid.ip",       # Invalid IP
          "",                 # Empty string
          nil                 # Nil
        ]

        expected_keys = [:ip, :country, :country_code, :city, :latitude, :longitude, :timezone, :provider, :private_ip]

        test_ips.each do |ip|
          result = @service.locate(ip)

          expected_keys.each do |key|
            assert result.key?(key), "Missing key #{key} for IP: #{ip.inspect}"
          end
        end
      end

      # Test that service doesn't leak sensitive information
      test "truncates or sanitizes potentially dangerous input" do
        dangerous_ips = [
          "'; DROP TABLE security_events; --",
          "<script>alert('xss')</script>",
          "../../etc/passwd",
          "A" * 1000  # Very long string
        ]

        dangerous_ips.each do |ip|
          assert_nothing_raised do
            result = @service.locate(ip)
            assert result.is_a?(Hash)
          end
        end
      end

      # Performance and resource usage tests
      test "handles many concurrent location requests" do
        threads = []
        results = []
        mutex = Mutex.new

        # Simulate concurrent requests
        10.times do |i|
          threads << Thread.new do
            ip = "203.0.113.#{i}"
            result = @service.locate(ip)

            mutex.synchronize do
              results << result
            end
          end
        end

        threads.each(&:join)

        assert_equal 10, results.length
        results.each do |result|
          assert result.is_a?(Hash)
          assert result.key?(:ip)
        end
      end

      # MaxMind integration tests
      test "maxmind service initializes with configured provider" do
        # Save original configuration
        original_provider = Beskar.configuration.geolocation_provider

        # Configure MaxMind provider
        Beskar.configuration.geolocation[:provider] = :maxmind

        service = Beskar::Services::GeolocationService.new
        result = service.locate("8.8.8.8")

        assert_equal :maxmind, result[:provider]

        # Restore original configuration
        Beskar.configuration.geolocation[:provider] = original_provider
      ensure
        # Clean up
        Beskar.configuration.geolocation[:provider] = original_provider
      end

      test "maxmind reader returns nil when database path not configured" do
        # Save original configuration
        original_city_path = Beskar.configuration.maxmind_city_db_path

        # Clear database path
        Beskar.configuration.geolocation[:maxmind_city_db_path] = nil

        # Reset readers to force reinitialization
        Beskar::Services::GeolocationService.reset_readers!

        assert_nil Beskar::Services::GeolocationService.city_reader

        # Restore original configuration
        Beskar.configuration.geolocation[:maxmind_city_db_path] = original_city_path
        Beskar::Services::GeolocationService.reset_readers!
      end

      test "maxmind reader handles non-existent database file gracefully" do
        # Save original configuration
        original_city_path = Beskar.configuration.maxmind_city_db_path

        # Set non-existent database path
        Beskar.configuration.geolocation[:maxmind_city_db_path] = "/non/existent/path.mmdb"

        # Reset readers to force reinitialization
        Beskar::Services::GeolocationService.reset_readers!

        # Should return nil and log warning
        assert_nil Beskar::Services::GeolocationService.city_reader

        # Restore original configuration
        Beskar.configuration.geolocation[:maxmind_city_db_path] = original_city_path
        Beskar::Services::GeolocationService.reset_readers!
      end

      test "maxmind lookup includes city data when available" do
        db_path = Rails.root.join("config", "GeoLite2-City.mmdb").to_s
        skip "City database not available" unless File.exist?(db_path)

        # Don't reset readers in parallel tests - it causes race conditions
        service = Beskar::Services::GeolocationService.new(provider: :maxmind)

        # Use Google's public DNS IP
        result = service.locate("8.8.8.8")

        # Should have basic structure even if no data for this IP
        assert result.is_a?(Hash), "Result should be a hash"
        assert result.key?(:ip), "Should have IP key"
        assert result.key?(:provider), "Should have provider key"
        assert_equal :maxmind, result[:provider], "Provider should be maxmind"

        # If we got location data (some MaxMind DBs might not have Google DNS),
        # validate it's in the correct format
        if result[:country_code]
          assert result[:country_code].is_a?(String), "Country code should be a string"
          assert result[:country].is_a?(String), "Country should be a string" if result[:country]
        end

        if result[:latitude]
          assert result[:latitude].is_a?(Numeric), "Latitude should be numeric"
          assert result[:latitude].between?(-90, 90),
            "Latitude should be valid (-90 to 90)"
        end
      end

      test "maxmind service handles public IPs correctly" do
        db_path = Rails.root.join("config", "GeoLite2-City.mmdb").to_s
        skip "City database not available" unless File.exist?(db_path)

        service = Beskar::Services::GeolocationService.new(provider: :maxmind)

        # Test with well-known public IPs
        public_ips = [
          "8.8.8.8",      # Google DNS
          "1.1.1.1",      # Cloudflare DNS
          "208.67.222.222" # OpenDNS
        ]

        public_ips.each do |ip|
          result = service.locate(ip)

          assert_equal ip, result[:ip]
          assert_equal :maxmind, result[:provider]
          assert_equal false, result[:private_ip]

          # Should have some location data or return Unknown
          assert result.key?(:country)
          assert result.key?(:country_code)
          assert result.key?(:city)
          assert result.key?(:latitude)
          assert result.key?(:longitude)
        end
      end

      test "maxmind reader is thread-safe" do
        db_path = Rails.root.join("config", "GeoLite2-City.mmdb").to_s
        skip "City database not available" unless File.exist?(db_path)

        # Don't reset readers in parallel tests - it causes race conditions

        threads = []
        results = []
        mutex = Mutex.new

        # Multiple threads trying to initialize and use reader simultaneously
        20.times do |i|
          threads << Thread.new do
            service = Beskar::Services::GeolocationService.new(provider: :maxmind)
            result = service.locate("8.8.#{i}.#{i}")

            mutex.synchronize do
              results << result
            end
          end
        end

        threads.each(&:join)

        # All requests should complete successfully
        assert_equal 20, results.length
        results.each do |result|
          assert result.is_a?(Hash)
          assert_equal :maxmind, result[:provider]
        end
      end

      test "maxmind service falls back gracefully when database unavailable" do
        # Save original configuration
        original_provider = Beskar.configuration.geolocation_provider
        original_city_path = Beskar.configuration.maxmind_city_db_path

        # Configure MaxMind but with invalid path
        Beskar.configuration.geolocation[:provider] = :maxmind
        Beskar.configuration.geolocation[:maxmind_city_db_path] = nil

        # Reset readers
        Beskar::Services::GeolocationService.reset_readers!

        service = Beskar::Services::GeolocationService.new(provider: :maxmind)
        result = service.locate("8.8.8.8")

        # Should still return a valid result
        assert result.is_a?(Hash)
        assert_equal "8.8.8.8", result[:ip]
        assert_equal :maxmind, result[:provider]
        # Should return Unknown for unavailable data
        assert_equal "Unknown", result[:country]

        # Restore original configuration
        Beskar.configuration.geolocation[:provider] = original_provider
        Beskar.configuration.geolocation[:maxmind_city_db_path] = original_city_path
        Beskar::Services::GeolocationService.reset_readers!
      end

      test "configuration respects custom cache TTL" do
        # Save original configuration
        original_ttl = Beskar.configuration.geolocation_cache_ttl

        # Set custom TTL
        custom_ttl = 2.hours
        Beskar.configuration.geolocation[:cache_ttl] = custom_ttl

        service = Beskar::Services::GeolocationService.new
        assert_equal custom_ttl, service.instance_variable_get(:@cache_ttl)

        # Restore original configuration
        Beskar.configuration.geolocation[:cache_ttl] = original_ttl
      end

      test "reset_readers! clears cached reader instance" do
        # Initialize reader if database is available
        Beskar::Services::GeolocationService.city_reader

        # Reset
        Beskar::Services::GeolocationService.reset_readers!

        # Reader should be nil (will be reinitialized on next access)
        city_reader = Beskar::Services::GeolocationService.instance_variable_get(:@city_reader)

        assert_nil city_reader
      end
    end
  end
end
