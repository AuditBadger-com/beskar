# frozen_string_literal: true

require "digest"

begin
  require "maxminddb"
rescue LoadError
  # MaxMindDB gem not available
end

module Beskar
  module Services
    # Service for detecting geographic location from IP addresses
    #
    # This service provides IP-based geolocation capabilities for security analysis,
    # impossible travel detection, and geographic anomaly detection.
    #
    # Features:
    # - Efficient MaxMind database reading with singleton pattern
    # - Automatic caching with configurable TTL
    # - Private IP detection
    # - Impossible travel detection using Haversine formula
    #
    # @example Basic usage
    #   service = Beskar::Services::GeolocationService.new
    #   location = service.locate("203.0.113.1")
    #   # => {
    #   #   ip: "203.0.113.1",
    #   #   country: "United States",
    #   #   country_code: "US",
    #   #   city: "New York",
    #   #   latitude: 40.7128,
    #   #   longitude: -74.0060,
    #   #   timezone: "America/New_York"
    #   # }
    #
    class GeolocationService
      # Private/internal IP ranges that should not be geolocated
      PRIVATE_IP_RANGES = [
        IPAddr.new("10.0.0.0/8"),      # RFC 1918 - Private networks
        IPAddr.new("172.16.0.0/12"),   # RFC 1918 - Private networks
        IPAddr.new("192.168.0.0/16"),  # RFC 1918 - Private networks
        IPAddr.new("127.0.0.0/8"),     # Loopback
        IPAddr.new("169.254.0.0/16"),  # Link-local
        IPAddr.new("224.0.0.0/4"),     # Multicast
        IPAddr.new("::1/128"),         # IPv6 loopback
        IPAddr.new("fe80::/10"),       # IPv6 link-local
        IPAddr.new("fc00::/7")         # IPv6 unique local
      ].freeze

      # Cache TTL for geolocation results (4 hours)
      CACHE_TTL = 4.hours

      # Thread-safe reader for MaxMind City database
      @city_reader_mutex = Mutex.new
      @city_reader = nil

      class << self
        attr_reader :city_reader_mutex
        # Convenience method for one-off location lookup
        #
        # @param ip_address [String] The IP address to locate
        # @return [Hash] Location information
        def locate(ip_address)
          new.locate(ip_address)
        end

        # Check if an IP address is private/internal
        #
        # @param ip_address [String] The IP address to check
        # @return [Boolean] true if private/internal IP
        def private_ip?(ip_address)
          return true if ip_address.blank?

          begin
            ip = IPAddr.new(ip_address)
            PRIVATE_IP_RANGES.any? { |range| range.include?(ip) }
          rescue IPAddr::InvalidAddressError
            true # Treat invalid IPs as private
          end
        end

        # Calculate distance between two geographic points using Haversine formula
        #
        # @param lat1 [Float] Latitude of first point
        # @param lon1 [Float] Longitude of first point
        # @param lat2 [Float] Latitude of second point
        # @param lon2 [Float] Longitude of second point
        # @return [Float] Distance in kilometers
        def calculate_distance(lat1, lon1, lat2, lon2)
          return 0.0 if lat1.nil? || lon1.nil? || lat2.nil? || lon2.nil?

          # Convert degrees to radians
          lat1_rad = lat1 * Math::PI / 180
          lon1_rad = lon1 * Math::PI / 180
          lat2_rad = lat2 * Math::PI / 180
          lon2_rad = lon2 * Math::PI / 180

          # Haversine formula
          dlat = lat2_rad - lat1_rad
          dlon = lon2_rad - lon1_rad

          a = Math.sin(dlat / 2)**2 + Math.cos(lat1_rad) * Math.cos(lat2_rad) * Math.sin(dlon / 2)**2
          a = a.clamp(0.0, 1.0)
          c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a))

          # Earth's radius in kilometers
          earth_radius = 6371.0
          earth_radius * c
        end
      end

      # Namespace readers and optional caches by the configured database generation.
      def self.database_identity
        path = Beskar.configuration.maxmind_city_db_path.to_s
        stat = File.stat(path) if path.present?
        [path, stat&.ino, stat&.size, stat&.mtime&.to_r&.to_s]
      rescue SystemCallError
        [path, nil, nil, nil]
      end

      def self.city_reader(identity = database_identity)
        @city_reader_mutex.synchronize do
          return @city_reader if @city_reader_identity == identity && @city_reader
          @city_reader = nil
          @city_reader_identity = identity
          path = identity.first
          return nil unless path.present? && defined?(MaxMindDB) && File.file?(path)
          @city_reader = MaxMindDB.new(path)
        end
      rescue => error
        Beskar::Logger.error("Failed to load MaxMind database (#{error.class})", component: :GeolocationService)
        nil
      end

      # Existing lookups can finish using their reader; do not close it underneath
      # another thread. New lookups select the current database generation.
      def self.reset_readers!
        @city_reader_mutex.synchronize do
          @city_reader = nil
          @city_reader_identity = nil
        end
      end

      # Initialize the geolocation service
      #
      # @param provider [Symbol] The geolocation provider to use (:maxmind, :mock)
      def initialize(provider: nil)
        @provider = provider || Beskar.configuration.geolocation_provider
        unless Configuration::GEOLOCATION_PROVIDERS.include?(@provider)
          raise Configuration::Error, "geolocation.provider must be mock or maxmind"
        end
        @database_identity = self.class.database_identity
        @cache_key_prefix = "beskar:geolocation:v2:#{Digest::SHA256.hexdigest([@provider, @database_identity].to_json)}"
        @cache_ttl = Beskar.configuration.geolocation_cache_ttl
      end

      # Locate an IP address and return geographic information
      #
      # @param ip_address [String] The IP address to locate
      # @return [Hash] Location information with country, city, coordinates, etc.
      def locate(ip_address)
        if self.class.private_ip?(ip_address)
          result = private_ip_result(ip_address)
          result[:provider] = @provider
          return result
        end

        # Check cache first
        if (cached_result = get_cached_location(ip_address))
          return cached_result
        end

        # Perform lookup based on provider
        result = case @provider
        when :maxmind
          lookup_maxmind(ip_address)
        when :mock
          lookup_mock(ip_address)
        else
          unknown_location(ip_address)
        end

        # Cache the result
        cache_location(ip_address, result)

        result
      rescue => e
        Beskar::Logger.warn("Failed to locate IP #{ip_address}: #{e.class}", component: :GeolocationService)
        unknown_location(ip_address)
      end

      # Check if travel between two locations is impossible given the time difference
      #
      # @param location1 [Hash] First location with latitude/longitude
      # @param location2 [Hash] Second location with latitude/longitude
      # @param time_diff_seconds [Integer] Time difference in seconds
      # @param max_speed_kmh [Integer] Maximum realistic travel speed in km/h (default: 1000 for commercial flights)
      # @return [Boolean] true if travel is impossible
      def impossible_travel?(location1, location2, time_diff_seconds, max_speed_kmh: 1000)
        first, second = LocationAssessment.coordinates(location1), LocationAssessment.coordinates(location2)
        elapsed, speed = LocationAssessment.number(time_diff_seconds), LocationAssessment.number(max_speed_kmh)
        return false unless first && second && elapsed&.positive? && speed&.positive?
        self.class.calculate_distance(*first, *second) > speed * elapsed / 3600.0
      end

      def assess_location(ip_address, observations: [], at: Time.current, location: nil)
        LocationAssessment.new(location || locate(ip_address), observations: observations, at: at).call
      end

      # Compatibility API for a single previous location and elapsed duration.
      # Multi-observation callers must supply each observation's own timestamp.
      def calculate_location_risk(ip_address, previous_locations = [], time_since_last = nil)
        at = Time.current
        observations = if previous_locations.all? { |entry| entry.is_a?(Hash) && (entry.key?(:occurred_at) || entry.key?("occurred_at")) }
          previous_locations
        elsif previous_locations.size == 1 && (elapsed = LocationAssessment.number(time_since_last))&.positive?
          [{location: previous_locations.first, occurred_at: at - elapsed}]
        else
          []
        end
        assess_location(ip_address, observations: observations, at: at)[:score]
      end

      private

      # Return result for private/internal IP addresses
      #
      # @param ip_address [String] The private IP address
      # @return [Hash] Location information for private IP
      def private_ip_result(ip_address)
        {
          ip: ip_address,
          country: "Private",
          country_code: nil,
          city: "Local Network",
          latitude: nil,
          longitude: nil,
          timezone: nil,
          provider: @provider,
          private_ip: true
        }
      end

      # Return result for unknown/unlocatable IP addresses
      #
      # @param ip_address [String] The IP address
      # @return [Hash] Unknown location information
      def unknown_location(ip_address)
        {
          ip: ip_address,
          country: "Unknown",
          country_code: nil,
          city: "Unknown",
          latitude: nil,
          longitude: nil,
          timezone: nil,
          provider: @provider,
          private_ip: false
        }
      end

      # Mock geolocation lookup for testing/development
      #
      # @param ip_address [String] The IP address
      # @return [Hash] Mock location information
      def lookup_mock(ip_address)
        # Generate consistent mock data based on IP
        country_codes = ["US", "CA", "GB", "DE", "FR", "JP", "AU"]
        cities = ["New York", "Toronto", "London", "Berlin", "Paris", "Tokyo", "Sydney"]

        index = ip_address.bytes.sum % country_codes.length

        {
          ip: ip_address,
          country: case country_codes[index]
                   when "US" then "United States"
                   when "CA" then "Canada"
                   when "GB" then "United Kingdom"
                   when "DE" then "Germany"
                   when "FR" then "France"
                   when "JP" then "Japan"
                   when "AU" then "Australia"
                   end,
          country_code: country_codes[index],
          city: cities[index],
          latitude: (40.0 + (index * 10)) % 90,
          longitude: (-74.0 + (index * 15)) % 180,
          timezone: "UTC#{(index > 3) ? "+" : "-"}#{index + 1}",
          provider: @provider,
          private_ip: false
        }
      end

      # Lookup using MaxMind GeoIP2 database
      #
      # @param ip_address [String] The IP address
      # @return [Hash] Location information from MaxMind
      def lookup_maxmind(ip_address)
        result = {ip: ip_address, provider: @provider, private_ip: false}

        # Lookup city/location data
        if (city_reader = self.class.city_reader(@database_identity))
          begin
            city_data = city_reader.lookup(ip_address)
            if city_data&.found?
              city_hash = city_data.to_hash
              result.merge!(
                country: city_hash.dig("country", "names", "en") || "Unknown",
                country_code: city_hash.dig("country", "iso_code"),
                city: city_hash.dig("city", "names", "en") || "Unknown",
                latitude: city_hash.dig("location", "latitude"),
                longitude: city_hash.dig("location", "longitude"),
                timezone: city_hash.dig("location", "time_zone"),
                postal_code: city_hash.dig("postal", "code"),
                subdivision: city_hash.dig("subdivisions", 0, "names", "en"),
                subdivision_code: city_hash.dig("subdivisions", 0, "iso_code")
              )
            else
              result.merge!(unknown_location(ip_address).except(:ip, :provider, :private_ip))
            end
          rescue => e
            Beskar::Logger.warn("MaxMind City lookup failed for #{ip_address}: #{e.class}", component: :GeolocationService)
            result.merge!(unknown_location(ip_address).except(:ip, :provider, :private_ip))
          end
        else
          # No city database configured, return basic unknown location
          result.merge!(unknown_location(ip_address).except(:ip, :provider, :private_ip))
        end

        result
      rescue => e
        Beskar::Logger.error("MaxMind lookup failed for #{ip_address}: #{e.class}", component: :GeolocationService)
        unknown_location(ip_address)
      end

      # Get cached location result
      #
      # @param ip_address [String] The IP address
      # @return [Hash, nil] Cached location or nil
      def get_cached_location(ip_address)
        cache_key = "#{@cache_key_prefix}:#{ip_address}"
        Rails.cache.read(cache_key)
      rescue => e
        Beskar::Logger.debug("Cache read failed: #{e.class}", component: :GeolocationService)
        nil
      end

      # Cache location result
      #
      # @param ip_address [String] The IP address
      # @param result [Hash] The location result to cache
      def cache_location(ip_address, result)
        cache_key = "#{@cache_key_prefix}:#{ip_address}"
        Rails.cache.write(cache_key, result, expires_in: @cache_ttl)
      rescue => e
        Beskar::Logger.debug("Cache write failed: #{e.class}", component: :GeolocationService)
      end
    end
  end
end
