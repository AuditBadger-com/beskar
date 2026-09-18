module Beskar
  module Middleware
    class RequestAnalyzer
      def initialize(app)
        @app = app
      end

      def call(env)
        request = ActionDispatch::Request.new(env)
        ip_address = Beskar::Services::RequestContext.ip(request)

        Beskar::Logger.debug("[RequestAnalyzer] Processing request from IP: #{ip_address}", component: :Middleware)

        # 1. Check if IP is whitelisted (whitelisted IPs skip blocking but still get logged)
        is_whitelisted = Beskar::Services::IpWhitelist.whitelisted?(ip_address)

        # 2. Check if IP is banned (early exit for blocked IPs, unless whitelisted or in monitor-only mode)
        if !is_whitelisted && Beskar::BannedIp.banned?(ip_address)
          if Beskar.configuration.monitor_only?
            Beskar::Logger.warn("🔍 MONITOR-ONLY: Would block request from banned IP: #{ip_address}, but monitor_only=true. Request proceeding normally.", component: :Middleware)
          else
            Beskar::Logger.warn("Blocked request from banned IP: #{ip_address}", component: :Middleware)
            return blocked_response("Your IP address has been blocked due to suspicious activity.")
          end
        end

        # 3. Check rate limiting (unless whitelisted)
        rate_limit = Beskar.configuration.rate_limiting[:ip_attempts][:block_requests] ?
          Beskar::Services::RateLimiter.check_ip_rate_limit(ip_address) : {allowed: true}
        if !is_whitelisted && !rate_limit[:allowed]
          # Observe denials separately in monitor mode; never create active bans.
          if should_auto_block_rate_limit?(ip_address) && !Beskar.configuration.monitor_only?
            Beskar::BannedIp.ban!(
              ip_address,
              reason: "rate_limit_abuse",
              duration: 1.hour,
              details: "Excessive rate limit violations"
            )
          end

          if Beskar.configuration.monitor_only?
            Beskar::Logger.warn("🔍 MONITOR-ONLY: Would block rate limit exceeded for IP: #{ip_address}, but monitor_only=true. Request proceeding normally.", component: :Middleware)
          else
            Beskar::Logger.warn("Rate limit exceeded for IP: #{ip_address}", component: :Middleware)
            return rate_limit_response(rate_limit[:retry_after])
          end
        end

        # 4. Check WAF patterns (vulnerability scans)
        if Beskar.configuration.waf_enabled?
          Beskar::Logger.debug("[RequestAnalyzer] WAF enabled, analyzing request", component: :Middleware)
          waf_analysis = Beskar::Services::Waf.analyze_request(request)

          if waf_analysis
            Beskar::Logger.debug("[RequestAnalyzer] WAF detected threat: #{waf_analysis[:patterns].map { |p| p[:description] }.join(", ")}", component: :Middleware)
            # Log the violation (and create security event if configured)
            # Pass whitelist status to prevent auto-blocking whitelisted IPs
            current_score = Beskar::Services::Waf.record_violation(ip_address, waf_analysis, whitelisted: is_whitelisted)
            waf_recorded = true
            Beskar::Logger.debug("[RequestAnalyzer] Current score after recording: #{current_score.round(2)}", component: :Middleware)

            # Log even for whitelisted IPs (but don't block)
            if is_whitelisted
              Beskar::Logger.info("WAF violation from whitelisted IP #{ip_address} " \
                "(not blocking): #{waf_analysis[:patterns].map { |p| p[:description] }.join(", ")}", component: :Middleware)
            else
              # Check if we should block
              should_block = Beskar::Services::Waf.should_block?(ip_address)
              Beskar::Logger.debug("[RequestAnalyzer] Should block IP #{ip_address}?: #{should_block}", component: :Middleware)

              if Beskar.configuration.monitor_only?
                # Monitor-only mode records observations without creating active bans.
                if should_block
                  Beskar::Logger.warn("🔍 MONITOR-ONLY: Would block IP #{ip_address} " \
                    "with score #{current_score.round(2)}, but monitor_only=true. " \
                    "Request proceeding normally.", component: :Middleware)
                end
              elsif should_block && !Beskar.configuration.monitor_only?
                # Actually block the request (not in monitor-only mode)
                Beskar::Logger.warn("🔒 Blocking IP #{ip_address} " \
                  "with WAF score #{current_score.round(2)}", component: :Middleware)
                # Block already handled by WAF.record_violation auto-block logic
                # But we return 403 immediately
                return blocked_response("Access denied due to suspicious activity.")
              end
            end
          else
            Beskar::Logger.debug("[RequestAnalyzer] No WAF threat detected", component: :Middleware)
          end
        else
          Beskar::Logger.debug("[RequestAnalyzer] WAF is disabled", component: :Middleware)
        end

        # 5. Process the request normally (will raise 404 if route not found)
        Beskar::Logger.debug("[RequestAnalyzer] Passing request to application", component: :Middleware)
        processing_host = true
        @app.call(env)
      rescue Beskar::Services::AuthenticationAttempt::Unavailable
        Beskar::Services::AuthenticationAttempt.unavailable_response
      rescue ActionController::UnknownFormat => e
        # Analyze unknown format as potential scanner
        if Beskar.configuration.waf_enabled?
          handle_rails_exception(request, e, ip_address, is_whitelisted) unless waf_recorded
        end
        # Re-raise to allow normal error handling
        raise
      rescue ActionDispatch::RemoteIp::IpSpoofAttackError => e
        # Attribute downstream errors only when Rails already resolved a trusted
        # client IP. Never ban an address from a rejected proxy chain.
        handle_rails_exception(request, e, ip_address, is_whitelisted) if !waf_recorded && ip_address && Beskar.configuration.waf_enabled?
        raise
      rescue ActiveRecord::RecordNotFound => e
        # Analyze record not found as potential enumeration scan
        if Beskar.configuration.waf_enabled?
          handle_rails_exception(request, e, ip_address, is_whitelisted) unless waf_recorded
        end
        # Re-raise to allow normal error handling
        raise
      rescue ActionDispatch::Http::MimeNegotiation::InvalidType => e
        # Analyze invalid MIME type as potential scanner
        if Beskar.configuration.waf_enabled?
          handle_rails_exception(request, e, ip_address, is_whitelisted) unless waf_recorded
        end
        # Re-raise to allow normal error handling
        raise
      rescue ActionController::RoutingError => e
        # If WAF is enabled, log 404s as potential scanning attempts
        if Beskar.configuration.waf_enabled?
          log_404_for_waf(request, e)
        end
        # Re-raise to allow normal 404 handling
        raise
      rescue ActiveRecord::ActiveRecordError => error
        raise if processing_host
        Beskar::Logger.warn("Request security state unavailable (#{error.class})")
        Beskar::Services::AuthenticationAttempt.unavailable_response
      end

      private

      def should_auto_block_rate_limit?(ip_address)
        mode = Beskar.configuration.monitor_only? ? "observe" : "enforce"
        key = "rate_denials:#{mode}:#{ip_address}"
        Beskar::SecurityState.mutate(key, ttl: 1.hour) do |state|
          data = state.fetch(key)
          now = Time.current.to_f
          # A fixed window: repeated requests cannot prolong old violations.
          data.clear if data["window_end"] && data["window_end"] <= now
          data["window_end"] ||= now + 1.hour
          data["count"] = [data.fetch("count", 0) + 1, 5].min
          data["count"] >= 5
        end
      end

      def handle_rails_exception(request, exception, ip_address, is_whitelisted)
        # Analyze the exception using WAF
        waf_analysis = Beskar::Services::Waf.analyze_exception(exception, request)

        if waf_analysis
          Beskar::Logger.debug("[RequestAnalyzer] WAF detected threat from exception: #{exception.class.name}", component: :Middleware)

          # Record the violation (similar to regular WAF violations)
          current_score = Beskar::Services::Waf.record_violation(ip_address, waf_analysis, whitelisted: is_whitelisted)

          # Log for whitelisted IPs
          if is_whitelisted
            Beskar::Logger.info("Exception-based WAF violation from whitelisted IP #{ip_address} " \
              "(not blocking): #{exception.class.name} - #{waf_analysis[:patterns].first[:description]}", component: :Middleware)
          else
            # Check if we should block
            should_block = Beskar::Services::Waf.should_block?(ip_address)

            if Beskar.configuration.monitor_only?
              if should_block
                Beskar::Logger.warn("🔍 MONITOR-ONLY: Would block IP #{ip_address} " \
                  "with score #{current_score.round(2)} (exception: #{exception.class.name}), " \
                  "but monitor_only=true. Request proceeding normally.", component: :Middleware)
              end
            elsif should_block && !Beskar.configuration.monitor_only?
              Beskar::Logger.warn("🔒 Blocking IP #{ip_address} " \
                "with score #{current_score.round(2)} (exception: #{exception.class.name})", component: :Middleware)
              # Note: We don't return blocked response here as exception is already raised
              # The ban record is created by WAF.record_violation
            end
          end
        end
      end

      def log_404_for_waf(request, error)
        # Only log if it matches WAF patterns (already analyzed in analyze_request)
        waf_analysis = Beskar::Services::Waf.analyze_request(request)

        if waf_analysis
          Beskar::Logger.info("404 matching WAF rules from #{Beskar::Services::RequestContext.ip(request)} " \
            "(WAF patterns: #{waf_analysis[:patterns].map { |p| p[:description] }.join(", ")})", component: :Middleware)
        end
      end

      def blocked_response(message = "Forbidden")
        [
          403,
          {
            "content-type" => "text/html; charset=utf-8",
            "x-beskar-blocked" => "true"
          },
          [render_blocked_page(message)]
        ]
      end

      def rate_limit_response(retry_after)
        [
          429,
          {
            "content-type" => "text/html; charset=utf-8",
            "retry-after" => [retry_after.to_i, 1].max.to_s,
            "x-beskar-rate-limited" => "true"
          },
          [render_rate_limit_page]
        ]
      end

      def render_blocked_page(message)
        <<~HTML
          <!DOCTYPE html>
          <html>
          <head>
            <title>Access Denied</title>
            <style>
              body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
              h1 { color: #d32f2f; }
              p { color: #666; }
            </style>
          </head>
          <body>
            <h1>Access Denied</h1>
            <p>#{message}</p>
            <p>If you believe this is an error, please contact the site administrator.</p>
          </body>
          </html>
        HTML
      end

      def render_rate_limit_page
        <<~HTML
          <!DOCTYPE html>
          <html>
          <head>
            <title>Too Many Requests</title>
            <style>
              body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
              h1 { color: #ff9800; }
              p { color: #666; }
            </style>
          </head>
          <body>
            <h1>Too Many Requests</h1>
            <p>You have exceeded the rate limit. Please try again later.</p>
          </body>
          </html>
        HTML
      end
    end
  end
end
