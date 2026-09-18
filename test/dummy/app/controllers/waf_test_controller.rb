class WafTestController < ApplicationController
  skip_before_action :verify_authenticity_token

  def trigger_wordpress
    # This path should trigger WordPress vulnerability scan pattern
    render json: {
      path: request.path,
      ip: request.ip,
      remote_ip: request.remote_ip,
      x_forwarded_for: request.headers["X-Forwarded-For"],
      violation_count: Beskar::Services::Waf.get_violation_count(request.ip),
      is_banned: Beskar::BannedIp.banned?(request.ip),
      message: "WordPress vulnerability scan pattern triggered"
    }
  end

  def trigger_config
    # This path should trigger config file access pattern
    render json: {
      path: request.path,
      ip: request.ip,
      violation_count: Beskar::Services::Waf.get_violation_count(request.ip),
      is_banned: Beskar::BannedIp.banned?(request.ip),
      message: "Config file access pattern triggered"
    }
  end

  def status
    ip = params[:ip] || request.ip

    # Get violation count from cache
    violation_count = Beskar::Services::Waf.get_violation_count(ip)

    # Check if banned
    banned_record = Beskar::BannedIp.find_by(ip_address: ip)

    # Get security events
    security_events = Beskar::SecurityEvent.where(ip_address: ip, event_type: "waf_violation")
      .order(created_at: :desc)
      .limit(10)

    # Check cache directly
    cache_key = "beskar:waf_violations:#{ip}"
    cached_violations = Rails.cache.read(cache_key)

    banned_cache_key = "beskar:banned_ip:#{ip}"
    banned_in_cache = Rails.cache.read(banned_cache_key)

    render json: {
      ip: ip,
      request_details: {
        path: request.path,
        fullpath: request.fullpath,
        user_agent: request.user_agent,
        headers: {
          x_forwarded_for: request.headers["X-Forwarded-For"],
          x_real_ip: request.headers["X-Real-IP"],
          remote_addr: request.headers["REMOTE_ADDR"]
        }
      },
      waf_status: {
        enabled: Beskar.configuration.waf_enabled?,
        auto_block: Beskar.configuration.waf[:auto_block],
        score_threshold: Beskar.configuration.waf[:score_threshold],
        monitor_only: Beskar.configuration.monitor_only?
      },
      violations: {
        current_count: violation_count,
        cached_count: cached_violations,
        should_block: Beskar::Services::Waf.should_block?(ip)
      },
      ban_status: {
        is_banned: Beskar::BannedIp.banned?(ip),
        banned_in_cache: banned_in_cache,
        ban_record: banned_record ? {
          reason: banned_record.reason,
          details: banned_record.details,
          violation_count: banned_record.violation_count,
          permanent: banned_record.permanent,
          expires_at: banned_record.expires_at,
          created_at: banned_record.created_at,
          metadata: banned_record.metadata
        } : nil
      },
      security_events: {
        total_count: security_events.count,
        recent_events: security_events.map do |event|
          {
            created_at: event.created_at,
            risk_score: event.risk_score,
            would_be_blocked: event.metadata["would_be_blocked"],
            violation_count: event.metadata["violation_count"],
            patterns_matched: event.metadata["patterns_matched"]
          }
        end
      }
    }
  end

  def clear_violations
    ip = params[:ip] || request.ip

    # Clear WAF violations cache
    cache_key = "beskar:waf_violations:#{ip}"
    Rails.cache.delete(cache_key)

    # Clear banned cache
    banned_cache_key = "beskar:banned_ip:#{ip}"
    Rails.cache.delete(banned_cache_key)

    # Remove ban record
    Beskar::BannedIp.where(ip_address: ip).destroy_all

    # Remove security events
    Beskar::SecurityEvent.where(ip_address: ip).destroy_all

    render json: {
      ip: ip,
      message: "Cleared all violations and bans for IP",
      cleared: {
        cache_keys: [cache_key, banned_cache_key],
        ban_records: true,
        security_events: true
      }
    }
  end

  def simulate_violations
    ip = params[:ip] || request.ip
    count = params[:count]&.to_i || 5

    results = []

    count.times do |i|
      # Create mock request
      mock_request = OpenStruct.new(
        fullpath: "/wp-admin.php",
        path: "/wp-admin.php",
        ip: ip,
        user_agent: request.user_agent || "Test Agent"
      )

      # Analyze request
      analysis = Beskar::Services::Waf.analyze_request(mock_request)

      if analysis
        # Record violation
        violation_count = Beskar::Services::Waf.record_violation(ip, analysis, whitelisted: false)

        results << {
          violation_number: i + 1,
          violation_count: violation_count,
          patterns_detected: analysis[:patterns].map { |p| p[:description] },
          severity: analysis[:highest_severity]
        }
      end
    end

    # Check final status
    banned_record = Beskar::BannedIp.find_by(ip_address: ip)

    render json: {
      ip: ip,
      simulated_violations: count,
      results: results,
      final_status: {
        total_violations: Beskar::Services::Waf.get_violation_count(ip),
        is_banned: Beskar::BannedIp.banned?(ip),
        should_block: Beskar::Services::Waf.should_block?(ip),
        ban_created: banned_record.present?,
        ban_details: banned_record ? {
          reason: banned_record.reason,
          violation_count: banned_record.violation_count,
          expires_at: banned_record.expires_at
        } : nil
      }
    }
  end

  def test_middleware
    # This should go through the middleware and trigger WAF
    render json: {
      message: "This request went through the middleware",
      middleware_stack: Rails.application.config.middleware.map(&:to_s).select { |m| m.include?("Beskar") },
      ip: request.ip,
      path: request.path
    }
  end
end
