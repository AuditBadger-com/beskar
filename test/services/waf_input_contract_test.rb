require "test_helper"

class WafInputContractTest < ActiveSupport::TestCase
  setup do
    Beskar.configuration.waf.merge!(enabled: true, auto_block: true, score_threshold: 95, decay_enabled: false)
    @waf = Beskar::Services::Waf
    @ip = "198.51.100.40"
  end

  test "benign path and query corpus is not mistaken for scanner endpoints" do
    ["/", "/.well-known/openid-configuration", "/.well-known/acme-challenge/private-value",
      "/.well-known/security.txt", "/debugging", "/phpmyadministrator", "/wp-admin-guide",
      "/administrator-guide", "/.github/workflows", "/.environment", "/articles/wordpress",
      "/blog/joomla-news", "/profile/admin-guide", "/downloads/report..pdf", "/sale/50%25-off"].each do |path|
      assert_nil @waf.analyze_request(request(path, query: "q=/wp-admin&token=secret")), path
    end
    assert_nil @waf.analyze_request(request("/search", query: "q=format%3Dphp"))
  end

  test "encoded slash backslash and double encoded traversal are detected" do
    ["/%2e%2e%2fprivate", "/%252e%252e%252fprivate", "/files/..%5cprivate",
      "/%2E%2E/etc/passwd", "/files/../private", "/files/.."].each do |path|
      analysis = @waf.analyze_request(request(path))
      assert_equal :critical, analysis[:highest_severity], path
      assert_includes analysis[:patterns].map { |pattern| pattern[:category] }, :path_traversal
      refute analysis.to_json.include?(path)
    end
  end

  test "matching budget failures produce explicit bounded evidence" do
    ["/%zz", "/%00/private", "/%25252e%25252e%25252fprivate", "/" + "a" * 9000].each do |path|
      analysis = @waf.analyze_request(request(path))
      assert_equal :malformed_path, analysis[:patterns].first[:category]
      assert_operator analysis.to_json.bytesize, :<, 2048
    end
  end

  test "only the exact format query parameter is checked without recording its query" do
    ["format=php&token=secret-marker", "a=1&%66ormat=EXE", "format=json&format=jar"].each do |query|
      analysis = @waf.analyze_request(request("/reports", query: query))
      assert_equal "rails_exceptions:format", analysis[:patterns].last[:rule_id]
      refute_includes analysis.to_json, "secret-marker"
    end
    assert_nil @waf.analyze_request(request("/reports", query: "format=json&search=/etc/passwd"))
  end

  test "method path and category exclusions are precise and use decoded paths" do
    Beskar.configuration.waf[:request_exclusions] = [{path: %r{\A/wp-content/}, methods: ["GET"], categories: [:wordpress_static]}]
    assert_nil @waf.analyze_request(request("/%77p-content/themes/site.css"))
    assert @waf.analyze_request(request("/wp-content/themes/site.css", method: "POST"))
    assert @waf.analyze_request(request("/wp-content/uploads/attack.php"))
    assert_equal :critical, @waf.analyze_request(request("/wp-content/../.env"))[:highest_severity]
  end

  test "ordinary Rails errors are not scanner evidence unless broad scoring is opted into" do
    [ActiveRecord::RecordNotFound.new("secret database details"), ActionController::UnknownFormat.new("secret format"),
      ActionDispatch::Http::MimeNegotiation::InvalidType.new("secret MIME")].each do |error|
      assert_nil @waf.analyze_exception(error, request("/reports/17"))
      Beskar.configuration.waf[:exception_detection] = :all
      analysis = @waf.analyze_exception(error, request("/reports/17"))
      assert analysis
      refute_includes analysis.to_json, "secret"
      Beskar.configuration.waf[:exception_detection] = :suspicious
    end
    assert @waf.analyze_exception(ActionController::UnknownFormat.new, request("/users/1.exe"))
  end

  test "exception exclusions use the same method and category contract" do
    Beskar.configuration.waf[:exception_detection] = :all
    Beskar.configuration.waf[:request_exclusions] = [{path: %r{\A/reports/}, methods: [:get], categories: [:unknown_format]}]
    error = ActionController::UnknownFormat.new
    assert_nil @waf.analyze_exception(error, request("/reports/17"))
    assert @waf.analyze_exception(error, request("/reports/17", method: "POST"))
    Beskar.configuration.waf[:exception_detection] = :none
    assert_nil @waf.analyze_exception(error, request("/users/1.exe"))
  end

  test "raw WAF URLs headers and old-style exception messages never reach sinks" do
    messages = []
    Beskar::Logger.stubs(:warn).with { |message, **|
      messages << message
      true
    }
    analysis = @waf.analyze_request(request("/.env/SECRET_PATH", query: "token=SECRET_QUERY"))
    analysis[:user_agent] = "SECRET_HEADER"
    analysis[:exception_message] = "SECRET_EXCEPTION"
    analysis[:patterns].first[:matched_path] = "/.env?token=SECRET_OLD_PATH"
    @waf.record_violation(@ip, analysis)
    event = Beskar::SecurityEvent.last
    state = Beskar::SecurityState.find_by!(key: "waf:enforce:#{@ip}")
    ban = Beskar::BannedIp.find_by!(ip_address: @ip)
    [analysis.except(:user_agent, :exception_message, :patterns), event.attributes, state.data, ban.metadata, messages].each do |sink|
      refute_includes sink.to_json, "SECRET_"
    end
    assert_nil event.user_agent
    assert_equal "config_files:0", state.data["violations"].first["rule_id"]
  end

  test "middleware charges one path violation even when the application raises" do
    Beskar.configuration.waf[:score_threshold] = 1000
    app = ->(_) { raise ActionController::UnknownFormat, "SECRET_EXCEPTION" }
    env = Rack::MockRequest.env_for("/users/1.exe?secret=value", "REMOTE_ADDR" => @ip)
    assert_raises(ActionController::UnknownFormat) { Beskar::Middleware::RequestAnalyzer.new(app).call(env) }
    assert_equal 1, @waf.get_violation_count(@ip)
    assert_equal 60, @waf.get_current_score(@ip)
  end

  test "legacy WAF state drops raw paths on reads and the next normal write" do
    key = "waf:enforce:#{@ip}"
    Beskar::SecurityState.mutate(key, ttl: 6.hours) do |state|
      state[key]["violations"] = [{timestamp: Time.current.to_i, score: 30, severity: "low",
                                   category: "wordpress_static", path: "/SECRET_PATH", description: "SECRET_DESCRIPTION"}]
    end
    refute_includes @waf.get_violations(@ip).to_json, "SECRET_"
    assert_includes Beskar::SecurityState.read(key).to_json, "SECRET_"
    @waf.record_violation(@ip, @waf.analyze_request(request("/wp-admin")))
    refute_includes Beskar::SecurityState.read(key).to_json, "SECRET_"
    assert_equal 110, @waf.get_current_score(@ip)
  end

  test "failed optional WAF audit does not prevent state or bans and logs only the error class" do
    Beskar::SecurityEvent.stubs(:create!).raises(ActiveRecord::StatementInvalid, "SECRET_SQL_VALUE")
    Beskar::Logger.expects(:error).with("Failed to create security event (ActiveRecord::StatementInvalid)", component: :WAF)
    @waf.record_violation(@ip, @waf.analyze_request(request("/.env")))
    assert_equal 95, @waf.get_current_score(@ip)
    assert Beskar::BannedIp.banned?(@ip)
  end

  private

  def request(path, query: "", method: "GET")
    ActionDispatch::TestRequest.create("PATH_INFO" => path, "QUERY_STRING" => query,
      "REQUEST_METHOD" => method, "REMOTE_ADDR" => @ip, "HTTP_USER_AGENT" => "SECRET_HEADER")
  end
end
