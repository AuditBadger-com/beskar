require "test_helper"

class WafAnalysisDisplayTest < ActionDispatch::IntegrationTest
  setup do
    Beskar.configuration.authenticate_admin = ->(_) { true }
    Beskar.configuration.waf.merge!(enabled: true, auto_block: true, score_threshold: 95, decay_enabled: false)
  end

  test "captured request is visible on WAF event and ban pages and safely escaped" do
    path = "/.env/<script>alert(1)</script>"
    request = ActionDispatch::TestRequest.create("PATH_INFO" => path, "QUERY_STRING" => "token=PRIVATE_QUERY",
      "REMOTE_ADDR" => "198.51.100.45")
    waf = Beskar::Services::Waf
    waf.record_violation(request.remote_ip, waf.analyze_request(request))
    event = Beskar::SecurityEvent.last
    ban = Beskar::BannedIp.find_by!(ip_address: request.remote_ip)

    ["/beskar/security_events/#{event.id}", "/beskar/banned_ips/#{ban.id}"].each do |url|
      get url
      assert_response :success
      assert_select "[data-waf-analysis] [data-request-path]", text: path
      assert_select "[data-waf-analysis]", text: /config_files:0/
      assert_select "[data-waf-analysis] script", count: 0
      refute_includes response.body, "PRIVATE_QUERY"
    end
    assert_select "tbody td", text: path

    [{}, {event_type: "waf_violation"}].each do |filters|
      get "/beskar/security_events", params: filters
      assert_response :success
      assert_select "th", text: "Requested Path"
      assert_select "td[data-request-path]", text: path
      assert_select "td[data-request-path] script", count: 0
      refute_includes response.body, "PRIVATE_QUERY"
    end
  end

  test "older WAF events and bans explicitly report missing paths" do
    event = create(:security_event, event_type: "waf_violation", metadata: {waf_analysis: {highest_severity: "high"}})
    ban = create(:banned_ip, reason: "waf_violation", metadata: {})
    ["/beskar/security_events/#{event.id}", "/beskar/banned_ips/#{ban.id}"].each do |url|
      get url
      assert_response :success
      assert_select "[data-request-path]", text: "Not recorded"
    end
    get "/beskar/security_events", params: {event_type: "waf_violation"}
    assert_response :success
    assert_select "td[data-request-path]", text: "Not recorded"
  end

  test "WAF display respects filters applied after capture" do
    event = create(:security_event, event_type: "waf_violation", metadata: {waf_analysis: {request_path: "/private-path"}})
    Rails.application.config.stubs(:filter_parameters).returns([:request_path])
    get "/beskar/security_events/#{event.id}"
    assert_response :success
    assert_select "[data-request-path]", text: "[FILTERED]"
    refute_includes response.body, "/private-path"
    get "/beskar/security_events"
    assert_response :success
    assert_select "td[data-request-path]", text: "[FILTERED]"
    refute_includes response.body, "/private-path"
  end
end
