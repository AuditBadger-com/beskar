require "test_helper"

class AdministrativeActionsTest < ActionDispatch::IntegrationTest
  setup do
    @actor = create(:user)
    actor_id = "admin:#{@actor.id}"
    Beskar.configure do |config|
      config.authenticate_admin = ->(_) { true }
      config.audit_actor = ->(_) { actor_id }
    end
    @ban = create(:banned_ip, expires_at: 1.day.from_now, violation_count: 2)
  end

  test "create records server actor reason correlation and bounded state in the same transaction" do
    post "/beskar/banned_ips", params: {audit_reason: "Case 42: reviewed abuse", actor: "attacker", operation_id: "spoofed",
                                        ban_type: "temporary", duration: 3600, banned_ip: {ip_address: "198.51.100.91", reason: "manual_ban", metadata: {password: "SECRET_PASSWORD"}}},
      headers: {"X-Request-ID" => "request-42"}
    assert_response :redirect
    entry = Beskar::AdministrativeAction.last
    assert_equal "admin:#{@actor.id}", entry.actor
    assert_equal "Case 42: reviewed abuse", entry.reason
    assert_equal "ban_created", entry.action
    assert_equal "request-42", entry.request_id
    assert_match(/\A[0-9a-f-]{36}\z/, entry.operation_id)
    refute_equal "spoofed", entry.operation_id
    assert_empty entry.before_state
    assert_equal "198.51.100.91", entry.after_state["ip_address"]
    assert_equal "[FILTERED]", entry.after_state.dig("metadata", "password")
    assert_equal Beskar::BannedIp.last.id, entry.target_id
  end

  test "update and unban preserve before and after history beyond ban and actor deletion" do
    original = @ban.reason
    patch ban_path, params: {audit_reason: "Case 43: adjusted classification", banned_ip: {reason: "manual_review"}}
    assert_response :redirect
    update = Beskar::AdministrativeAction.last
    assert_equal original, update.before_state["reason"]
    assert_equal "manual_review", update.after_state["reason"]
    delete ban_path, params: {audit_reason: "Case 43: confirmed false positive"}
    assert_response :redirect
    deletion = Beskar::AdministrativeAction.last
    assert_equal "ban_unbanned", deletion.action
    assert_equal "manual_review", deletion.before_state["reason"]
    assert_empty deletion.after_state
    refute Beskar::BannedIp.exists?(@ban.id)
    actor_id = @actor.id
    @actor.destroy!
    assert_equal "admin:#{actor_id}", deletion.reload.actor
    get "/beskar/administrative_actions/#{deletion.id}"
    assert_response :success
    assert_includes response.body, "Case 43: confirmed false positive"
  end

  test "extension changes deadline without manufacturing another violation" do
    previous_expiry = @ban.expires_at
    post "#{ban_path}/extend", params: {duration: "24h", audit_reason: "Case 44: ongoing review"}
    assert_response :redirect
    assert_in_delta previous_expiry.to_f + 24.hours, @ban.reload.expires_at.to_f, 0.001
    assert_equal 2, @ban.violation_count
    assert_equal "ban_extended", Beskar::AdministrativeAction.last.action
    post "#{ban_path}/extend", params: {duration: "permanent", audit_reason: "Case 44: indefinite restriction approved"}
    assert_response :redirect
    assert @ban.reload.permanent?
    assert_nil @ban.expires_at
    assert_equal "ban_made_permanent", Beskar::AdministrativeAction.last.action
  end

  test "missing actor allows reads but rejects every dashboard mutation" do
    Beskar.configuration.audit_actor = nil
    get "/beskar/banned_ips"
    assert_response :success
    assert_no_difference ["Beskar::BannedIp.count", "Beskar::AdministrativeAction.count"] do
      delete ban_path, params: {audit_reason: "Case 45"}
      assert_response :service_unavailable
      patch ban_path, params: {audit_reason: "Case 45", banned_ip: {reason: "changed"}}
      assert_response :service_unavailable
      post "#{ban_path}/extend", params: {audit_reason: "Case 45", duration: "24h"}
      assert_response :service_unavailable
      post "/beskar/banned_ips/bulk_action", params: {audit_reason: "Case 45", bulk_action: "unban", ip_ids: [@ban.id]}
      assert_response :service_unavailable
      post "/beskar/banned_ips", params: {audit_reason: "Case 45", banned_ip: {ip_address: "198.51.100.92", reason: "manual"}}
      assert_response :service_unavailable
    end
  end

  test "authorization and CSRF run before actor resolution or changes" do
    calls = 0
    Beskar.configuration.audit_actor = ->(_) {
      calls += 1
      "admin:server"
    }
    Beskar.configuration.authenticate_admin = ->(_) { false }
    delete ban_path, params: {audit_reason: "Case 46"}
    assert_response :not_found
    assert_equal 0, calls
    Beskar.configuration.authenticate_admin = ->(_) { true }
    original = Beskar::ApplicationController.allow_forgery_protection
    Beskar::ApplicationController.allow_forgery_protection = true
    delete ban_path, params: {audit_reason: "Case 46"}
    assert_response :unprocessable_content
    assert_equal 0, calls
    assert Beskar::BannedIp.exists?(@ban.id)
    assert_empty Beskar::AdministrativeAction.all
  ensure
    Beskar::ApplicationController.allow_forgery_protection = original unless original.nil?
  end

  test "invalid actor callback and missing reason cannot produce unattributed changes" do
    Beskar.configuration.audit_actor = ->(_) { raise "SECRET_CALLBACK" }
    delete ban_path, params: {audit_reason: "Case 47"}
    assert_response :service_unavailable
    refute_includes response.body, "SECRET_CALLBACK"
    Beskar.configuration.audit_actor = ->(_) { "admin:server" }
    [nil, " ", "x" * 1001, {actor: "spoofed"}].each do |reason|
      delete ban_path, params: {audit_reason: reason}
      assert_response :unprocessable_content
    end
    assert Beskar::BannedIp.exists?(@ban.id)
    assert_empty Beskar::AdministrativeAction.all
  end

  test "required journal failure rolls back create update and delete" do
    previous = @ban.attributes
    Beskar::AdministrativeAction.stubs(:create!).raises(ActiveRecord::StatementInvalid, "SECRET_DATABASE")
    patch ban_path, params: {audit_reason: "Case 48", banned_ip: {reason: "changed"}}
    assert_response :service_unavailable
    assert_equal previous, @ban.reload.attributes
    delete ban_path, params: {audit_reason: "Case 48"}
    assert_response :service_unavailable
    assert Beskar::BannedIp.exists?(@ban.id)
    assert_no_difference "Beskar::BannedIp.count" do
      post "/beskar/banned_ips", params: {audit_reason: "Case 48", banned_ip: {ip_address: "198.51.100.93", reason: "manual"}}
      assert_response :service_unavailable
    end
    refute_includes response.body, "SECRET_DATABASE"
  end

  test "aborted destruction never reports a successful unban" do
    callback = -> { throw :abort }
    Beskar::BannedIp.set_callback(:destroy, :before, callback)
    delete ban_path, params: {audit_reason: "Case 49"}
    assert_response :service_unavailable
    assert Beskar::BannedIp.exists?(@ban.id)
    assert_empty Beskar::AdministrativeAction.all
  ensure
    Beskar::BannedIp.skip_callback(:destroy, :before, callback)
  end

  test "bulk changes are deduplicated correlated and all or nothing" do
    other = create(:banned_ip)
    post "/beskar/banned_ips/bulk_action", params: {bulk_action: "make_permanent", ip_ids: [@ban.id, other.id, @ban.id], audit_reason: "Case 50"}
    assert_response :redirect
    entries = Beskar::AdministrativeAction.order(:id).to_a
    assert_equal 2, entries.size
    assert_equal 1, entries.map(&:operation_id).uniq.size
    assert_equal [@ban.id, other.id].sort, entries.map(&:target_id).sort
    assert entries.all? { |entry| entry.after_state["permanent"] && entry.after_state["expires_at"].nil? }
    post "/beskar/banned_ips/bulk_action", params: {bulk_action: "unban", ip_ids: [@ban.id, other.id], audit_reason: "Case 50 closed"}
    assert_response :redirect
    assert_equal 4, Beskar::AdministrativeAction.count
    refute Beskar::BannedIp.exists?(@ban.id)
    refute Beskar::BannedIp.exists?(other.id)
  end

  test "a failure on a later bulk item rolls back earlier changes and history rows" do
    other = create(:banned_ip)
    failing_id = other.id
    callback = -> { raise ActiveRecord::RecordInvalid, self if target_id == failing_id }
    Beskar::AdministrativeAction.set_callback(:create, :before, callback)
    post "/beskar/banned_ips/bulk_action", params: {bulk_action: "make_permanent", ip_ids: [@ban.id, other.id], audit_reason: "Case 51"}
    assert_response :service_unavailable
    refute @ban.reload.permanent?
    refute other.reload.permanent?
    assert_empty Beskar::AdministrativeAction.all
  ensure
    Beskar::AdministrativeAction.skip_callback(:create, :before, callback)
  end

  test "malformed oversized or partly missing selections never partially apply" do
    [[], [@ban.id, "bad"], Array.new(101, @ban.id)].each do |ids|
      post "/beskar/banned_ips/bulk_action", params: {bulk_action: "unban", ip_ids: ids, audit_reason: "Case 52"}
      assert_response :unprocessable_content
    end
    post "/beskar/banned_ips/bulk_action", params: {bulk_action: "unban", ip_ids: [@ban.id, @ban.id + 99999], audit_reason: "Case 52"}
    assert_response :not_found
    assert Beskar::BannedIp.exists?(@ban.id)
    assert_empty Beskar::AdministrativeAction.all
  end

  test "unknown duration IP edits and no-op updates do not create misleading history" do
    post "#{ban_path}/extend", params: {duration: "invalid", audit_reason: "Case 53"}
    assert_response :unprocessable_content
    original_ip = @ban.ip_address
    patch ban_path, params: {audit_reason: "Case 53", banned_ip: {ip_address: "198.51.100.94"}}
    assert_response :unprocessable_content
    assert_equal original_ip, @ban.reload.ip_address
    patch ban_path, params: {audit_reason: "Case 53", banned_ip: {reason: @ban.reason}}
    assert_response :redirect
    assert_empty Beskar::AdministrativeAction.all
  end

  test "stored changes are journaled even when bounded snapshots look identical" do
    @ban.update!(expires_at: 1.day.from_now.change(usec: 100_000))
    deadline = @ban.expires_at + 0.2
    assert_difference "Beskar::AdministrativeAction.count", 1 do
      patch ban_path, params: {audit_reason: "Case 53: precise correction", banned_ip: {expires_at: deadline.iso8601(6)}}
      assert_response :redirect
    end
    assert_in_delta deadline.to_f, @ban.reload.expires_at.to_f, 0.00001
  end

  test "service creation rejects existing bans without fabricating creation history" do
    service = Beskar::Services::AdministrativeBans.new(actor: "admin:server", reason: "Case 53", request_id: "request-53")
    assert_no_difference "Beskar::AdministrativeAction.count" do
      assert_raises(Beskar::Services::AdministrativeBans::InvalidInput) { service.create!(@ban) }
    end
  end

  test "ordinary instance CRUD rejects history rewrites and read views escape and filter data" do
    patch ban_path, params: {audit_reason: "<script>case54</script>", banned_ip: {metadata: {secret_token: "SECRET_TOKEN"}, details: "<script>detail</script>"}}
    assert_response :redirect
    entry = Beskar::AdministrativeAction.last
    assert_raises(ActiveRecord::ReadOnlyRecord) { entry.update!(reason: "rewritten") }
    assert_raises(ActiveRecord::ReadOnlyRecord) { entry.destroy! }
    assert_raises(ActiveRecord::ReadOnlyRecord) { entry.delete }
    assert_raises(ActiveRecord::ReadOnlyRecord) { entry.update_columns(reason: "rewritten") }
    get "/beskar/administrative_actions/#{entry.id}"
    assert_response :success
    assert_equal "no-store", response.headers["Cache-Control"]
    assert_includes response.body, "&lt;script&gt;case54&lt;/script&gt;"
    refute_includes response.body, "SECRET_TOKEN"
    assert_select "script", text: /case54/, count: 0
    Beskar.configuration.authenticate_admin = ->(_) { false }
    get "/beskar/administrative_actions/#{entry.id}"
    assert_response :not_found
    get "/beskar/administrative_actions"
    assert_response :not_found
  end

  test "review pages provide real forms with required reason and do not mutate on GET" do
    get "#{ban_path}/review", params: {operation: "unban"}
    assert_response :success
    assert_select "form[action='#{ban_path}'][method='post']"
    assert_select "input[name='_method'][value='delete']"
    assert_select "textarea[name='audit_reason'][required][maxlength='1000']"
    get "#{ban_path}/review", params: {operation: "extend"}
    assert_response :success
    assert_select "form[action='#{ban_path}/extend'][method='post']"
    assert_select "select[name='duration']"
    assert_empty Beskar::AdministrativeAction.all
    assert Beskar::BannedIp.exists?(@ban.id)
  end

  test "history index is bounded ordered and filterable after live targets disappear" do
    now = Time.current
    target_id = @ban.id
    Beskar::AdministrativeAction.insert_all!(101.times.map do |index|
      {actor: "admin:server", action: "ban_unbanned", reason: "Case #{index}", target_id: target_id,
       operation_id: SecureRandom.uuid, request_id: "request-#{index}", before_state: {}, after_state: {}, created_at: now}
    end)
    @ban.destroy!
    Beskar.configuration.audit_actor = nil
    get "/beskar/administrative_actions", params: {target_id: target_id, per_page: 999}
    assert_response :success
    assert_equal "no-store", response.headers["Cache-Control"]
    assert_select "tbody tr", count: 100
    assert_select "tbody tr:first-child", text: /Case 100/
    assert_select "nav a", text: "Next"
    get "/beskar/administrative_actions", params: {target_id: target_id, per_page: 100, page: 2}
    assert_response :success
    assert_select "tbody tr", count: 1
    assert_select "tbody tr", text: /Case 0/
    get "/beskar/administrative_actions", params: {target_id: target_id + 1}
    assert_response :success
    assert_select "tbody tr", count: 0
    [:patch, :delete].each do |method|
      assert_raises(ActionController::RoutingError) do
        Beskar::Engine.routes.recognize_path("/administrative_actions/1", method: method)
      end
    end
  end

  test "legacy history is filtered on reads without rewriting stored evidence" do
    patch ban_path, params: {audit_reason: "Case 55", banned_ip: {reason: "manual_review"}}
    entry = Beskar::AdministrativeAction.last
    records = Beskar::AdministrativeAction.where(id: entry.id)
    records.update_all(before_state: {password: "SECRET_LEGACY", safe: "original"})
    stored = records.pick(:before_state)
    get "/beskar/administrative_actions/#{entry.id}"
    assert_response :success
    refute_includes response.body, "SECRET_LEGACY"
    assert_includes response.body, "original"
    assert_equal stored, records.pick(:before_state)
  end

  private

  def ban_path
    "/beskar/banned_ips/#{@ban.id}"
  end
end
