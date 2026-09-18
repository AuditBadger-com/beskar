require_relative "../application_system_test_case"

class DashboardSystemTest < ApplicationSystemTestCase
  test "export form submits an explicit reason and records the disclosed page" do
    create(:security_event, event_type: "export_probe")
    visit "/beskar/security_events?event_type=export_probe"
    fill_in "Export reason", with: "Case 42: browser export"
    select "JSON", from: "Export format"
    click_button "Export"
    assert_current_path "/beskar/security_events/export", ignore_query: true
    assert_text "export_probe"
    entry = Beskar::AdministrativeAction.order(:id).last
    assert_equal "audit_exported", entry.action
    assert_equal "Case 42: browser export", entry.reason
    assert_equal "export_probe", entry.after_state.dig("filters", "event_type")
    assert_equal 1, entry.after_state["count"]
  end

  test "presets use server time even with a different browser zone and clock" do
    browser_timezone("Pacific/Auckland")
    visit "/beskar/banned_ips/new"
    fill_in "IP Address", with: "198.51.100.221"
    select "Manual Ban", from: "Ban Reason"
    choose "duration_3600"
    fill_in "Administrative reason", with: "Browser preset"
    assert_text "1 Hour"
    assert_equal "", find_field("Custom Expiry Date/Time (UTC)").value
    page.execute_script("Date.now = () => 2208988800000")
    earliest = Time.current + 1.hour
    click_button "Ban IP Address"
    assert_ban_notice %r{\A/beskar/banned_ips/\d+\z}, "has been banned successfully"
    ban = Beskar::BannedIp.find_by!(ip_address: "198.51.100.221")
    assert_operator ban.expires_at, :>=, earliest
    assert_operator ban.expires_at, :<=, Time.current + 1.hour
    assert_equal 1, Beskar::AdministrativeAction.where(target_id: ban.id).count
    assert_no_script_errors
  end

  test "UTC editing and quick extension stay exact through browser DST and repeat initialization" do
    ["America/New_York", "Europe/Warsaw"].each_with_index do |zone, index|
      browser_timezone(zone)
      expiry = Time.utc(2030, 11, 3, 1, 30)
      ban = create(:banned_ip, ip_address: "198.51.100.#{222 + index}", reason: "manual_ban", expires_at: expiry)
      visit "/beskar/banned_ips/#{ban.id}/edit"
      assert_match(/2030-11-03T01:30/, find_field("Expiry Date/Time (UTC)").value)
      3.times { page.execute_script("document.dispatchEvent(new Event('turbo:load'))") }
      click_button "+1 Hour"
      assert_match(/2030-11-03T02:30/, find_field("Expiry Date/Time (UTC)").value)
      fill_in "Administrative reason", with: "Browser extension"
      click_button "Update Ban"
      assert_ban_notice "/beskar/banned_ips/#{ban.id}", "has been updated"
      assert_equal expiry + 1.hour, ban.reload.expires_at
      assert_equal 1, ban.violation_count
      assert_equal 1, Beskar::AdministrativeAction.where(target_id: ban.id).count
      assert_no_script_errors
    end
  end

  test "success checks wait for delayed native navigation instead of an outgoing notice" do
    ban = create(:banned_ip, reason: "manual_ban", details: "Before review")
    visit "/beskar/banned_ips/#{ban.id}/edit"
    fill_in "Administrative reason", with: "Delayed navigation review"
    fill_in "Additional Details", with: "After delayed review"
    page.execute_script(<<~JS, find("form[data-beskar-ban-form]"))
      const form = arguments[0];
      const notice = document.createElement('div');
      notice.className = 'alert alert-success';
      notice.textContent = 'has been updated';
      form.before(notice);
      // Deliberately keep matching text in the outgoing document while the
      // native submission is pending. Text alone must not signal completion.
      form.addEventListener('submit', (event) => {
        event.preventDefault();
        setTimeout(() => HTMLFormElement.prototype.submit.call(form), 250);
      }, { once: true });
    JS

    click_button "Update Ban"
    assert_ban_notice "/beskar/banned_ips/#{ban.id}", "has been updated"
    assert_equal "After delayed review", ban.reload.details
    assert_equal 1, Beskar::AdministrativeAction.where(target_id: ban.id).count
    assert_no_script_errors
  end

  test "temporary and permanent controls work under nonce-only script policy" do
    browser_timezone("America/Los_Angeles")
    ban = create(:banned_ip, reason: "manual_ban", permanent: true, expires_at: nil)
    visit "/beskar/banned_ips/#{ban.id}/edit"
    assert_no_selector "#temporary-options", visible: true
    choose "Temporary Ban"
    assert_selector "#temporary-options", visible: true
    assert find_field("Expiry Date/Time (UTC)").value.present?
    fill_in "Expiry Date/Time (UTC)", with: Time.utc(2031, 3, 9, 2, 30)
    fill_in "Administrative reason", with: "Temporary after review"
    click_button "Update Ban"
    assert_ban_notice "/beskar/banned_ips/#{ban.id}", "has been updated"
    refute ban.reload.permanent?
    assert_equal Time.utc(2031, 3, 9, 2, 30), ban.expires_at
    click_link "Edit", exact: true
    assert_current_path "/beskar/banned_ips/#{ban.id}/edit"
    click_button "Make Permanent"
    assert_no_selector "#temporary-options", visible: true
    fill_in "Administrative reason", with: "Permanent after review"
    click_button "Update Ban"
    assert_ban_notice "/beskar/banned_ips/#{ban.id}", "has been updated"
    assert ban.reload.permanent?
    assert_nil ban.expires_at
    assert_no_script_errors
  end

  test "editing preserves a custom reason and an unchanged microsecond expiry" do
    browser_timezone("Asia/Kathmandu")
    expiry = Time.iso8601("2030-01-01T09:15:00.123456Z")
    ban = create(:banned_ip, reason: "Case ABC: reviewed activity", expires_at: expiry)
    visit "/beskar/banned_ips/#{ban.id}/edit"
    assert_equal ban.reason, find_field("Ban Reason").value
    assert_equal "2030-01-01T09:15:00.123", find_field("Expiry Date/Time (UTC)").value
    fill_in "Administrative reason", with: "Retain original expiry"
    click_button "Update Ban"
    assert_ban_notice "/beskar/banned_ips/#{ban.id}", "has been updated"
    assert_equal expiry, ban.reload.expires_at
    assert_equal "Case ABC: reviewed activity", ban.reason
    assert_no_script_errors
  end

  test "validation feedback persists and retry preserves the selected duration" do
    visit "/beskar/banned_ips/new"
    fill_in "IP Address", with: "not-an-ip"
    select "Manual Ban", from: "Ban Reason"
    choose "duration_86400"
    fill_in "Administrative reason", with: "Validation retry"
    click_button "Ban IP Address"
    assert_current_path "/beskar/banned_ips"
    assert_selector ".alert-danger", text: "must be a valid individual IP address"
    assert find_field("duration_86400").checked?
    assert_equal "", find_field("Custom Expiry Date/Time (UTC)").value
    sleep 5.1 # The former layout removed even validation errors after 5 seconds.
    assert_selector ".alert-danger", text: "must be a valid individual IP address"
    fill_in "IP Address", with: "198.51.100.225"
    earliest = Time.current + 24.hours
    click_button "Ban IP Address"
    assert_ban_notice %r{\A/beskar/banned_ips/\d+\z}, "has been banned successfully"
    ban = Beskar::BannedIp.find_by!(ip_address: "198.51.100.225")
    assert_operator ban.expires_at, :>=, earliest
    assert_operator ban.expires_at, :<=, Time.current + 24.hours
    assert_no_script_errors(expected_http_status: 422)
  end

  test "bulk selection clear cancellation and confirmed unban preserve one journal operation" do
    bans = create_list(:banned_ip, 2)
    visit "/beskar/banned_ips"
    assert_no_selector "#bulk-actions-bar", visible: true
    check "Select all bans"
    assert_selector "#selected-count", text: "2"
    click_button "Clear Selection"
    assert_no_selector "#bulk-actions-bar", visible: true
    check "Select all bans"
    fill_in "Administrative reason", with: "Bulk browser review"
    dismiss_confirm { click_button "Unban Selected" }
    assert_equal 2, Beskar::BannedIp.where(id: bans.map(&:id)).count
    assert_empty Beskar::AdministrativeAction.all
    accept_confirm { click_button "Unban Selected" }
    assert_ban_notice "/beskar/banned_ips", "2 ban(s) unbanned"
    assert_empty Beskar::BannedIp.where(id: bans.map(&:id))
    entries = Beskar::AdministrativeAction.all
    assert_equal 2, entries.count
    assert_equal 1, entries.distinct.count(:operation_id)
    assert_no_script_errors
  end

  test "page size preserves filters and resets page without duplicate hidden values" do
    create_list(:banned_ip, 12, :active)
    visit "/beskar/banned_ips?status=active&per_page=10&page=2"
    select "25", from: "Per page:"
    assert_selector "#bulk-actions-form tbody tr", count: 12
    query = Rack::Utils.parse_query(URI.parse(page.current_url).query)
    assert_equal "25", query["per_page"]
    assert_equal "active", query["status"]
    refute query.key?("page")
    assert_no_script_errors
  end

  test "loaded Turbo does not intercept native dashboard links or submit a mutation twice" do
    ban = create(:banned_ip, reason: "manual_ban")
    visit "/beskar/banned_ips/#{ban.id}"
    load_host_turbo
    page.execute_script("window.beskarNavigationProbe = true")
    click_link "Edit", exact: true
    assert_current_path "/beskar/banned_ips/#{ban.id}/edit"
    assert_selector "h3", text: "Edit IP Ban"
    assert_nil page.evaluate_script("window.beskarNavigationProbe")
    load_host_turbo
    fill_in "Administrative reason", with: "Turbo loaded review"
    fill_in "Additional Details", with: "Reviewed exactly once"
    click_button "Update Ban"
    assert_ban_notice "/beskar/banned_ips/#{ban.id}", "has been updated"
    assert_equal 1, Beskar::AdministrativeAction.where(target_id: ban.id).count
    page.go_back
    assert_current_path "/beskar/banned_ips/#{ban.id}/edit"
    assert_selector "h3", text: "Edit IP Ban"
    click_button "+1 Hour"
    assert find_field("Expiry Date/Time (UTC)").value.present?
    assert_no_script_errors
  end

  test "native creation and review deletion still work with JavaScript disabled and real CSRF" do
    page.driver.browser.execute_cdp("Emulation.setScriptExecutionDisabled", value: true)
    visit "/beskar/banned_ips/new"
    fill_in "IP Address", with: "198.51.100.224"
    select "Manual Ban", from: "Ban Reason"
    choose "Permanent Ban"
    fill_in "Administrative reason", with: "No scripts review"
    click_button "Ban IP Address"
    assert_ban_notice %r{\A/beskar/banned_ips/\d+\z}, "has been banned successfully"
    ban = Beskar::BannedIp.find_by!(ip_address: "198.51.100.224")
    assert ban.permanent?
    click_link "Unban", exact: true
    assert_selector "h3", text: "Unban"
    fill_in "Reason for this administrative action", with: "No scripts reversal"
    click_button "Confirm unban"
    assert_ban_notice "/beskar/banned_ips", "has been unbanned"
    refute Beskar::BannedIp.exists?(ban.id)
    assert_equal 2, Beskar::AdministrativeAction.where(target_id: ban.id).count
  ensure
    page.driver.browser.execute_cdp("Emulation.setScriptExecutionDisabled", value: false)
  end

  private

  def assert_ban_notice(path, message)
    # A native submit can return before navigation begins. Do not read text
    # from the outgoing document while Chrome replaces it (CI Chrome 153 race).
    assert_current_path path
    # This also waits for same-path redirects, such as bulk unban, where the
    # URL alone cannot distinguish the old document from the completed action.
    assert_selector ".alert-success", text: message
  end
end
