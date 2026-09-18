# Monitor-only mode

Monitor mode lets you observe WAF and rate-limit decisions without rejecting
requests or automatically creating IP bans:

```ruby
Beskar.configure do |config|
  config.monitor_only = true
  config.waf[:enabled] = true
  config.waf[:auto_block] = true
end
```

The installer defaults to monitor mode in every environment. Turn it off explicitly
only after reviewing traffic and tuning thresholds.

## What is recorded

WAF violations remain available as `Beskar::SecurityEvent` records when
`config.waf[:create_security_events]` is enabled. Their metadata includes:

- `monitor_only_mode`: whether the observation was made in monitor mode.
- `would_be_blocked`: whether the threshold and auto-block policy would deny a
  non-whitelisted IP.
- `current_score`, `score_threshold`, and matched patterns.

Matched patterns contain rule identifiers and static descriptions, not URLs,
query strings, raw headers, or exception messages. Default exception scoring
requires independent scanner-path/format evidence (with resolved IP-spoof signals
handled separately). See [Audit data and WAF](../guides/audit-and-waf.md) before changing this
policy or interpreting exports.

Monitor WAF history, authentication counters, and rate-denial counters are stored
separately from enforcement state. Switching to enforcement does not promote
monitor observations into active counters or bans. Switching modes does not delete
either history; unexpired enforcement state from an earlier enforcement period
remains effective when enforcement resumes.

Existing manually created or previously enforced bans remain in the database, but
middleware does not enforce them while monitoring. Monitor mode does not prevent an
administrator from explicitly creating or modifying a ban.

## Review and enable enforcement

Use the dashboard, or inspect recent observations in the console:

```ruby
Beskar::SecurityEvent.where(event_type: "waf_violation")
  .where("created_at >= ?", 24.hours.ago)
  .find_each do |event|
    next unless event.metadata["monitor_only_mode"]
    puts [event.ip_address, event.metadata["would_be_blocked"],
      event.metadata["current_score"]].inspect
  end
```

Review false positives, configure trusted proxies and whitelist entries, then set:

```ruby
Beskar.configure do |config|
  config.monitor_only = false
end
```

Use `config.waf[:score_threshold]` to tune cumulative WAF scores.
`block_threshold` and nested `config.waf[:monitor_only]` are not supported options.

## Important limitations during remediation

Beskar's automatic account locks, current-attempt sign-outs, and emergency password
resets now honor monitor mode and the IP whitelist. Rails-native applications must
use the [admission and session-reader guards](../guides/authentication.md). Host application
restrictions—such as Devise's own failed-attempt Lockable policy or Rails' own rate
limiter—remain independent of Beskar monitor mode. Risk-enabled login audits now
include `lock_decision.would_lock`, adapter availability, enforcement policy, and
the scored evidence. Observed successes/failures do not supply enforced risk
history. See [Risk scoring](../guides/risk-scoring.md). Production calibration and real
notifications remain open; observation does not prove the signals are accurate.

Older versions created bans during monitoring. Existing bans cannot reliably be
classified as monitor-only after the fact. Review and explicitly remove any
unwanted legacy bans before enabling enforcement; this release does not silently
delete ban records.

See [state storage and upgrade notes](state-storage.md) for database requirements.
