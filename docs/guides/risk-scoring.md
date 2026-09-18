# Authentication risk evidence

Authentication now uses one `RiskAssessment` snapshot for the decision, login
audit, and lock context. `metadata["risk_assessment"]` contains a version, assessment
time, observation/enforcement mode, score, and named factors with points/evidence.
Factor points, including negative cap adjustments, sum to the recorded score.
`device_info` and `geolocation` carry the same facts used by that assessment.

## Factors and limits

| Factor | Points |
| --- | ---: |
| Successful / failed credentials | 1 / 10 |
| Missing User-Agent | 20 |
| Bot-like User-Agent claim | 30 |
| User-Agent shorter than 20 or longer than 500 characters | 15 |
| Test/debug/script marker in User-Agent | 10 |
| More than three parentheses in User-Agent | 5 |
| Chrome/Firefox major version below the legacy cutoff of 90 | 5 |
| Mobile User-Agent, application-local hour 22:00–05:59 | 5 |
| At least two recent account failures in ten minutes | 20 |
| Private or unavailable geographic location | 10 |
| Impossible-travel heuristic | 25 |
| Changed known country | 10 |

User-Agent factors are capped at 50, geographic factors at 30, and total risk at
100. The version-90 cutoff is a retained heuristic, not a browser support policy.
Password contents and length are no longer used as risk factors. User-Agent
assessment/storage is bounded to 500 sanitized characters; the length factor uses
the original length. User-Agent risk logging no longer includes the raw header.
Other audit surfaces still need the privacy work tracked under F11.

These are heuristic weights, not calibrated probabilities. A travel signal alone
does not reach the default locking threshold of 75. IP geolocation can describe a
VPN, proxy, mobile carrier, or shared egress; User-Agent values can be forged. None
of these factors proves the identity, intent, or physical position of a person.

## Timestamped geographic history

The geographic assessment considers up to the latest 20 success records in four
hours, explicitly ordered by `created_at` and ID. A history record must have
`authentication.allowed == true` and must not report `locked_now == true`.
Blocked outcomes, legacy successes without explicit admission evidence, future
events, and malformed records are not travel baselines. Observation-mode records
are excluded from enforcement assessments. Monitor assessments may inspect
enforced history as well as observations.

Every usable location is paired with its own event timestamp and ID. Travel uses
the newest comparable coordinate observation, actual elapsed seconds, and a
1,000 km/h heuristic. Evidence includes the previous event ID/time, elapsed
seconds, distance, and speed threshold. Country change independently uses the
newest known-country observation. JSON string/symbol keys and numeric coordinate
strings are normalized; missing, non-finite, or out-of-range coordinates cannot
produce travel evidence. Equal, future, or malformed times are ignored.

History remains optional audit data, not an independent travel-enforcement store.
Disabled/missing audits reduce available history. Concurrent authentications do
not serialize geographic observations, and records outside the bounded window
are not considered. The recent-failure factor similarly examines the latest 20
failures within ten minutes, excluding observations in enforcement mode. These
limits bound database work; they are not exhaustive forensic analysis.

The integer `calculate_location_risk` compatibility method accepts timestamped
observations (`location`, `occurred_at`, optional `event_id`), or one previous
location with a positive elapsed duration. An untimestamped collection no longer
shares one duration across all entries. Prefer `assess_location` for evidence.

## Providers and configuration changes

The default `:mock` provider produces synthetic data for development. Synthetic
locations never establish country/travel evidence or add geographic risk. Private
addresses still receive the explicitly labeled unavailable-location factor.
Configure `:maxmind` with an actual city database for geographic observations.
Unknown provider names and the unimplemented IP2Location provider are rejected
by configuration validation and service construction. Valid MaxMind lookups may
still return unknown data when enrichment is unavailable; this is not fabricated
geographic evidence. See [Configuration](configuration.md).

Cache keys include provider and MaxMind database identity (path, inode, size,
modification time). New service instances/readers follow configuration or database
generation changes. An in-flight service instance can finish using its snapshot.
Old cache entries expire under their TTL; they are not reused across generations.
Any Rails.cache backend remains supported, including NullStore and unavailable
optional caches. Replacements that preserve every identity attribute require an
explicit reader reset and cache invalidation, or a new database path.

## Locks, observation, and trust

The actual computed travel, country-change, and bot/suspicious flags drive lock
reasons. Lock audits include the same risk factors and authentication attempt ID.
When risk locking is enabled, login metadata includes `lock_decision` with the
threshold, adapter availability, `would_lock`, and whether policy permits
enforcement. `would_lock` describes eligibility, not successful persistence;
`authentication.locked_now` records the actual result. Monitor mode/whitelists do
not mutate accounts. Unknown/custom strategies are not advertised as available.

There is **no automatic trust discount**. Repeated IP use, lock attempts, and
manual/automatic unlocks do not prove a verified device or confirmed recovery.
The former 30% scoring discount and complete geographic bypass have been removed.
A future trust mechanism needs explicit host-verified identity/recovery evidence.

## Upgrade and validation

No new migration is required for this batch. Legacy login records without explicit
admission evidence are not promoted into geographic history. Scores can rise when
unsafe trust discounts disappear, and fall when mock geography or erroneous old-
browser penalties disappear. Review recorded factors in monitor mode before
enabling risk locking or opt-in emergency resets; do not assume old thresholds
have been calibrated for the corrected inputs.

Local coverage includes real Devise/native logins, persisted JSON history,
chronological ordering, midnight boundaries, modern browsers, malformed locations,
provider/cache isolation, monitor/whitelist policy, and matching lock evidence.
Real MaxMind database accuracy, production false-positive rates, and verified
recovery/notification delivery remain unverified or unfinished. See
[Authentication](authentication.md) and [Repair status](../audits/repair-status.md).
