# Rust performance assessment

Assessed on 2026-09-11 against the current working tree, including uncommitted remediation changes. This records an exploratory assessment for future consideration; no Rust implementation was built or benchmarked.

**There is room for a small Rust component, especially WAF matching and large IP/CIDR lists. Current evidence favors reducing database work before introducing Rust.** A broad rewrite is not justified by the measurements below.

The intended constraints are performance improvements only, no Rust toolchain requirement for applications installing Beskar, precompiled binaries for supported platforms and architectures, and no net increase in request overhead.

[Original project review](../audits/project-review.md) and [Archived project overview](../archive/project-documentation.md) describe an older architecture in several places. The current implementation and [State storage](../operations/state-storage.md) establish that ordinary requests query both bans and rate-limit state. Authentication attempts and WAF violations also perform transactional state updates. Translating their calculations to Rust would leave database round trips and lock contention in place.

**Local measurements**

A read-only diagnostic used Ruby 4.0.6 with YJIT, Rails 8.0.2.1, and local SQLite on Linux x86-64. It measured a single thread with warm code and database state, SQL query caching disabled, and logging suppressed. SQLite query-only mode prevented writes during the measurements.

The clean request was `/products/42?sort=recent`, with an unbanned, unrestricted IP and two nonmatching whitelist CIDRs. The downstream endpoint returned a trivial HTTP 200 response. Each operation received 2,000 warmup iterations, followed by three timed batches of 10,000 iterations; the larger whitelist cases used batches of 1,000. Garbage collection ran before each batch and remained enabled during timing.

| Operation | Approximate average time per operation |
| --- | ---: |
| WAF analysis, clean URL, all 55 patterns | 2.4 µs |
| Whitelist lookup, 2 CIDRs | 1.2 µs |
| Whitelist lookup, 100 CIDRs, no match | 5.1–5.2 µs |
| Whitelist lookup, 1,000 CIDRs, no match | 40–41 µs |
| Ban lookup | 26–29 µs |
| IP rate-limit preview | 14–16 µs |
| Complete clean middleware call, 2 CIDRs | 52–59 µs |
| Device detection for one browser user agent | 7.8 µs |

Ranges summarize batch averages across the diagnostic runs, not latency percentiles. The complete clean middleware call allocated approximately 310 Ruby objects, while its isolated WAF analysis allocated one. Instrumentation confirmed two SELECTs per clean middleware call: one for bans and one for IP rate-limit state.

These measurements exclude the host application's real work, a full HTTP server stack, concurrent traffic, remote database latency, populated authentication history, and attack-path persistence. They are not production throughput or latency guarantees and do not establish a Rust speedup.

Even eliminating the WAF computation entirely would save only about **4–5% of Beskar's measured clean-request overhead** in this setup. Its share of the full host request would be smaller. Large whitelist configurations present a more substantial CPU cost.

**Candidates worth considering**

| Component | Possible Rust implementation | Assessment |
| --- | --- | --- |
| [WAF matcher](../../lib/beskar/services/waf.rb) | Compile the rule set once, match through one native call, and return compact rule IDs | Best initial experiment, particularly as rule counts or input lengths grow; current short clean-path cost is already small |
| [IP whitelist](../../lib/beskar/services/ip_whitelist.rb) | Compiled IPv4/IPv6 prefix tree, with exact-address lookup where appropriate | Promising for large lists; replacing linear scanning is the principal opportunity in either language |
| [Device detection](../../lib/beskar/services/device_detector.rb) | Combine classification and extraction in one native operation | Secondary candidate because it mainly affects authentication rather than every ordinary request |
| [Rate limiting](../../lib/beskar/services/rate_limiter.rb), [bans](../../app/models/beskar/banned_ip.rb), and audit persistence | Translate existing calculations and orchestration | Low priority: database round trips, transactions, and contention remain |
| Risk arithmetic and geographic distance | Native numeric calculations | Small workloads; optimize history retrieval and repeated enrichment first |

Rust's [RegexSet](https://docs.rs/regex/latest/regex/struct.RegexSet.html) can identify matching expressions in one pass, which fits the WAF's need to report matching rules without extracting captures. A performance-only port must preserve all matching rules, result ordering, case handling, encoding behavior, and path/query interpretation. Ruby and Rust regex semantics differ, and Rust's [regex crate](https://docs.rs/regex/latest/regex/) does not support arbitrary look-around or backreferences. Differential tests against the Ruby implementation are necessary; a literal pattern translation is insufficient.

For IP lookup, native acceleration would also need to avoid rebuilding configuration or comparing the entire source list on each request. Configuration updates must preserve the existing invalidation contract. Process-local native counters or ban snapshots would require a separate coordination design to preserve cross-worker enforcement correctness.

**Distribution without a Rust installation requirement**

A Ruby native extension built with [Magnus](https://github.com/matsadler/magnus) and the [rb-sys distribution tooling](https://oxidize-rb.org/docs/deployment/) is a suitable approach. Rust would be a maintainer/CI build dependency; consuming applications would load the compiled library.

- Publish platform-specific gems containing release binaries, allowing RubyGems/Bundler to select the applicable artifact.
- Define and test the supported matrix explicitly: Linux x86-64 and ARM64 with glibc and musl, macOS Intel and Apple Silicon, and Windows if included in Beskar's supported platforms.
- Cover supported Ruby ABIs as well as OS and CPU architecture. At assessment time, this repository's main CI matrix uses Ruby 3.4 and 4.0.6. Do not assume one extension binary covers all Ruby versions.
- Account for minimum OS/libc versions and CPU instruction compatibility when building distributable binaries.
- Keep a pure Ruby gem variant for unsupported combinations, without automatically requiring Rust compilation during installation. Verify its detection behavior matches the native implementation.
- Test installation and execution of published artifacts in environments without a Rust toolchain.

RubyGems supports platform-specific binary gems through the [platform attribute](https://guides.rubygems.org/specification-reference/#platform). Platform support would be an explicit release commitment, not a promise that one universal binary works everywhere.

**Keeping request overhead small**

Load the extension and compile its rule configuration once at boot. Select the native or Ruby implementation at boot as well. Use one native call per analysis, pass existing strings with minimal copying, and return a compact result. Construct detailed Ruby metadata only when a match needs it. Keep database access and enforcement decisions coordinated through the established authority.

The Ruby/native boundary has a cost. Releasing the Ruby GVL, copying strings, or converting nested Ruby structures may cost more than a small calculation saves. The requirement should therefore be a measured net improvement, including allocations and tail latency, rather than a claim of zero overhead.

Before implementing Rust, investigate repeated IP parsing and whitelist checks, eager debug-message construction, repeated configuration processing, and database access. Reducing database work must preserve the consistency guarantees introduced by the remediation; reinstating stale process-local enforcement caches would change behavior.

If revisited, first establish representative benchmarks for clean requests, already-blocked requests, authentication attempts, large whitelists, long inputs, and WAF violations under concurrency. Measure p50/p95/p99 latency, CPU, allocations, database queries, and lock waits with the intended production backend. Then prototype only the WAF matcher and, if large lists are expected, the CIDR matcher. Retain Rust only if equivalent behavior and meaningful end-to-end gains justify maintaining the binary matrix.
