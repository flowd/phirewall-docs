---
outline: deep
---

# Architecture

Phirewall's core decision engine uses an **evaluator pipeline**, a sequential chain of single-responsibility evaluator classes, each handling one type of firewall rule. The pipeline processes every request and short-circuits on the first decisive result.

## Evaluator Pipeline

When `Firewall::decide()` is called, it creates an `EvaluationContext` and passes the request through an ordered list of evaluators:

```text
Request
  |
  v
TrackEvaluator         (passive counting, always continues)
  |
  v
SafelistEvaluator      (match? --> allow, skip remaining)
  |
  v
BlocklistEvaluator     (match? --> 403, skip remaining)
  |
  v
Fail2BanEvaluator      (banned or filter match? --> 403, skip remaining)
  |
  v
ThrottleEvaluator      (rate exceeded? --> 429, skip remaining)
  |
  v
Allow2BanEvaluator     (volume exceeded? --> 403, skip remaining)
  |
  v
Pass (200)
```

Each evaluator returns either a `FirewallResult` (to short-circuit) or `null` (to continue to the next evaluator). If all evaluators return `null`, the request passes through to the application.

## EvaluatorInterface

Every evaluator implements a single method:

```php
namespace Flowd\Phirewall\Http\Evaluator;

interface EvaluatorInterface
{
    public function evaluate(
        ServerRequestInterface $request,
        EvaluationContext $context,
    ): ?FirewallResult;
}
```

- Return `null` to continue to the next evaluator
- Return a `FirewallResult` to short-circuit the pipeline with a decision

## EvaluationContext

The `EvaluationContext` is a mutable transport object that carries shared configuration and accumulates decision state as evaluators run:

| Property | Type | Description |
|----------|------|-------------|
| `config` | `Config` | Firewall configuration (rules, cache, key generator) |
| `normalize` | `Closure(string): string` | Discriminator key normalizer |
| `responseHeadersEnabled` | `bool` | Whether `X-Phirewall` headers are active |
| `rateLimitHeadersEnabled` | `bool` | Whether `X-RateLimit-*` headers are active |
| `diagnosticsHeadersEnabled` | `bool` | Whether matcher-provided diagnostic headers are copied onto blocked responses |
| `counter` | `FixedWindowCounter` | Shared counter for Fail2Ban, Allow2Ban, and track rules |
| `decisionPath` | `DecisionPath` | Updated by evaluators to record which stage decided |
| `decisionRule` | `?string` | Updated by evaluators to record the matching rule name |
| `pendingRateLimitHeaders` | `?array` | Rate-limit headers captured by `ThrottleEvaluator` for pass-through responses |

The context also provides helper methods:

- `dispatch(object $event): void` - dispatches a PSR-14 event if a dispatcher is configured
- `responseHeaders(string $type, string $rule): array` - builds `X-Phirewall` response headers when enabled

## Evaluators

### TrackEvaluator

**Always returns `null`.** Increments counters and dispatches `TrackHit` events for every matching track rule. Because it never blocks, it runs first to ensure passive monitoring is not skipped by earlier short-circuits.

### SafelistEvaluator

Checks safelist rules. On the first match, dispatches `SafelistMatched`, sets the decision path to `Safelisted`, and returns `FirewallResult::safelisted()`. Safelisted requests bypass all blocking rules.

### BlocklistEvaluator

Checks blocklist rules. On the first match, dispatches `BlocklistMatched`, sets the decision path to `Blocklisted`, and returns `FirewallResult::blocked()`. Diagnostic headers the matcher declared in its `MatchResult` metadata (`diagnostic_headers`) are copied onto the response when `enableDiagnosticsHeaders()` is active.

### Fail2BanEvaluator

For each Fail2Ban rule:

1. Checks if the key is already banned - if so, dispatches `Fail2BanBlocked` and returns a blocked result immediately
2. If the filter matches, increments the failure counter and blocks the request (`403`). A match below the threshold sets `DecisionPath::Fail2BanMatched` and dispatches `Fail2BanMatched`; the Nth match additionally bans the key, sets `DecisionPath::Fail2BanBanned`, and dispatches `Fail2BanBanned` (never both events)

The pre-handler path (during `decide()`) blocks on every match and bans at the threshold. The post-handler path (via `processRecordedSignal()`) shares the same `count >= threshold` ban comparison but never blocks the current request and never dispatches `Fail2BanMatched`. The ban fires on the Nth match, consistent with Allow2Ban.

See [Request Context](/advanced/request-context) for post-handler failure signaling.

### ThrottleEvaluator

For each throttle rule:

1. Increments the counter via the configured strategy (fixed or sliding window)
2. If the count exceeds the limit, dispatches `ThrottleExceeded` and returns `FirewallResult::throttled()` with `Retry-After` and optional `X-RateLimit-*` headers
3. If the count is within the limit, captures pending rate-limit headers in the context for pass-through responses

### Allow2BanEvaluator

Unlike other evaluators, Allow2BanEvaluator **processes all rules before returning**. For each Allow2Ban rule:

1. If the key is already banned, records the block (regardless of the filter); the rule that captures the block dispatches `Allow2BanBlocked`
2. Otherwise, if the rule has a filter that does not match, skips the rule (not counted)
3. Otherwise, increments the counter and bans if the threshold is reached (`count >= threshold`); the matching request itself passes until it is the one that reaches the threshold

After processing all rules, it returns the first block found (or `null` if none). This ensures every counter is incremented on every request, even when an earlier rule already triggered a ban.

## Evaluation Order

The evaluation order is fixed and intentional:

| Order | Evaluator | Can Block? | Rationale |
|-------|-----------|------------|-----------|
| 1 | TrackEvaluator | No | Passive monitoring must run before any short-circuit |
| 2 | SafelistEvaluator | No (allows) | Trusted traffic escapes all blocking checks early |
| 3 | BlocklistEvaluator | Yes (403) | Static denylists are cheap to evaluate |
| 4 | Fail2BanEvaluator | Yes (403) | Ban lookups are a single cache read |
| 5 | ThrottleEvaluator | Yes (429) | Counter increment + comparison |
| 6 | Allow2BanEvaluator | Yes (403) | Processes all rules, most expensive |

The order is optimized so cheap checks run before expensive ones, and passive tracking is never skipped.

## Performance

The evaluator pipeline adds negligible overhead. Each evaluator is a lightweight object; the `Fail2BanEvaluator` and `Allow2BanEvaluator` are additionally retained on the firewall so post-handler signal processing can reuse them. The pipeline iterates a fixed-size array with early exit on the first decisive result.

Performance timing for every `decide()` call is captured in the `PerformanceMeasured` event, which includes the `DecisionPath` and `durationMicros`. See [Observability](/advanced/observability#performancemeasured) for details.

## Related Pages

- [Observability](/advanced/observability) - PSR-14 events, diagnostics counters, performance monitoring
- [Request Context](/advanced/request-context) - post-handler failure signaling for Fail2Ban
- [Rate Limiting](/features/rate-limiting) - throttle rules, sliding windows, and multi-throttle
- [Fail2Ban & Allow2Ban](/features/fail2ban) - automatic banning configuration
