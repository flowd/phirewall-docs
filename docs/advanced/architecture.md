---
outline: deep
---

# Architecture

Phirewall's core decision engine uses an **evaluator pipeline** -- a sequential chain of single-responsibility evaluator classes, each handling one type of firewall rule. The pipeline processes every request and short-circuits on the first decisive result.

## Evaluator Pipeline

When `Firewall::decide()` is called, it creates an `EvaluationContext` and passes the request through an ordered list of evaluators:

```text
Request
  |
  v
TrackEvaluator         (passive counting -- always continues)
  |
  v
SafelistEvaluator      (match? --> allow, skip remaining)
  |
  v
BlocklistEvaluator     (match? --> 403, skip remaining)
  |
  v
Fail2BanEvaluator      (banned or threshold hit? --> 403, skip remaining)
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
| `owaspDiagnosticsHeaderEnabled` | `bool` | Whether `X-Phirewall-Owasp-Rule` header is active |
| `counter` | `FixedWindowCounter` | Shared counter for fail2ban, allow2ban, and track rules |
| `decisionPath` | `DecisionPath` | Updated by evaluators to record which stage decided |
| `decisionRule` | `?string` | Updated by evaluators to record the matching rule name |
| `pendingRateLimitHeaders` | `?array` | Rate-limit headers captured by `ThrottleEvaluator` for pass-through responses |

The context also provides helper methods:

- `dispatch(object $event): void` -- dispatches a PSR-14 event if a dispatcher is configured
- `responseHeaders(string $type, string $rule): array` -- builds `X-Phirewall` response headers when enabled

## Evaluators

### TrackEvaluator

**Always returns `null`.** Increments counters and dispatches `TrackHit` events for every matching track rule. Because it never blocks, it runs first to ensure passive monitoring is not skipped by earlier short-circuits.

### SafelistEvaluator

Checks safelist rules. On the first match, dispatches `SafelistMatched`, sets the decision path to `Safelisted`, and returns `FirewallResult::safelisted()`. Safelisted requests bypass all blocking rules.

### BlocklistEvaluator

Checks blocklist rules. On the first match, dispatches `BlocklistMatched`, sets the decision path to `Blocklisted`, and returns `FirewallResult::blocked()`. For OWASP-sourced rules, includes the `X-Phirewall-Owasp-Rule` diagnostic header when enabled.

### Fail2BanEvaluator

For each fail2ban rule:

1. Checks if the key is already banned -- if so, returns a blocked result immediately
2. If the filter matches, increments the failure counter and bans if the threshold is exceeded

The threshold semantics differ between pre-handler and post-handler modes:

| Mode | Comparison | Behavior |
|------|------------|----------|
| Pre-handler (during `decide()`) | count **>** threshold | Allows N matches, bans on N+1 |
| Post-handler (via `processRecordedFailure()`) | count **>=** threshold | Bans on the Nth recorded failure |

See [Request Context](/advanced/request-context) for post-handler failure signaling.

### ThrottleEvaluator

For each throttle rule:

1. Increments the counter via the configured strategy (fixed or sliding window)
2. If the count exceeds the limit, dispatches `ThrottleExceeded` and returns `FirewallResult::throttled()` with `Retry-After` and optional `X-RateLimit-*` headers
3. If the count is within the limit, captures pending rate-limit headers in the context for pass-through responses

### Allow2BanEvaluator

Unlike other evaluators, Allow2BanEvaluator **processes all rules before returning**. For each allow2ban rule:

1. If the key is already banned, records the block
2. Otherwise, increments the counter and bans if the threshold is exceeded

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

The evaluator pipeline adds no measurable overhead compared to the previous monolithic implementation. Each evaluator is a lightweight, stateless object (except `Fail2BanEvaluator`, which is retained for post-handler failure processing). The pipeline iterates a fixed-size array with early exit on the first decisive result.

Performance timing for every `decide()` call is captured in the `PerformanceMeasured` event, which includes the `DecisionPath` and `durationMicros`. See [Observability](/advanced/observability#performancemeasured) for details.

## Related Pages

- [Observability](/advanced/observability) -- PSR-14 events, diagnostics counters, performance monitoring
- [Request Context](/advanced/request-context) -- post-handler failure signaling for Fail2Ban
- [Rate Limiting](/features/rate-limiting) -- throttle rules, sliding windows, and multi-throttle
- [Fail2Ban & Allow2Ban](/features/fail2ban) -- automatic banning configuration
