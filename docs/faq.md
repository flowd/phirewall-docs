---
outline: deep
---

# Frequently Asked Questions

## General

### What PHP version does Phirewall require?

PHP 8.2 or higher. Phirewall uses modern PHP features like readonly classes, enums, and union types.

### Which frameworks does Phirewall support?

Phirewall works with any PSR-15 (PHP Standard Recommendation for HTTP Server Middleware) compatible framework, including:

- **Slim** (4.x+)
- **Mezzio** (Laminas)
- **TYPO3** (via an extension middleware)
- **Laravel** (via `symfony/psr-http-message-bridge` + `nyholm/psr7`)
- **Symfony** (via `symfony/psr-http-message-bridge`)
- **Spiral**
- **Any custom PSR-15 middleware stack**

See [Getting Started](/getting-started#step-5-add-to-your-application) for framework-specific integration examples.

### Does Phirewall replace a WAF like ModSecurity?

No. Phirewall operates at the **application layer** (PHP), not at the web server layer. It complements server-level WAFs (Web Application Firewalls) by providing application-aware protection that understands your routes, users, and business logic.

For defense-in-depth, use Phirewall alongside a WAF. The [infrastructure adapters](/advanced/infrastructure) can mirror application-level bans to your web server so blocked IPs never even reach PHP.

### Is Phirewall suitable for production use?

Yes. With a Redis or APCu storage backend, Phirewall is designed for production workloads:

- **Redis** supports multi-server deployments and uses atomic Lua scripts for accurate counters under high concurrency
- **APCu** provides sub-microsecond latency for single-server deployments
- **PDO** (MySQL, PostgreSQL, SQLite) works when Redis is not available

The default fail-open behavior ensures that a cache outage does not take down your application.

### How does Phirewall compare to CloudFlare or AWS WAF?

Phirewall works at a different layer. Cloud WAFs filter traffic before it reaches your server. Phirewall filters traffic **within** your PHP application, giving it access to application-level context (user sessions, form data, business logic) that cloud WAFs cannot see. They work best together:

| Feature | Cloud WAF | Phirewall |
|---------|-----------|-----------|
| DDoS protection | Yes (network layer) | No (application layer only) |
| Bot detection | Generic signatures | Application-aware |
| Rate limiting | IP/path based | User/session/API key based |
| Login protection | No | Yes (Fail2Ban + RequestContext) |
| Custom rules | Limited | Full PHP expressiveness |
| OWASP CRS | Yes | Practical subset |

### What license is Phirewall under?

Phirewall is dual licensed under LGPL-3.0-or-later and a proprietary license. See the [LICENSE](https://github.com/flowd/phirewall/blob/main/LICENSE) file for details.

## Configuration

### What is the evaluation order of rules?

Phirewall evaluates rules in a strict, deterministic order. The first match wins:

1. **Track**: passive counting, never blocks
2. **Safelist**: if matched, bypass all other checks (returns 200)
3. **Blocklist**: if matched, returns 403 Forbidden
4. **Fail2Ban**: if already banned, 403; if the filter matches, block with 403 and count (the Nth match also bans)
5. **Throttle**: if counter exceeds limit, returns 429 Too Many Requests
6. **Allow2Ban**: counts every request (or only filtered ones); returns 403 once the threshold is reached
7. **Pass**: request reaches your application

### How do I handle trusted proxies?

When your application sits behind a load balancer, CDN (Content Delivery Network), or reverse proxy, `REMOTE_ADDR` contains the proxy's IP, not the client's. Use `TrustedProxyResolver` to extract the real client IP:

```php
use Flowd\Phirewall\Http\TrustedProxyResolver;

$proxy = new TrustedProxyResolver([
    '10.0.0.0/8',      // Internal network
    '172.16.0.0/12',   // Docker
    '192.168.0.0/16',  // Private ranges
]);

// Configure proxy trust once; every rule without an explicit key keys on the resolved client IP.
$config->setIpResolver($proxy->resolve(...));
```

Rules added without an explicit `key` argument automatically key on the resolved client IP - no per-rule wiring is needed:

```php
$config->throttles->add('api', limit: 100, period: 60);
// Keys on the resolved client IP (via the resolver set above).
```

A few details worth knowing:

- **`allowedHeaders` defaults to `['X-Forwarded-For']`** (a single header). If your stack emits the RFC 7239 `Forwarded` header, pass it explicitly: `new TrustedProxyResolver([...], ['Forwarded'])`.
- **All `X-Forwarded-For` / `Forwarded` instances are folded into one chain**, which the resolver walks right to left, returning the first hop not in your trusted-proxy list. The protection is this trusted-hop walk (and reading proxy headers only when the direct peer is itself trusted), not discarding duplicate lines.
- **IPv6 is canonicalized**: IPv4-mapped peers (`::ffff:1.2.3.4`) match IPv4 rules, and alternate IPv6 spellings are treated as one identity by `ip()` / CIDR list matching (rate-limit and ban keys use the spelling the resolver returns).

See [Client IP Behind Proxies](/getting-started#client-ip-behind-proxies) for the full behavior.

::: danger
The raw `REMOTE_ADDR` peer address is the connecting peer, not the client. Behind a CDN or load balancer that is the proxy's address, so every client collapses onto one key. If you need the raw peer address explicitly, read `$request->getServerParams()['REMOTE_ADDR']` directly. For the actual client IP, configure proxy trust once with `$config->setIpResolver((new TrustedProxyResolver([...]))->resolve(...))` and omit the `key` argument on your rules. And never trust `X-Forwarded-For` without configuring trusted proxies: an attacker can otherwise spoof this header to bypass rate limiting.
:::

### What happens when the cache backend is unavailable?

By default, Phirewall operates in **fail-open** mode. If the cache backend throws an exception (for example, Redis is down), the request is allowed through and a `FirewallError` event is dispatched for logging.

To switch to fail-closed mode (exceptions propagate, resulting in a 500 error):

```php
$config->setFailOpen(false);
```

::: warning
In fail-open mode, a down cache means firewall rules are not being enforced. Monitor your cache backend health and alert on `FirewallError` events. See [Observability](/advanced/observability) for monitoring setup.
:::

### How do I customize error responses?

For simple body text, use `usePsr17Responses()`:

```php
use Nyholm\Psr7\Factory\Psr17Factory;

$psr17 = new Psr17Factory();
$config->usePsr17Responses($psr17, $psr17);
```

For full control (JSON responses, HTML pages, content negotiation), use closure-based factories:

```php
use Flowd\Phirewall\Config\Response\ClosureBlocklistedResponseFactory;
use Flowd\Phirewall\Config\Response\ClosureThrottledResponseFactory;
use Nyholm\Psr7\Response;

$config->blocklistedResponseFactory = new ClosureBlocklistedResponseFactory(
    fn(string $rule, string $type, $request) => new Response(
        403, ['Content-Type' => 'application/json'],
        json_encode(['error' => 'Blocked', 'rule' => $rule])
    )
);

$config->throttledResponseFactory = new ClosureThrottledResponseFactory(
    fn(string $rule, int $retryAfter, $request) => new Response(
        429, ['Content-Type' => 'application/json', 'Retry-After' => (string) $retryAfter],
        json_encode(['error' => 'Rate limited', 'retry_after' => $retryAfter])
    )
);
```

See [PSR-17 Factories](/advanced/psr17) for full details.

### What is the difference between Fail2Ban and Allow2Ban?

| Feature | Fail2Ban | Allow2Ban |
|---------|----------|-----------|
| Filter | Required: marks a request as malicious | Optional: without it counts every request, with it counts only matches |
| On a match | **Blocks immediately** (403) and counts | **Lets the request pass** and counts, until the threshold |
| Use case | Unambiguously malicious matches (scanner paths, invalid signatures), signal-only rules | Login brute-force counting, volume abuse |
| Think of it as | "any bad request is blocked; N bad requests and you're banned" | "N requests and you're out, but they pass until then" |

**Fail2Ban** requires a filter closure that marks a request as malicious. From 0.8 every match is blocked with 403; the Nth match also bans the key. Use it only for unambiguously malicious matches, or as a signal-only rule (`filter: fn() => false`) driven by [`RequestContext::recordFailure()`](/advanced/request-context).

**Allow2Ban** counts requests for a key, either every request (a hard volume cap) or only those an optional filter matches, and lets matching requests pass until the threshold. It bans as soon as the counted volume reaches the threshold. This is the natural home for login brute-force counting and for blocking aggressive scrapers or bots by volume.

See [Fail2Ban & Allow2Ban](/features/fail2ban) for details.

### How do I signal Fail2Ban failures from inside my handler?

Use [RequestContext](/advanced/request-context) for post-handler failure signaling. This lets you verify credentials before deciding whether a request counts as a failure:

```php
use Flowd\Phirewall\Context\RequestContext;

// In your handler, after authentication fails:
$context = $request->getAttribute(RequestContext::ATTRIBUTE_NAME);
$context?->recordFailure('login-failures');
```

The second argument to `recordFailure()` is optional; when omitted, the firewall extracts the discriminator key from the rule's own `keyExtractor`. The matching Fail2Ban rule should use `filter: fn($request): bool => false` so it only counts failures signaled programmatically.

For allow2ban rules, use `$context->recordHit('rule-name')`, same shape, routed through the allow2ban evaluator instead.

## Rate Limiting

### What rate limiting algorithms does Phirewall support?

Phirewall supports three throttling strategies:

- **Fixed window** (`add()`): time is divided into fixed intervals. Simple and fast, but allows double bursts at period boundaries.
- **Sliding window** (`sliding()`): uses a weighted average of current and previous window to provide smooth rate enforcement. Prevents the "double burst" problem.
- **Multi-window** (`multi()`): registers multiple time windows in a single call. Useful for setting both burst limits (short window) and sustained limits (long window).

See [Dynamic Throttle](/advanced/dynamic-throttle) for details.

### How do I prevent boundary exploitation?

Use sliding window throttling:

```php
$config->throttles->sliding('api', limit: 100, period: 60);
```

Or combine multiple fixed windows with `multi()`:

```php
$config->throttles->multi('api', [
    1  => 3,    // 3 req/s burst protection
    60 => 100,  // 100 req/min sustained limit
]);
```

### What happens when a throttle key returns `null`?

The rule is **skipped entirely** for that request, as if the rule did not exist. This is the primary mechanism for conditional rate limits. For example, return `null` for admin users to exempt them from rate limiting.

### Are rate limit counters atomic?

Yes, when using the bundled storage backends:

- **RedisCache** uses Lua scripts for atomic increment-and-expire
- **ApcuCache** uses `apcu_inc()` which is atomic
- **InMemoryCache** is single-threaded by nature

Generic PSR-16 caches use a non-atomic read-modify-write pattern, which may be slightly inaccurate under high concurrency.

### Can I set different rate limits for different users?

Yes. Use a dynamic `limit` closure:

```php
$config->throttles->add('api',
    limit: fn($request): int => match ($request->getAttribute('plan')) {
        'enterprise' => 10000,
        'pro' => 1000,
        default => 100,
    },
    period: 60,
);
```

`plan` is a PSR-7 request **attribute** your authentication middleware sets after verifying the principal (`$request->withAttribute('plan', ...)`), not a client header a caller could forge. Place that middleware before Phirewall in the pipeline.

See [Dynamic Throttle: Per-User Tier Limits](/advanced/dynamic-throttle#per-user-tier-limits) for more patterns.

## Storage

### Which storage backend should I use?

| Scenario | Backend | Why |
|----------|---------|-----|
| Testing / Development | `InMemoryCache` | No dependencies, resets each request |
| Single server | `ApcuCache` | Sub-microsecond, shared across PHP-FPM workers |
| Multiple servers | `RedisCache` | Shared state, atomic operations |
| Long-running workers (Swoole, RoadRunner, FrankenPHP, Octane) | `RedisCache` (or `PdoCache`) | Each worker is a separate process; avoid `InMemoryCache` and `ApcuCache`, whose state fragments across workers |
| Kubernetes / Docker | `RedisCache` | Containers are ephemeral, need external state |
| Serverless | `RedisCache` (external) | Function instances are short-lived |
| No Redis available | `PdoCache` | MySQL, PostgreSQL, or SQLite |

See [Storage Backends](/features/storage) for a detailed comparison.

### Can I use Symfony Cache or Laravel Cache?

Yes, Phirewall accepts any PSR-16 (PHP Standard Recommendation for Simple Caching) compatible implementation, but most host-framework caches are **not** PSR-16 out of the box: Laravel's `Cache` repository (`Illuminate\Contracts\Cache\Repository`) and TYPO3's caching framework (`FrontendInterface`) are not `Psr\SimpleCache\CacheInterface`, so passing one directly to `Config` is a type error. Symfony Cache exposes a PSR-16 adapter (`Symfony\Component\Cache\Psr16Cache`) you can wrap a pool in. For production, prefer the bundled `RedisCache` or `ApcuCache`: they implement `CounterStoreInterface` for atomic increments, whereas a generic PSR-16 cache may have non-atomic counter increments.

### Why does InMemoryCache not work in production?

In PHP-FPM (FastCGI Process Manager), worker processes are pooled and reused across requests, but PHP tears down userland state at the end of each request. The in-memory cache therefore starts empty on every request, so counters always reset to zero. This means rate limits and ban counters never accumulate.

Under long-running worker runtimes (Swoole, RoadRunner, FrankenPHP worker mode, Octane) the failure is the opposite and easy to miss: the array survives across requests within a worker, so a single-worker demo looks like it "works", but each worker is a separate process with its own array. State is never shared across workers (counters and bans fragment, so the effective rate limit is roughly N times the configured value) and the array grows for the worker's lifetime.

Solutions:
- **Single server**: use `ApcuCache` (shared memory across the FPM pool)
- **Multiple servers**: use `RedisCache` (shared across all servers)
- **Long-running workers**: use `RedisCache` or `PdoCache` (not `ApcuCache`, whose memory is per process)
- **Any server**: use `PdoCache` with a database

## OWASP Rules

### Does Phirewall implement the full OWASP CRS?

No. Phirewall supports a practical subset of the OWASP (Open Web Application Security Project) CRS (Core Rule Set) syntax, covering the most common variables (`ARGS`, `REQUEST_URI`, `REQUEST_HEADERS`, etc.) and operators (`@rx`, `@pm`, `@pmFromFile`, `@contains`, etc.). It is not a full ModSecurity replacement.

For full OWASP CRS coverage, use a dedicated WAF (like ModSecurity) alongside Phirewall.

### How do I load custom OWASP rules?

OWASP CRS support ships in the companion package `flowd/phirewall-preset-owasp-crs` (`composer require flowd/phirewall-preset-owasp-crs`):

```php
use Flowd\Phirewall\Config\Rule\BlocklistRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;
use Flowd\PhirewallPresetOwaspCrs\Engine\SecRuleLoader;

// From a string of rules
$crs = SecRuleLoader::fromString($rulesText);

// From a single file
$crs = SecRuleLoader::fromFile('/path/to/rules.conf');

// From a directory (all .conf files)
$crs = SecRuleLoader::fromDirectory('/path/to/rules/');

$config->blocklists->addRule(new BlocklistRule('owasp', new CoreRuleSetMatcher($crs)));
```

### Can I disable specific OWASP rules?

Yes. After loading a rule set, disable individual rules by ID:

```php
$crs = SecRuleLoader::fromDirectory('/path/to/rules');
$crs->disable(942100);  // Disable a specific SQL injection rule
$crs->enable(942100);   // Re-enable it later
```

### How do I debug which OWASP rule is blocking a request?

Enable diagnostic headers:

```php
$config->enableDiagnosticsHeaders();
```

The CRS matcher attaches an `X-Phirewall-Owasp-Rule` header with the matched rule ID to blocked responses. This works wherever the matcher decides the block: as a blocklist rule and as a fail2ban filter. Any matcher can ship such headers via the `diagnostic_headers` metadata key on its `MatchResult`.

::: warning
Only enable this in development or staging. In production, it reveals information about your security rules to potential attackers.
:::

## Track Rules

### What are track rules for?

Track rules count requests passively **without blocking**. They are ideal for:

- Monitoring traffic patterns before enforcing rules
- Feeding data into dashboards and alerting systems
- Detecting anomalies without affecting users

### What is the `limit` parameter on track rules?

The optional `limit` parameter adds a threshold to your track rule. When set, the `TrackHit` event includes a `thresholdReached` flag that becomes `true` once the counter meets or exceeds the limit. The event fires on **every** matching request regardless of the threshold.

```php
$config->tracks->add('suspicious-burst',
    period: 60,
    filter: fn($request) => $request->getUri()->getPath() === '/login',
    limit: 10, // thresholdReached=true at 10+ hits
);
```

This is useful for alerting: you get full observability, but can filter your event handler to only act when the threshold is crossed.

See [Track & Notifications](/advanced/track-notifications) for details.

## Troubleshooting

### All requests are being blocked

Common causes:
- A blocklist rule filter is too broad (for example, matching all paths)
- `REMOTE_ADDR` is a proxy IP that matches a blocklist CIDR range
- OWASP rules are triggering on legitimate input

Debug steps:
1. Enable `$config->enableResponseHeaders()` and check the `X-Phirewall` and `X-Phirewall-Matched` response headers to identify the blocking rule
2. Temporarily disable suspect rules and re-enable them one by one
3. If OWASP rules are involved, enable `$config->enableDiagnosticsHeaders()` to see which rule ID matched

### Rate limits are not working in PHP-FPM

You are likely using `InMemoryCache`, which resets on every request in PHP-FPM. Switch to `ApcuCache` (single server) or `RedisCache` (multi-server) for production.

### How do I debug which rule blocked a request?

Enable `$config->enableResponseHeaders()` and check the response headers on blocked requests:

| Header | Value |
|--------|-------|
| `X-Phirewall` | Block type: `blocklist`, `throttle`, `fail2ban`, or `allow2ban` |
| `X-Phirewall-Matched` | Name of the rule that triggered the block |
| `X-Phirewall-Owasp-Rule` | OWASP rule ID (only if `enableDiagnosticsHeaders()` is active) |

::: info
These headers are disabled by default. Call `$config->enableResponseHeaders()` to enable them for debugging.
:::

### Can I log all firewall decisions?

Yes. Pass a PSR-14 (PHP Standard Recommendation for Event Dispatching) event dispatcher to the `Config` constructor and listen for events. Phirewall dispatches events for every significant decision. See [Observability](/advanced/observability) for complete examples with Monolog, OpenTelemetry, Prometheus, and structured JSON logging.

### How do I test my firewall configuration?

Use `InMemoryCache` with the `Firewall` class directly (without the middleware layer). This is the core decision engine used internally by `Middleware`:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;

$config = new Config(new InMemoryCache());
// ... configure rules ...

$firewall = new Firewall($config);
$request = new ServerRequest('GET', '/api/test', [], null, '1.1', [
    'REMOTE_ADDR' => '192.168.1.100',
]);

$result = $firewall->decide($request);

if ($result->isBlocked()) {
    echo "Blocked by: " . $result->rule . "\n";
    echo "Block type: " . $result->blockType . "\n";
} else {
    echo "Allowed (outcome: " . $result->outcome->value . ")\n";
}
```

### How do I reset a ban or throttle counter?

Use the `Firewall` class:

```php
use Flowd\Phirewall\BanType;

$firewall = new Firewall($config);

// Reset a specific throttle counter
$firewall->resetThrottle('api', '192.168.1.100');

// Lift a specific fail2ban ban (also clears its fail counter)
$firewall->resetFail2Ban('login-failures', '192.168.1.100');

// Check whether a key is currently banned (BanType is required)
$banned = $firewall->isBanned('login-failures', '192.168.1.100', BanType::Fail2Ban);

// Reset all counters and bans
$firewall->resetAll();
```

`BanType` is `enum BanType: string { case Allow2Ban = 'allow2ban'; case Fail2Ban = 'fail2ban'; }`.
