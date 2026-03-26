---
outline: deep
---

# Rate Limiting

Phirewall provides rate limiting (throttling) that returns `429 Too Many Requests` when limits are exceeded. Throttle rules are evaluated after safelists, blocklists, and Fail2Ban -- making them the last check before a request reaches your application.

Three throttle strategies are available:

| Strategy | Method | Best For |
|----------|--------|----------|
| **Fixed window** | `add()` | Simple, low-overhead counters |
| **Sliding window** | `sliding()` | Smooth rate limits without double-burst |
| **Multi-window** | `multi()` | Combined burst + sustained limits |

## Fixed Window Throttle

The default strategy. Time is divided into fixed windows (e.g., 60-second intervals aligned to clock time) and each unique key gets a counter that resets at the end of the window.

```php
$config->throttles->add(
    string $name,
    int|Closure $limit,
    int|Closure $period,
    Closure $key
): ThrottleSection
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$name` | `string` | Unique rule identifier |
| `$limit` | `int\|Closure` | Max requests per window, or a [dynamic closure](#dynamic-limits) |
| `$period` | `int\|Closure` | Window size in seconds, or a [dynamic closure](#dynamic-limits) |
| `$key` | `Closure` | `fn(ServerRequestInterface): ?string` -- return a key to group by, or `null` to skip |

```php
use Flowd\Phirewall\KeyExtractors;

// 100 requests per minute per IP
$config->throttles->add('ip-limit', limit: 100, period: 60, key: KeyExtractors::ip());
```

When the key closure returns `null`, the rule is skipped for that request. This lets you apply throttles conditionally -- only to certain paths, methods, or user types.

```text
Window 1 (00:00-00:59)    Window 2 (01:00-01:59)    Window 3 (02:00-02:59)
[|||||||||  ] 9/10 OK     [||||||||||x] 11/10 BLOCK  [|||       ] 3/10 OK
```

::: warning
Fixed-window rate limiting has a known edge case: a burst of requests at the boundary of two windows could allow up to 2x the configured limit in a short period. Use `sliding()` or `multi()` if you need stricter guarantees.
:::

## Sliding Window Throttle

The sliding window strategy prevents the "double burst" problem at window boundaries. It uses a weighted average of the current and previous window counters to produce a smooth rate estimate.

```php
$config->throttles->sliding(
    string $name,
    int|Closure $limit,
    int|Closure $period,
    Closure $key
): ThrottleSection
```

The parameters are identical to `add()`. The only difference is the algorithm used.

```php
// Sliding window: 10 requests per 60 seconds per IP
$config->throttles->sliding(
    name: 'api-sliding',
    limit: 10,
    period: 60,
    key: KeyExtractors::ip(),
);
```

### How It Works

The sliding window calculates a weighted estimate using the current and previous window:

```
estimate = previousCount * (1 - elapsed/period) + currentCount
```

This means if a client sends 10 requests at the end of one window, the estimate at the start of the next window will still be close to 10 (rather than resetting to 0), preventing the double-burst:

```text
Fixed window:   10 requests at T=59s + 10 at T=61s = 20 in 2 seconds (allowed!)
Sliding window: 10 requests at T=59s + 1 at T=61s = ~10.83 (blocked!)
```

::: tip
Use sliding windows for public APIs and any endpoint where consistent rate enforcement matters. The slight additional overhead (one extra cache read for the previous window) is negligible.
:::

## Multi-Window Throttle

The `multi()` method registers multiple throttle windows under a single logical name, combining burst protection with sustained rate limiting.

```php
$config->throttles->multi(
    string $name,
    array $windowLimits,
    Closure $key
): ThrottleSection
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$name` | `string` | Logical name prefix |
| `$windowLimits` | `array<int, int>` | Map of period (seconds) => limit (max requests) |
| `$key` | `Closure` | Key extractor closure |

Each entry creates a sub-rule named `{$name}:{$period}s`. Windows are evaluated shortest-first (burst before sustained).

```php
// 3 req/s burst + 60 req/min sustained
$config->throttles->multi('api', [
    1  => 3,    // "api:1s" -- burst protection
    60 => 60,   // "api:60s" -- sustained throughput
], KeyExtractors::ip());
```

A request is blocked if it exceeds **any** of the windows. This catches both rapid-fire bursts and slow-and-steady abuse.

### Practical Multi-Window Examples

```php
// API with generous sustained limits but strict burst protection
$config->throttles->multi('public-api', [
    1   => 5,      // 5 req/s burst
    60  => 200,    // 200 req/min sustained
    3600 => 5000,  // 5000 req/hour daily budget
], KeyExtractors::ip());

// Login endpoint with tight controls
$config->throttles->multi('login', [
    60  => 5,      // 5 attempts/min
    3600 => 20,    // 20 attempts/hour
], fn($req) => $req->getUri()->getPath() === '/login'
    ? ($req->getServerParams()['REMOTE_ADDR'] ?? null)
    : null
);
```

## Dynamic Limits

Both `limit` and `period` accept closures that receive the current `ServerRequestInterface`. This lets you vary rate limits per request based on user role, subscription plan, or any other request property.

```php
$config->throttles->add(
    string $name,
    int|Closure(ServerRequestInterface): int $limit,
    int|Closure(ServerRequestInterface): int $period,
    Closure $key
): ThrottleSection
```

### Per-Plan Rate Limits

```php
use Psr\Http\Message\ServerRequestInterface;

// Single rule handles all plans -- no need for separate rules per tier
$config->throttles->add(
    'api',
    fn(ServerRequestInterface $req): int => match ($req->getHeaderLine('X-Plan')) {
        'enterprise' => 10000,
        'pro'        => 1000,
        default      => 100,
    },
    60,
    fn(ServerRequestInterface $req): ?string => $req->getHeaderLine('X-User-Id') ?: null
);
```

### Per-Role Rate Limits

```php
// Admins get 100 req/min, regular users get 5 req/min
$config->throttles->add(
    'role-based',
    fn(ServerRequestInterface $req): int =>
        $req->getHeaderLine('X-Role') === 'admin' ? 100 : 5,
    60,
    fn(ServerRequestInterface $req): string =>
        $req->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1'
);
```

### Dynamic Period

```php
// Tighter window during peak hours (9am-5pm)
$config->throttles->add(
    'peak-aware',
    100,
    fn(ServerRequestInterface $req): int =>
        (int) date('G') >= 9 && (int) date('G') < 17 ? 30 : 60,
    KeyExtractors::ip()
);
```

::: tip
Dynamic limits work with `sliding()` too. The limit closure is evaluated per request, so each request gets the correct limit for its context.
:::

## KeyExtractors Helpers

Phirewall ships with common key extractors for typical rate limiting scenarios:

| Helper | Description | Returns |
|--------|-------------|---------|
| `KeyExtractors::ip()` | Client IP from `REMOTE_ADDR` | `?string` |
| `KeyExtractors::clientIp($resolver)` | Client IP via trusted proxy resolver | `?string` |
| `KeyExtractors::header('X-User-Id')` | Value of a specific header | `?string` |
| `KeyExtractors::method()` | HTTP method (uppercase) | `?string` |
| `KeyExtractors::path()` | Request path (always returns a value, never skips) | `string` |
| `KeyExtractors::userAgent()` | User-Agent header value | `?string` |

All extractors except `path()` return `null` when the value is missing or empty, which causes the throttle rule to be skipped for that request.

### Custom Key Extractors

Write your own closure for any logic:

```php
// Only rate limit login attempts
$config->throttles->add('login-rate', limit: 10, period: 60,
    key: function ($req): ?string {
        if ($req->getUri()->getPath() === '/login') {
            return $req->getServerParams()['REMOTE_ADDR'] ?? null;
        }
        return null; // Skip non-login requests
    }
);

// Composite key: IP + path
$config->throttles->add('per-endpoint', limit: 50, period: 60,
    key: function ($req): ?string {
        $ip = $req->getServerParams()['REMOTE_ADDR'] ?? null;
        return $ip ? $ip . ':' . $req->getUri()->getPath() : null;
    }
);
```

## Tiered Rate Limits

Define multiple throttle rules with different limits for different use cases. All rules are evaluated independently -- a request must satisfy all of them.

```php
use Flowd\Phirewall\Http\TrustedProxyResolver;
use Flowd\Phirewall\KeyExtractors;

$proxyResolver = new TrustedProxyResolver([
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
]);

// Tier 1: Global per-IP limit
$config->throttles->add('global-ip',
    limit: 1000, period: 60,
    key: KeyExtractors::clientIp($proxyResolver)
);

// Tier 2: Stricter limit for write operations
$config->throttles->add('write-operations',
    limit: 100, period: 60,
    key: function ($req) use ($proxyResolver): ?string {
        if (in_array($req->getMethod(), ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            return $proxyResolver->resolve($req);
        }
        return null;
    }
);

// Tier 3: Per-endpoint limit for expensive operations
$config->throttles->add('search-endpoint',
    limit: 20, period: 60,
    key: function ($req) use ($proxyResolver): ?string {
        if ($req->getUri()->getPath() === '/api/search') {
            return $proxyResolver->resolve($req);
        }
        return null;
    }
);
```

## Per-User Limits

Differentiate between authenticated and anonymous traffic:

```php
// Authenticated user limits (higher)
$config->throttles->add('api-user',
    limit: 1000, period: 3600,
    key: KeyExtractors::header('X-User-Id')
);

// Anonymous limits (lower, keyed by IP)
$config->throttles->add('api-anon',
    limit: 100, period: 3600,
    key: function ($req) use ($proxyResolver): ?string {
        if ($req->getHeaderLine('X-User-Id') !== '') {
            return null; // Skip authenticated requests
        }
        return $proxyResolver->resolve($req);
    }
);
```

::: tip
Your application's authentication middleware should set headers like `X-User-Id` and `X-Plan` on the request before it reaches the Phirewall middleware. This allows clean separation of concerns.
:::

## Rate Limit Headers

Enable standard `X-RateLimit-*` headers on all responses:

```php
$config->enableRateLimitHeaders();
```

### Headers on Successful Responses (200)

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Configured request limit |
| `X-RateLimit-Remaining` | Remaining requests in the current window |
| `X-RateLimit-Reset` | Seconds until the window resets |

### Headers on Throttled Responses (429)

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Configured request limit |
| `X-RateLimit-Remaining` | `0` |
| `X-RateLimit-Reset` | Seconds until the window resets |
| `Retry-After` | Seconds until the client should retry |
| `X-Phirewall` | `throttle` (only when `enableResponseHeaders()` is active) |
| `X-Phirewall-Matched` | Name of the throttle rule that triggered (only when `enableResponseHeaders()` is active) |

::: tip
When multiple throttle rules match, the rate limit headers reflect the **first** matching rule. Add stricter rules before more lenient ones if you want the most restrictive limits shown.
:::

## Custom Throttled Response

Override the default `429` response with custom content:

```php
use Flowd\Phirewall\Config\Response\ClosureThrottledResponseFactory;
use Nyholm\Psr7\Response;

$config->throttledResponseFactory = new ClosureThrottledResponseFactory(
    function (string $rule, int $retryAfter, $req) {
        return new Response(
            429,
            ['Content-Type' => 'application/json'],
            json_encode([
                'error' => 'Rate limit exceeded',
                'rule' => $rule,
                'retry_after' => $retryAfter,
            ])
        );
    }
);
```

Phirewall automatically adds the `Retry-After` header and any rate limit headers to your custom response.

See [PSR-17 Factories](/advanced/psr17) for framework-integrated response customization.

## Trusted Proxy Configuration

When your application sits behind a load balancer, CDN, or reverse proxy, `REMOTE_ADDR` contains the proxy IP, not the client IP. Always use `TrustedProxyResolver` in production:

```php
use Flowd\Phirewall\Http\TrustedProxyResolver;
use Flowd\Phirewall\KeyExtractors;

$resolver = new TrustedProxyResolver([
    '10.0.0.0/8',       // Internal network
    '172.16.0.0/12',    // Docker
    '192.168.0.0/16',   // Private ranges
    '2001:db8::/32',    // IPv6 support
]);

$config->throttles->add('api', limit: 100, period: 60,
    key: KeyExtractors::clientIp($resolver)
);
```

You can also set a global IP resolver so all IP-aware matchers use it automatically:

```php
$config->setIpResolver(KeyExtractors::clientIp($resolver));
```

::: danger
Never trust `X-Forwarded-For` without configuring trusted proxies. An attacker can spoof this header to bypass rate limiting entirely.
:::

## Events

When a throttle limit is exceeded, a `ThrottleExceeded` event is dispatched via PSR-14:

```php
use Flowd\Phirewall\Events\ThrottleExceeded;

// Event properties
$event->rule;           // string - Rule name (e.g., "api:1s")
$event->key;            // string - Throttle key (e.g., client IP)
$event->limit;          // int - Configured limit
$event->period;         // int - Window size in seconds
$event->count;          // int - Current request count
$event->retryAfter;     // int - Seconds until window resets
$event->serverRequest;  // ServerRequestInterface
```

Use this event for alerting, logging, or triggering further actions. See [Observability](/advanced/observability) for integration examples.

## Best Practices

1. **Use `sliding()` for public APIs.** It prevents the double-burst problem with negligible overhead. Reserve `add()` for internal or high-throughput services where simplicity matters more.

2. **Use `multi()` for combined burst + sustained.** A single `multi()` call replaces manually defining separate burst and sustained rules.

3. **Use dynamic limits for per-plan pricing.** A single rule with a closure is cleaner than separate rules per subscription tier.

4. **Use `clientIp()` in production.** Raw `REMOTE_ADDR` is the proxy IP behind load balancers. Always configure trusted proxies.

5. **Return `null` to skip.** Key closures that return `null` cause the rule to be skipped entirely for that request, with zero overhead.

6. **Enable rate limit headers.** They help well-behaved API clients self-throttle before hitting limits.

7. **Combine with Fail2Ban.** For persistent abusers, add a [Fail2Ban](/features/fail2ban) rule that bans IPs after repeated throttle violations.
