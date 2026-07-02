---
outline: deep
---

# Dynamic Throttle & Advanced Rate Limiting

Phirewall's throttle system does more than fixed-window rate limiting. This page covers dynamic limits, sliding windows, multi-window throttling, and patterns for fine-grained rate limiting.

For basic rate limiting setup, see [Rate Limiting](/features/rate-limiting).

## Dynamic Limits

Both the `limit` and `period` parameters in `throttles->add()` accept either a static `int` or a `Closure` that receives the current `ServerRequestInterface` and returns an `int`. This lets you vary rate limits per-request based on user tier, endpoint, time of day, or any other factor.

### Dynamic Limit (Closure)

Give different users different quotas based on a request header:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;
use Psr\Http\Message\ServerRequestInterface;

$config = new Config(new InMemoryCache());
$config->enableRateLimitHeaders();

// `role` is a PSR-7 request attribute your auth middleware sets before Phirewall
// runs (e.g. $request->withAttribute('role', $user->role)). Attributes are
// server-side only, so a client cannot forge them the way it could a header.
// Admins get 1000 req/min, regular users get 100 req/min
$config->throttles->add('role-based',
    limit: fn(ServerRequestInterface $request): int =>
        $request->getAttribute('role') === 'admin' ? 1000 : 100,
    period: 60,
);
```

The closure is called on every request, so the limit is always based on the **current** request's properties. If a user's role changes, the new limit applies immediately.

### Dynamic Period (Closure)

Use different observation windows based on the endpoint:

```php
// Export endpoints use a 1-hour window; everything else uses 1 minute
$config->throttles->add('endpoint-adaptive',
    limit: 100,
    period: fn(ServerRequestInterface $request): int =>
        str_starts_with($request->getUri()->getPath(), '/api/export') ? 3600 : 60,
);
```

::: tip Dynamic period cache keys
When the period is a closure, Phirewall appends `:p{period}` to the cache key (for example, `api:p60`, `api:p3600`). This ensures that different resolved periods for the same discriminator key get independent counters.
:::

### Both Dynamic

You can make both the limit and the period dynamic:

```php
// Enterprise users: 10,000 req/hour. Everyone else: 100 req/min.
$config->throttles->add('fully-dynamic',
    limit: fn(ServerRequestInterface $request): int =>
        $request->getAttribute('plan') === 'enterprise' ? 10000 : 100,
    period: fn(ServerRequestInterface $request): int =>
        $request->getAttribute('plan') === 'enterprise' ? 3600 : 60,
);
```

### Method Signature

```php
$config->throttles->add(
    string $name,
    int|Closure $limit,     // Static int or Closure(ServerRequestInterface): int
    int|Closure $period,    // Static int or Closure(ServerRequestInterface): int
    ?Closure $key = null,   // Closure(ServerRequestInterface): ?string
): ThrottleSection
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$name` | `string` | Rule name (appears in headers and events) |
| `$limit` | `int\|Closure` | Maximum requests in the period. Closure receives the request. |
| `$period` | `int\|Closure` | Time window in seconds. Closure receives the request. |
| `$key` | `?Closure` | Key extractor; return `null` to skip this rule. Omit to default to the client IP (Config IP resolver, else REMOTE_ADDR). |

## Sliding Window

The sliding window algorithm prevents the "double burst" problem that occurs at fixed-window boundaries.

### The Double Burst Problem

With fixed windows aligned to clock boundaries, a client can send a burst right before a window ends, and another burst right after the new window starts, effectively doubling their allowed rate:

```text
Fixed window (limit=100, period=60s):

Window 1 (0:00-0:59)    Window 2 (1:00-1:59)
                    |
          90 reqs   |  100 reqs
          at 0:55   |  at 1:00
                    |
Total in 5 seconds: 190 requests (nearly double the limit!)
```

### How Sliding Window Fixes This

The sliding window uses a **weighted average** of the current and previous window counters:

```
estimate = previousCount x (1 - weight) + currentCount
weight   = elapsed / period
```

For example, if we are 30 seconds into a 60-second window with 50 requests in the previous window and 30 in the current window:

```
weight   = 30/60 = 0.5
estimate = 50 x 0.5 + 30 = 55
```

As time progresses within the current window, the previous window's contribution diminishes smoothly. This prevents the boundary exploitation shown above.

### Usage

```php
$config->throttles->sliding('api-sliding',
    limit: 100,
    period: 60,
);
```

The method signature is identical to `add()`; the only difference is the internal algorithm. Sliding windows also support dynamic `limit` and `period` closures.

### Fixed vs. Sliding Comparison

| Aspect | Fixed Window | Sliding Window |
|--------|-------------|----------------|
| Accuracy | Can allow ~2x burst at boundary | Smooth, consistent rate |
| Cache entries | 1 per key | 2 per key (current + previous) |
| Performance | Slightly faster | Slightly more cache reads |
| Best for | Simple rate limiting, internal APIs | Public APIs, strict limit enforcement |

::: tip
The sliding window algorithm is not atomic under high concurrency; a small number of requests may slip through at the exact moment the threshold is crossed. This is acceptable for rate limiting, which is a fairness mechanism, not a security boundary. For hard security limits, use [Fail2Ban](/features/fail2ban) or [Allow2Ban](/features/fail2ban#allow2ban).
:::

## Multi-Window Throttling

Register multiple time windows under a single logical name with `multi()`. This lets you set both a burst limit (short window) and a sustained limit (long window) in a single call.

### Usage

```php
// Creates "api:1s" (3 req/s burst) and "api:60s" (100 req/min sustained)
$config->throttles->multi('api', [
    1  => 3,    // 3 requests per second (burst protection)
    60 => 100,  // 100 requests per minute (sustained limit)
]);
```

A request is blocked if it exceeds **any** window's limit. Windows are evaluated from shortest to longest period.

### Method Signature

```php
$config->throttles->multi(
    string $name,
    array $windowLimits,   // array<int period, int limit>
    ?Closure $key = null,
): ThrottleSection
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$name` | `string` | Base name. Sub-rules are named `{name}:{period}s`. |
| `$windowLimits` | `array<int, int>` | Map of period (seconds) to limit (max requests). Must not be empty. |
| `$key` | `?Closure` | Key extractor, shared across all sub-rules. Omit to default to the client IP (Config IP resolver, else REMOTE_ADDR). |

### Naming Convention

Sub-rules follow the pattern `{name}:{period}s`:

```php
$config->throttles->multi('api', [1 => 5, 60 => 100, 3600 => 2000]);

// Creates three rules:
// - "api:1s"    -> 5 req/s
// - "api:60s"   -> 100 req/min
// - "api:3600s" -> 2000 req/hour
```

These names appear in `ThrottleExceeded` events and, when `enableResponseHeaders()` is active, in the `X-Phirewall-Matched` response header, so you can tell which window triggered the block.

### Three-Tier Example

A common pattern for APIs: burst, sustained, and daily limits:

```php
$config->throttles->multi('public-api', [
    1    => 10,     // 10 req/s burst cap
    60   => 300,    // 300 req/min sustained
    3600 => 5000,   // 5000 req/hour daily budget
]);
```

## Per-User Tier Limits

Apply different rate limits based on subscription plan. There are two approaches:

### Approach 1: Dynamic Limit Closure (Recommended)

Use a single rule with a dynamic limit. This is simpler and requires less configuration:

```php
$config->throttles->add('api',
    limit: fn(ServerRequestInterface $request): int => match ($request->getAttribute('plan')) {
        'enterprise' => 10000,
        'pro' => 1000,
        'free' => 100,
        default => 50,
    },
    period: 60,
    key: fn($request): ?string => $request->getServerParams()['REMOTE_ADDR'] ?? null,
);
```

### Approach 2: Separate Rules per Tier

Create separate rules and use the key closure returning `null` to skip:

```php
// Free tier: 100 requests/minute
$config->throttles->add('free-tier',
    limit: 100, period: 60,
    key: function ($request): ?string {
        if ($request->getAttribute('plan') !== 'free') return null;
        return $request->getAttribute('userId');
    },
);

// Pro tier: 1000 requests/minute
$config->throttles->add('pro-tier',
    limit: 1000, period: 60,
    key: function ($request): ?string {
        if ($request->getAttribute('plan') !== 'pro') return null;
        return $request->getAttribute('userId');
    },
);

// Anonymous fallback: 50 requests/minute per IP
$config->throttles->add('anonymous',
    limit: 50, period: 60,
    key: function ($request): ?string {
        if ($request->getAttribute('userId') !== null) return null;
        return $request->getServerParams()['REMOTE_ADDR'] ?? null;
    },
);
```

::: tip Read tier and identity from request attributes, not headers
`plan` and `userId` here are PSR-7 request **attributes**, set by your authentication middleware after it verifies the principal: `$request = $request->withAttribute('plan', $user->plan)`. Attributes live only on the server-side request object and are never part of the incoming HTTP message, so a client cannot forge them the way it could an `X-Plan` header. Place that middleware before Phirewall in the pipeline (Phirewall still runs after your error handler). Only fall back to a header if a separate upstream service sets it, and then strip or overwrite any inbound copy at the trusted edge.
:::

## Per-Endpoint Cost

Assign different limits to endpoints based on their resource cost:

```php
// Cheap read operations: 1000 req/min
$config->throttles->add('read-operations',
    limit: 1000, period: 60,
    key: function ($request): ?string {
        if ($request->getMethod() !== 'GET') return null;
        return $request->getServerParams()['REMOTE_ADDR'] ?? null;
    },
);

// Moderate write operations: 100 req/min
$config->throttles->add('write-operations',
    limit: 100, period: 60,
    key: function ($request): ?string {
        if (!in_array($request->getMethod(), ['POST', 'PUT', 'PATCH', 'DELETE'], true)) return null;
        return $request->getServerParams()['REMOTE_ADDR'] ?? null;
    },
);

// Expensive export endpoints: 10 req/hour
$config->throttles->add('export-endpoints',
    limit: 10, period: 3600,
    key: function ($request): ?string {
        if (!str_starts_with($request->getUri()->getPath(), '/api/export')) return null;
        return $request->getAttribute('userId')
            ?? ($request->getServerParams()['REMOTE_ADDR'] ?? null);
    },
);
```

## Conditional Bypass

Skip rate limiting for certain scenarios by returning `null` from the key closure:

```php
$config->throttles->add('api-limit',
    limit: 100, period: 60,
    key: function ($request): ?string {
        // Skip for internal services
        $ip = $request->getServerParams()['REMOTE_ADDR'] ?? '';
        if (str_starts_with($ip, '10.')) return null;

        // Skip for admin users
        if ($request->getAttribute('role') === 'admin') return null;

        // Skip for webhooks
        if (str_starts_with($request->getUri()->getPath(), '/webhooks/')) return null;

        return $ip;
    },
);
```

::: tip
For trusted traffic that should bypass **all** rules (not only throttles), use [safelists](/features/safelists-blocklists) instead. Safelisted requests skip the entire firewall pipeline, including blocklists, fail2ban, and track rules.
:::

## Database-Driven Key Assignment

Pre-load user data at bootstrap time rather than querying inside closures. Closures run on every request, so database queries inside them would cause significant latency:

```php
// Pre-load user tiers from database at application bootstrap
$userTiers = $db->fetchAll('SELECT user_id, plan FROM users');
$tierMap = array_column($userTiers, 'plan', 'user_id');

$config->throttles->add('db-tiered',
    limit: fn(ServerRequestInterface $request): int =>
        match ($tierMap[$request->getAttribute('userId') ?? ''] ?? 'anonymous') {
            'enterprise' => 10000,
            'pro' => 1000,
            'free' => 100,
            default => 50,
        },
    period: 60,
    key: fn($request): ?string => $request->getServerParams()['REMOTE_ADDR'] ?? null,
);
```

::: danger
**Never** perform database queries, HTTP calls, or file I/O inside key closures or limit closures. They run on every request, and slow closures directly impact response latency. Pre-load any data you need at configuration time or from a fast in-memory cache.
:::

## Resetting Throttle Counters

The `Firewall` class provides methods to reset counters programmatically. This is useful for admin tools, customer support workflows, or testing:

```php
use Flowd\Phirewall\Http\Firewall;

$firewall = new Firewall($config);

// Reset a specific throttle counter for a key
$firewall->resetThrottle('api', '192.168.1.100');

// For multi-throttle, reset each sub-rule individually
$firewall->resetThrottle('api:1s', '192.168.1.100');
$firewall->resetThrottle('api:60s', '192.168.1.100');

// For dynamic period throttles, include the resolved period suffix
$firewall->resetThrottle('api:p60', '192.168.1.100');

// Reset all counters and bans across all rules
$firewall->resetAll();
```

::: warning
`resetThrottle()` clears fixed-window, multi-window, and dynamic-period counters only. It does **not** reset sliding-window counters created via `throttles->sliding(...)`: sliding windows are stored under per-window keys (suffixed `.w.{windowStart}`) rather than the key `resetThrottle()` deletes. To clear a sliding-window counter, call `resetAll()` or let the windows expire (TTL = 2 x period).
:::

## Best Practices

1. **Use descriptive rule names.** Names appear in `ThrottleExceeded` events and, when `enableResponseHeaders()` is active, in the `X-Phirewall-Matched` response header. (The `X-RateLimit-*` headers carry only numeric limit/remaining/reset values, not the rule name.) Use `api-free-tier` instead of `rule1`.

2. **Return `null` to skip.** This is the primary mechanism for conditional rate limiting. When a key closure returns `null`, the rule is skipped with zero overhead.

3. **Pre-load external data.** Never query databases or external services inside key or limit closures. Load data at configuration time.

4. **Order rules carefully.** The first rule that exceeds its limit determines the response. Put the most restrictive rules first if you want them to take precedence in headers and events.

5. **Enable rate limit headers.** Call `$config->enableRateLimitHeaders()` to expose `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset` headers. This helps well-behaved API clients self-throttle.

6. **Prefer dynamic closures over multiple rules.** A single rule with a closure limit is simpler to maintain than multiple rules with null-routing key closures.

7. **Use sliding windows for public APIs.** If your API is consumed by third parties, sliding windows provide more predictable behavior and prevent boundary exploitation.

## Related Pages

- [Rate Limiting](/features/rate-limiting) - basic throttle setup and rate limit headers
- [Observability](/advanced/observability) - `ThrottleExceeded` events and metrics
- [Safelists & Blocklists](/features/safelists-blocklists) - bypass all rules for trusted traffic
- [Track & Notifications](/advanced/track-notifications) - passive counting for monitoring
