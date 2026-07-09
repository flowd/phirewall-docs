---
outline: deep
---

# Fail2Ban & Allow2Ban

Fail2Ban and Allow2Ban are Phirewall's automatic banning mechanisms. They monitor request patterns and temporarily ban clients that exceed configurable thresholds, the primary defense against brute force attacks, credential stuffing, and persistent scanners.

## Fail2Ban

A Fail2Ban **filter** marks a request as malicious by definition, so Fail2Ban **blocks every filter match with `403`** and counts it. When the count for a given key reaches the threshold within the observation period, the key is additionally banned for the ban duration.

::: warning Behavioral change in 0.8
Before 0.8 a filter match below the threshold passed through, so a Fail2Ban filter acted as a slow counter. From 0.8 **every** match is blocked. A rule whose filter can match a legitimate request (for example counting every login POST) must move to [Allow2Ban with a filter](#allow2ban), which counts matches but lets them pass until the threshold. See [Migrating to 0.8](#migrating-to-08).
:::

### How It Works

```text
Request --> Is key already banned? --> Yes --> 403 Forbidden
                    |
                    No
                    |
                    v
            Does filter match? --> No --> Continue to throttle rules
                    |
                    Yes
                    |
                    v
            Increment failure counter, then block (403)
                    |
                    v
            Counter >= threshold? --> No  --> 403 (Fail2BanMatched event)
                    |
                    Yes
                    |
                    v
            BAN key for configured duration --> 403 (Fail2BanBanned event)
```

1. A **filter** closure checks each incoming request for a condition (e.g., a request to a scanner path)
2. Every match is **blocked with `403`** and counted per **key** (e.g., IP address) within a time **period**
3. A match **below** the threshold blocks via `DecisionPath::Fail2BanMatched` and dispatches the [`Fail2BanMatched`](#fail2banmatched) event
4. When the count **reaches** the **threshold**, the key is additionally **banned** for the configured duration; that match blocks via `DecisionPath::Fail2BanBanned` and dispatches [`Fail2BanBanned`](#fail2banbanned) (never both events)
5. Banned keys then receive `403 Forbidden` immediately, without further rule evaluation

### Configuration

```php
$config->fail2ban->add(
    string $name,
    int $threshold,
    int $period,
    int $ban,
    Closure $filter,
    ?Closure $key = null
): Fail2BanSection
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$name` | `string` | Unique rule identifier |
| `$threshold` | `int` | Number of filter matches that triggers the ban (must be >= 1). Every match is blocked; the Nth match additionally bans the key. |
| `$period` | `int` | Time window for counting matches in seconds (must be >= 1) |
| `$ban` | `int` | Ban duration in seconds (must be >= 1) |
| `$filter` | `Closure` | `fn(ServerRequestInterface): bool`, return `true` to block and count the request as a match |
| `$key` | `?Closure` | `fn(ServerRequestInterface): ?string`, return key to track, or `null` to skip. When the whole argument is omitted, defaults to the client IP from the Config's IP resolver (`Config::setIpResolver()`), falling back to REMOTE_ADDR. Configure proxy trust once with `$config->setIpResolver((new TrustedProxyResolver([...]))->resolve(...))` and all keyless rules key on the resolved client IP. The resolver is read per request, so it can be set before or after the rule. |

::: warning
Fail2Ban filters evaluate the **incoming request** before the handler runs. The filter can only inspect request data (path, method, headers, query parameters). It cannot see the application's response. To ban based on application outcomes (like actual failed logins), use the [Request Context API](#post-handler-signaling-with-requestcontext) instead.
:::

### Login Brute Force Protection

Do **not** use a request-time Fail2Ban filter to count login POSTs: from 0.8 every match is blocked, so `filter: fn($req) => $req->getUri()->getPath() === '/login'` would reject the **first** legitimate login attempt with `403`. A login POST is a legitimate request that deserves a few retries, so counting it belongs in Allow2Ban or in a post-handler signal:

- **Count login attempts** with [Allow2Ban and a filter](#allow2ban) on `POST /login`: attempts are counted but pass until the threshold, then the key is banned. Successful attempts count too, so choose a generous threshold.
- **Count real, handler-verified failures** with a signal-only Fail2Ban rule whose filter never matches, driven by [`RequestContext::recordFailure()`](#post-handler-signaling-with-requestcontext). This is the most accurate option and only counts genuine failures.

```php

// Signal-only: the filter never matches at request time, so nothing is
// blocked pre-handler. Your login handler reports each verified failure
// (see "Post-Handler Signaling" below); the key is banned after 5 in 5 min.
$config->fail2ban->add('login-failures',
    threshold: 5,
    period: 300,       // 5 minute observation window
    ban: 3600,         // 1 hour ban
    filter: fn($req) => false,
);
```

::: tip
Set a generous enough threshold so users who mistype their password are not banned. The signal-only rule above counts only genuine failures, so its threshold can be tight (5-10); an Allow2Ban rule counting every login attempt should use a more generous threshold, since successful logins count too.
:::

### Credential Stuffing Defense

Credential stuffing uses stolen username/password lists from data breaches. Defend against it by combining Allow2Ban (to ban IPs that make many login attempts, letting real attempts through until the threshold) with user-based throttling:

```php

// Per-IP: count login attempts (POST /login) and ban after 30 in 10 minutes.
// Attempts pass until the threshold, so a user who mistypes their password a
// few times is not blocked on the spot. Successful attempts count too, so the
// threshold is generous; for exact failure counting, drive a signal-only rule
// from your handler with RequestContext::recordFailure().
$config->allow2ban->add('credential-stuffing-ip',
    threshold: 30,
    period: 600,
    banSeconds: 7200,  // 2 hour ban
    filter: fn($req) => $req->getMethod() === 'POST'
        && $req->getUri()->getPath() === '/login',
);

// Per-username throttle: 5 attempts per 5 minutes per username
$config->throttles->add('credential-stuffing-user',
    limit: 5,
    period: 300,
    key: function ($req): ?string {
        if ($req->getMethod() !== 'POST' || $req->getUri()->getPath() !== '/login') {
            return null;
        }
        $body = (array) $req->getParsedBody();
        $username = $body['username'] ?? $body['email'] ?? null;
        return $username ? 'user:' . strtolower(trim($username)) : null;
    }
);

// Burst detection: 3 login attempts in 10 seconds = suspicious
$config->throttles->add('login-burst',
    limit: 3,
    period: 10,
    key: function ($req): ?string {
        if ($req->getMethod() === 'POST' && $req->getUri()->getPath() === '/login') {
            return $req->getServerParams()['REMOTE_ADDR'] ?? null;
        }
        return null;
    }
);
```

This three-layer strategy defends against different attack speeds:
- **Allow2Ban** catches persistent IP-based attacks and bans for hours, without blocking a user's first mistyped password
- **Per-username throttle** prevents attacks that rotate IPs but target the same account
- **Burst detection** catches rapid-fire automated tools immediately

### API Signature Abuse

Block and ban clients sending invalid API signatures. An invalid signature is unambiguously malicious, so Fail2Ban is the right tool: each invalid-signature request is blocked with `403` on the spot, and the key is banned after the threshold. A middleware running before Phirewall validates the signature and records the outcome and the verified client id on the request as attributes:

```php
// The Fail2Ban rule reads the attributes the prior middleware set
$config->fail2ban->add('api-abuse',
    threshold: 3,
    period: 120,       // 2 minute window
    ban: 900,          // 15 minute ban
    filter: fn($req) => $req->getAttribute('apiSignatureValid') === false,
    // Key on the verified client id (an internal identifier, not the raw API
    // secret), falling back to the client IP when the request is unauthenticated.
    key: fn($req): ?string =>
        $req->getAttribute('apiClientId') ?? ($req->getServerParams()['REMOTE_ADDR'] ?? null),
);
```

### Persistent Scanner Blocking

Ban IPs that probe sensitive paths. Each probe is unambiguously malicious, so Fail2Ban blocks it with `403` immediately and bans the IP after repeated probes within the window:

```php

$config->fail2ban->add('persistent-scanner',
    threshold: 10,     // ban after 10 probes
    period: 60,        // in 1 minute
    ban: 86400,        // 24 hour ban
    filter: fn($req) => (bool) preg_match(
        '#^/(\.env|\.git|\.aws/credentials|\.htpasswd)#i',
        $req->getUri()->getPath(),
    ),
);
```

::: warning Do not use `fn($req) => true` for Fail2Ban
Before 0.8 a broad `fn($req) => true` filter merely counted requests and banned after the threshold. From 0.8 every match is blocked, so `fn($req) => true` blocks **every** request that reaches the Fail2Ban layer (everything not safelisted or blocklisted) with `403`. Keep Fail2Ban filters tied to specific, unambiguously malicious request characteristics. To ban purely on request volume, use [Allow2Ban](#allow2ban) instead.
:::

## Post-Handler Signaling with RequestContext {#post-handler-signaling-with-requestcontext}

Standard Fail2Ban filters run **before** your application handler, so they can only inspect the incoming request. The **RequestContext API** solves this by letting your handler signal failures **after** it has processed the request, for example after verifying credentials against a database.

### How It Works

```text
Request
   |
   v
Middleware (pre-handler)
   |
   ├── Firewall evaluates safelists, blocklists, fail2ban, throttles
   ├── Attaches RequestContext to request attribute
   |
   v
Your Handler
   |
   ├── Checks credentials, validates input, etc.
   ├── On failure: $context->recordFailure('rule-name')
   |
   v
Middleware (post-handler)
   |
   ├── Reads recorded signals from RequestContext
   ├── Increments fail2ban / allow2ban counters per signal
   |
   v
Response
```

### Setup

Configure a fail2ban rule with a filter that always returns `false`. The filter will never match pre-handler; all counting happens via `recordFailure()`:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;
use Psr\Http\Message\ServerRequestInterface;

$config = new Config(new InMemoryCache());

$config->fail2ban->add(
    name: 'login-failures',
    threshold: 3,
    period: 300,       // 5 minute window
    ban: 3600,         // 1 hour ban
    filter: fn(ServerRequestInterface $req): bool => false,
);
```

### Recording Failures in Your Handler

Inside your request handler, retrieve the `RequestContext` from the request attribute and call `recordFailure()`. The second argument is optional; when omitted, the firewall reuses the rule's own `keyExtractor` against this request, so the handler doesn't need to repeat the IP/header/etc. extraction:

```php
use Flowd\Phirewall\Context\RequestContext;

class LoginController
{
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $body = (array) $request->getParsedBody();
        $username = $body['username'] ?? '';
        $password = $body['password'] ?? '';

        if (!$this->auth->verify($username, $password)) {
            // Signal the failure; the firewall extracts the key from
            // the rule's own keyExtractor against this request.
            $context = $request->getAttribute(RequestContext::ATTRIBUTE_NAME);
            $context?->recordFailure('login-failures');

            return new Response(401, [], 'Invalid credentials');
        }

        return new Response(200, [], 'Welcome!');
    }
}
```

Pass an explicit second argument only when the handler knows a discriminator the firewall cannot derive from the request alone (e.g. a user id looked up in a session store):

```php
$context?->recordFailure('login-failures', $userIdFromSession);
```

| Method | Description |
|--------|-------------|
| `$context->recordFailure(string $ruleName, ?string $key = null)` | Record a fail2ban failure signal. `$ruleName` must match a configured fail2ban rule name. `$key` is **optional**; when omitted, the rule's own key extractor resolves the discriminator from the current request, so the handler does not need to know whether the rule keys on IP, header, or anything else. |
| `$context->recordHit(string $ruleName, ?string $key = null)` | Counterpart for allow2ban rules; same shape, routed through the allow2ban evaluator. See [Request Context](/advanced/request-context#recording-allow2ban-hits). |
| `$context->getResult()` | Returns the `FirewallResult` from the pre-handler evaluation |
| `$context->hasRecordedSignals()` | Whether any signals have been recorded |
| `$context->getRecordedSignals()` | Returns all recorded `RecordedSignal` objects |

::: tip
Use the null-safe operator (`$context?->recordFailure(...)`) so your handler works safely both with and without the middleware in the stack, useful in unit tests where the middleware may not be present.
:::

### Why Use RequestContext?

| Approach | Pros | Cons |
|----------|------|------|
| **Pre-handler Fail2Ban filter** (path/method) | Simple, no handler changes | Blocks **every** match from 0.8, so it cannot count legitimate login POSTs; only use it for unambiguously malicious matches |
| **Allow2Ban filter + failure marker header** | Counts matches but lets them pass until the threshold | Needs an upstream that sets a trustworthy marker header |
| **RequestContext API** (signal-only Fail2Ban) | Signals actual failures from handler; never blocks a legitimate attempt | Requires handler integration |

RequestContext is the most accurate approach because it only increments the fail2ban counter when your application confirms a failure (wrong password, invalid token, etc.). Successful logins are never counted, and no legitimate request is ever blocked pre-handler.

## Allow2Ban {#allow2ban}

Allow2Ban is a **dedicated section** (`$config->allow2ban`) with its own API. Like Fail2Ban it counts matches per key and bans once the count reaches the threshold, but unlike Fail2Ban it **lets matching requests pass** until the threshold is crossed instead of blocking each one. Think of it as "n requests allowed, then you're out": with `threshold: n`, the nth request itself is the one that triggers and is blocked.

Allow2Ban takes an **optional filter**:

- **Without a filter** it counts **every** request for the key, a hard volume cap.
- **With a filter** it counts only the requests the filter matches; other requests are not counted at all.

Either way, an already-banned key is blocked on **every** request regardless of the filter.

### How It Works

```text
Request --> Is key already banned? --> Yes --> 403 Forbidden
                    |
                    No
                    |
                    v
            Filter set and no match? --> Yes --> Allow (not counted)
                    |
                    No
                    |
                    v
            Increment request counter
                    |
                    v
            Counter >= threshold? --> No --> Allow (pass to handler)
                    |
                    Yes
                    |
                    v
            BAN key for configured duration --> 403 Forbidden
```

### Configuration

```php
$config->allow2ban->add(
    string $name,
    int $threshold,
    int $period,
    int $banSeconds,
    ?Closure $key = null,
    ?Closure $filter = null
): Allow2BanSection
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$name` | `string` | Unique rule identifier |
| `$threshold` | `int` | Number of counted requests that triggers the ban (must be >= 1). The Nth counted request is itself banned. |
| `$period` | `int` | Time window for counting requests in seconds (must be >= 1) |
| `$banSeconds` | `int` | Ban duration in seconds (must be >= 1) |
| `$key` | `?Closure` | `fn(ServerRequestInterface): ?string`, return key to track, or `null` to skip. When omitted, defaults to the client IP from the Config's IP resolver (see Fail2Ban's `$key` above). |
| `$filter` | `?Closure` | `fn(ServerRequestInterface): bool`, return `true` to count the request. Omit to count every request. Use `static fn() => false` for a signal-only rule driven solely by [`RequestContext::recordHit()`](/advanced/request-context#recording-allow2ban-hits). |

::: tip
Note the parameter name difference: Fail2Ban uses `$ban`, Allow2Ban uses `$banSeconds`. Both accept duration in seconds.
:::

### Filtered Counting

Count only the requests you care about and let everything else pass unmetered. This is the natural home for login brute-force counting and any "count these specific requests, ban after N" policy:

```php

// Only count login attempts (POST /login). Reads and other paths are never
// counted, so the client can browse freely but is banned after 30 login
// attempts in 5 minutes. Successful attempts count too, so the threshold is
// generous; to count only genuine failures, drive a signal-only rule from
// your handler with RequestContext::recordHit().
$config->allow2ban->add(
    name: 'login-brute-force',
    threshold: 30,
    period: 300,
    banSeconds: 3600,
    key: fn($req): string => $req->getServerParams()['REMOTE_ADDR'] ?? '',
    filter: fn($req): bool => $req->getMethod() === 'POST'
        && $req->getUri()->getPath() === '/login',
);
```

Matching requests still pass until the 30th within the window; the 30th is the one blocked and banned.

### High-Volume Request Banning

Ban any IP that sends an excessive number of requests:

```php

// Ban any IP that sends more than 100 requests in 60 seconds, for 1 hour
$config->allow2ban->add(
    name: 'high-volume-ban',
    threshold: 100,
    period: 60,
    banSeconds: 3600,
);
```

### API Key Abuse Protection

Ban API keys that exceed expected usage. Unlike rate limiting (which returns 429 and lets the client retry), Allow2Ban **bans** the key entirely, a stronger response for abuse:

```php
// Ban any client IP that makes more than 1000 requests in 60 seconds.
$config->allow2ban->add(
    name: 'api-volume-abuse',
    threshold: 1000,
    period: 60,
    banSeconds: 300,   // 5 minute ban
);
```

::: warning Header keys are client-controlled
A throttle, fail2ban, or allow2ban rule keyed on a request header (`X-Api-Key`, `X-User-Id`, …) is only as trustworthy as that header. A client can rotate or drop the header to land in a fresh counter on every request and never reach the threshold (a trivial bypass). Key such rules on a value the client cannot freely change: the client IP (configure proxy trust once with `$config->setIpResolver((new TrustedProxyResolver([...]))->resolve(...))` and omit the key so the rule keys on the resolved client IP), the authenticated principal your auth layer sets *after* verifying it, or a composite of both. When you must key on a credential-bearing header, use `KeyExtractors::hashedHeader('X-Api-Key')`: the raw value otherwise reaches the ban registry and event payloads (and your logs) in cleartext.
:::

### Unauthenticated Endpoint Abuse

Ban clients that repeatedly access authenticated endpoints without credentials:

```php

// Ban IPs making more than 20 unauthenticated API requests in 5 minutes
$config->allow2ban->add(
    name: 'unauth-api-abuse',
    threshold: 20,
    period: 300,
    banSeconds: 1800,  // 30 minute ban
    key: function ($req): ?string {
        // Only count unauthenticated requests to API endpoints
        if ($req->getHeaderLine('Authorization') === ''
            && str_starts_with($req->getUri()->getPath(), '/api/')) {
            return $req->getServerParams()['REMOTE_ADDR'] ?? null;
        }
        return null;
    },
);
```

### Fail2Ban vs. Allow2Ban

| Aspect | Fail2Ban | Allow2Ban |
|--------|----------|-----------|
| **Section** | `$config->fail2ban` | `$config->allow2ban` |
| **Filter** | Required: marks a request as malicious | Optional: without it counts every request, with it counts only matches |
| **On a match** | **Blocks immediately** (`403`) and counts | **Lets the request pass** and counts, until the threshold |
| **Trigger** | Any match (block); Nth match (ban) | Nth counted request (ban) |
| **Use case** | Unambiguously malicious matches (scanner paths, invalid signatures), signal-only rules | Login brute-force counting, volume abuse, "count these, ban after N" |
| **Events** | `Fail2BanMatched` (sub-threshold block), `Fail2BanBanned` (ban) | `Allow2BanBanned` (ban) |
| **Ban parameter** | `$ban` | `$banSeconds` |

## Managing Bans

`Flowd\Phirewall\Http\Firewall` is the supported runtime-management entry point. Construct it with the same `Config` your middleware uses; all state lives in the `Config` cache, so every `Firewall` over the same `Config` shares bans and counters.

```php
use Flowd\Phirewall\BanType;
use Flowd\Phirewall\Http\Firewall;

$firewall = new Firewall($config);

// Is a key currently banned? BanType is REQUIRED (no default).
$firewall->isBanned('login-failures', $ip, BanType::Fail2Ban);
$firewall->isBanned('high-volume-ban', $ip, BanType::Allow2Ban);

// Lift a specific fail2ban ban (also clears its fail counter).
$firewall->resetFail2Ban('login-failures', $ip);

// Clear a throttle counter.
$firewall->resetThrottle('api', $ip);

// Clear the whole cache instance (counters, bans, tracking).
$firewall->resetAll();
```

`isBanned()` requires an explicit `BanType` because allow2ban and fail2ban store their bans under distinct cache keys, so an implicit default would silently answer for the wrong category:

```php
enum BanType: string
{
    case Allow2Ban = 'allow2ban';
    case Fail2Ban = 'fail2ban';
}
```

Notes:

- For `multi()` throttle sub-rules, reset each window individually (for example `'api:1s'` and `'api:60s'`); for dynamic-period rules, pass the `:p{period}` suffix.
- `resetAll()` calls `cache->clear()` and wipes the entire cache instance, so give phirewall a dedicated cache (or key-prefixed namespace) if you share Redis/APCu with your application.
- All keys are normalized through the discriminator normalizer, so lookups match regardless of input casing.

## Events

Fail2Ban and Allow2Ban dispatch events through your PSR-14 event dispatcher. Fail2Ban dispatches `Fail2BanMatched` for every match blocked below the threshold and `Fail2BanBanned` for the match that bans (never both for the same request); Allow2Ban dispatches `Allow2BanBanned` when a key is banned.

### Fail2BanMatched

Dispatched when a Fail2Ban filter matches a request that is blocked **below** the ban threshold. The Nth (threshold) match dispatches `Fail2BanBanned` instead, never both. The post-handler `RequestContext::recordFailure()` path never dispatches this event.

```php
use Flowd\Phirewall\Events\Fail2BanMatched;

// Event properties
$event->rule;           // string - Rule name
$event->key;            // string - Matched key (e.g., IP address)
$event->threshold;      // int - Configured threshold
$event->period;         // int - Observation window (seconds)
$event->count;          // int - Match count after this request (< threshold)
$event->serverRequest;  // ServerRequestInterface
```

### Fail2BanBanned

```php
use Flowd\Phirewall\Events\Fail2BanBanned;

// Event properties
$event->rule;           // string - Rule name
$event->key;            // string - Banned key (e.g., IP address)
$event->threshold;      // int - Configured threshold
$event->period;         // int - Observation window (seconds)
$event->banSeconds;     // int - Ban duration (seconds)
$event->count;          // int - Failure count that triggered the ban
$event->serverRequest;  // ServerRequestInterface
```

### Allow2BanBanned

```php
use Flowd\Phirewall\Events\Allow2BanBanned;

// Event properties (same structure as Fail2BanBanned)
$event->rule;           // string - Rule name
$event->key;            // string - Banned key
$event->threshold;      // int - Configured threshold
$event->period;         // int - Observation window (seconds)
$event->banSeconds;     // int - Ban duration (seconds)
$event->count;          // int - Request count that triggered the ban
$event->serverRequest;  // ServerRequestInterface
```

### Alerting on Bans

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Flowd\Phirewall\Events\Allow2BanBanned;
use Psr\EventDispatcher\EventDispatcherInterface;

$dispatcher = new class implements EventDispatcherInterface {
    public function dispatch(object $event): object
    {
        if ($event instanceof Fail2BanBanned) {
            error_log(sprintf(
                '[PHIREWALL] Fail2Ban: IP %s banned (rule: %s, failures: %d, ban: %ds)',
                $event->key,
                $event->rule,
                $event->count,
                $event->banSeconds,
            ));
        }

        if ($event instanceof Allow2BanBanned) {
            error_log(sprintf(
                '[PHIREWALL] Allow2Ban: key %s banned (rule: %s, requests: %d, ban: %ds)',
                $event->key,
                $event->rule,
                $event->count,
                $event->banSeconds,
            ));
        }

        return $event;
    }
};

$config = new Config($cache, $dispatcher);
```

Use events to:
- Send Slack/email alerts when a key is banned
- Log bans to your monitoring system (see [Observability](/advanced/observability))
- Mirror bans to [infrastructure adapters](/advanced/infrastructure) (e.g., Apache `.htaccess`)
- Push bans to a WAF or external firewall

## Combining Fail2Ban with Other Layers

Fail2Ban and Allow2Ban work best as part of a layered defense:

```php

// Layer 1: Safelist trusted traffic
$config->safelists->add('health', fn($req) => $req->getUri()->getPath() === '/health');

// Layer 2: Blocklist known bad actors
$config->blocklists->knownScanners();

// Layer 3: Fail2Ban blocks and bans probes to sensitive paths on match
$config->fail2ban->add('scanner-probe',
    threshold: 5, period: 60, ban: 86400,
    filter: fn($req) => (bool) preg_match(
        '#^/(\.env|\.git|\.aws/credentials)#i',
        $req->getUri()->getPath(),
    ),
);

// Layer 4: Allow2Ban bans IPs that make many login attempts, letting real
// attempts through until the threshold
$config->allow2ban->add('login-brute-force',
    threshold: 30, period: 300, banSeconds: 3600,
    filter: fn($req) => $req->getMethod() === 'POST'
        && $req->getUri()->getPath() === '/login',
);

// Layer 4b: Allow2Ban for raw volume abuse
$config->allow2ban->add('volume-abuse',
    threshold: 200, period: 60, banSeconds: 1800,
);

// Layer 5: Rate limiting as backstop
$config->throttles->add('global',
    limit: 100, period: 60,
);
```

## Best Practices

1. **Use specific Fail2Ban filters.** From 0.8 a Fail2Ban filter blocks every match, so a broad filter like `fn() => true` blocks all traffic reaching the layer, not just repeat offenders. Tie Fail2Ban filters to unambiguously malicious characteristics (scanner paths, invalid signatures). To count requests that are themselves legitimate, use Allow2Ban.

2. **Set reasonable thresholds.** Too low and you risk banning legitimate users. Too high and attackers have more attempts. Start with 5-10 for login protection, 50-200 for Allow2Ban volume limits.

3. **Consider ban duration carefully.** Short bans (5-15 minutes) deter casual attackers while minimizing impact on legitimate users. Long bans (1-24 hours) are better for persistent automated attacks.

4. **Combine with rate limiting.** Even before the ban threshold is reached, [rate limiting](/features/rate-limiting) slows down attackers. Use throttles as a softer first response (429) and bans as the hard response (403).

5. **Monitor with events.** Always set up logging or alerting for `Fail2BanBanned` and `Allow2BanBanned` events so you know when bans are occurring and can detect false positives.

6. **Use RequestContext for accuracy.** When you need to ban based on actual application failures (not only request patterns), use the [RequestContext API](#post-handler-signaling-with-requestcontext) to signal failures from your handler.

7. **Use infrastructure mirroring.** For the most effective defense, mirror bans to Apache `.htaccess` or your web server so banned IPs are blocked before reaching PHP. See [Infrastructure Adapters](/advanced/infrastructure).

8. **Choose the right mechanism.** Use Fail2Ban to block and ban unambiguously malicious matches on the spot (or as a signal-only rule driven by `RequestContext`). Use Allow2Ban when the counted requests are themselves legitimate and should pass until the threshold (login brute-force counting, blanket volume limits).

## Migrating to 0.8

0.8 changes the Fail2Ban and Allow2Ban semantics. Two behavioral changes affect existing configs:

**Fail2Ban now blocks every filter match.** Previously a match below the threshold passed through, so a Fail2Ban filter acted as a slow counter. Now every match is blocked with `403`.

- A Fail2Ban rule whose filter matches **only unambiguously malicious** traffic (scanner paths, WAF-flagged requests, invalid signatures) needs **no change** and now blocks the probe immediately, which is the intended behavior.
- A Fail2Ban rule whose filter can match a **legitimate** request (for example counting every login POST) must move to **Allow2Ban with a filter**, which counts matches but lets them pass until the threshold:

  ```php
  // Before (0.7): counted login POSTs, banned after 5
  $config->fail2ban->add('login', threshold: 5, period: 300, ban: 3600,
      filter: fn($req) => $req->getMethod() === 'POST' && $req->getUri()->getPath() === '/login');

  // After (0.8): same intent, but real login attempts still pass until the ban
  $config->allow2ban->add('login', threshold: 5, period: 300, banSeconds: 3600,
      filter: fn($req) => $req->getMethod() === 'POST' && $req->getUri()->getPath() === '/login');
  ```

  Note the parameter rename `ban:` to `banSeconds:`; the key still defaults to the client IP.
- A **signal-only** rule (`filter: fn() => false` driven by `RequestContext::recordFailure()`) is **unaffected**: `recordFailure()` still only counts and may ban, never blocks the current request and never dispatches `Fail2BanMatched`. This is the recommended pattern for handler-verified login failures, and the one every shipped preset already uses, so presets need no change.

**Allow2Ban gained an optional filter** (see [Filtered Counting](#filtered-counting)). Existing filterless Allow2Ban rules keep the exact previous behavior (a hard volume cap counting every request), so no change is required.

New in 0.8: the [`Fail2BanMatched`](#fail2banmatched) event and `DecisionPath::Fail2BanMatched` (diagnostics category `fail2ban_matched`). See [Observability](/advanced/observability).
