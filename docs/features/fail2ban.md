---
outline: deep
---

# Fail2Ban & Allow2Ban

Fail2Ban and Allow2Ban are Phirewall's automatic banning mechanisms. They monitor request patterns and temporarily ban clients that exceed configurable thresholds -- the primary defense against brute force attacks, credential stuffing, and persistent scanners.

## Fail2Ban

Fail2Ban counts requests that match a **filter** condition. When the count for a given key reaches the threshold within the observation period, the key is banned.

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
            Increment failure counter
                    |
                    v
            Counter >= threshold? --> No --> Continue to throttle rules
                    |
                    Yes
                    |
                    v
            BAN key for configured duration --> 403 Forbidden
```

1. A **filter** closure checks each incoming request for a condition (e.g., a POST to `/login`)
2. Matches are counted per **key** (e.g., IP address) within a time **period**
3. When the count reaches the **threshold**, the key is **banned** for a configurable duration
4. Banned keys receive `403 Forbidden` immediately, without further rule evaluation

### Configuration

```php
$config->fail2ban->add(
    string $name,
    int $threshold,
    int $period,
    int $ban,
    Closure $filter,
    Closure $key
): Fail2BanSection
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$name` | `string` | Unique rule identifier |
| `$threshold` | `int` | Number of filter matches before ban (must be >= 1) |
| `$period` | `int` | Time window for counting matches in seconds (must be >= 1) |
| `$ban` | `int` | Ban duration in seconds (must be >= 1) |
| `$filter` | `Closure` | `fn(ServerRequestInterface): bool` -- return `true` to count as a match |
| `$key` | `Closure` | `fn(ServerRequestInterface): ?string` -- return key to track, or `null` to skip |

::: warning
Fail2Ban filters evaluate the **incoming request** before the handler runs. The filter can only inspect request data (path, method, headers, query parameters). It cannot see the application's response. To ban based on application outcomes (like actual failed logins), use the [Request Context API](#post-handler-signaling-with-requestcontext) instead.
:::

### Login Brute Force Protection

The most common use case: ban IPs that repeatedly POST to the login endpoint.

```php
use Flowd\Phirewall\KeyExtractors;

// Ban after 5 login attempts in 5 minutes, for 1 hour
$config->fail2ban->add('login-brute-force',
    threshold: 5,
    period: 300,       // 5 minute observation window
    ban: 3600,         // 1 hour ban
    filter: fn($req) => $req->getMethod() === 'POST'
        && $req->getUri()->getPath() === '/login',
    key: KeyExtractors::ip()
);
```

::: tip
Counting every POST to `/login` is simpler and works well for most applications. Legitimate users who log in successfully within the threshold are unaffected. Set a generous enough threshold (5-10) so users who mistype their password are not banned.
:::

### Credential Stuffing Defense

Credential stuffing uses stolen username/password lists from data breaches. Defend against it by combining IP-based banning with user-based throttling:

```php
use Flowd\Phirewall\KeyExtractors;

// Per-IP tracking: ban after 10 login attempts in 10 minutes
$config->fail2ban->add('credential-stuffing-ip',
    threshold: 10,
    period: 600,
    ban: 7200,         // 2 hour ban
    filter: fn($req) => $req->getMethod() === 'POST'
        && $req->getUri()->getPath() === '/login',
    key: KeyExtractors::ip()
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
- **Fail2Ban** catches persistent IP-based attacks and bans for hours
- **Per-username throttle** prevents attacks that rotate IPs but target the same account
- **Burst detection** catches rapid-fire automated tools immediately

### API Signature Abuse

Ban clients sending invalid API signatures. A middleware running before Phirewall validates signatures and marks the request:

```php
// The Fail2Ban rule reads the header set by the prior middleware
$config->fail2ban->add('api-abuse',
    threshold: 3,
    period: 120,       // 2 minute window
    ban: 900,          // 15 minute ban
    filter: fn($req) => $req->getHeaderLine('X-Signature-Invalid') === '1',
    key: function ($req): ?string {
        return $req->getHeaderLine('X-API-Key')
            ?: $req->getServerParams()['REMOTE_ADDR'];
    }
);
```

### Persistent Scanner Blocking

Ban IPs that persistently probe your application:

```php
use Flowd\Phirewall\KeyExtractors;

$config->fail2ban->add('persistent-scanner',
    threshold: 10,     // 10 matched requests
    period: 60,        // in 1 minute
    ban: 86400,        // 24 hour ban
    filter: fn($req) => true,
    key: KeyExtractors::ip()
);
```

::: warning
The filter `fn($req) => true` counts every request that reaches the Fail2Ban layer. Because safelisted and blocklisted requests never reach Fail2Ban, this effectively counts requests that passed safelists and blocklists but are still suspicious. Use with care -- this is a broad filter.
:::

## Post-Handler Signaling with RequestContext {#post-handler-signaling-with-requestcontext}

Standard Fail2Ban filters run **before** your application handler, so they can only inspect the incoming request. The **RequestContext API** solves this by letting your handler signal failures **after** it has processed the request -- for example, after verifying credentials against a database.

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
   ├── On failure: $context->recordFailure('rule-name', $key)
   |
   v
Middleware (post-handler)
   |
   ├── Reads recorded failures from RequestContext
   ├── Increments fail2ban counters for each recorded failure
   |
   v
Response
```

### Setup

Configure a fail2ban rule with a filter that always returns `false`. The filter will never match pre-handler -- all counting happens via `recordFailure()`:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\InMemoryCache;
use Psr\Http\Message\ServerRequestInterface;

$config = new Config(new InMemoryCache());

$config->fail2ban->add(
    name: 'login-failures',
    threshold: 3,
    period: 300,       // 5 minute window
    ban: 3600,         // 1 hour ban
    filter: fn(ServerRequestInterface $req): bool => false,
    key: KeyExtractors::ip(),
);
```

### Recording Failures in Your Handler

Inside your request handler, retrieve the `RequestContext` from the request attribute and call `recordFailure()`:

```php
use Flowd\Phirewall\Context\RequestContext;

class LoginController
{
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $username = $request->getParsedBody()['username'] ?? '';
        $password = $request->getParsedBody()['password'] ?? '';

        if (!$this->auth->verify($username, $password)) {
            // Signal the failure to fail2ban
            $context = $request->getAttribute(RequestContext::ATTRIBUTE_NAME);
            $ip = $request->getServerParams()['REMOTE_ADDR'] ?? 'unknown';
            $context?->recordFailure('login-failures', $ip);

            return new Response(401, [], 'Invalid credentials');
        }

        return new Response(200, [], 'Welcome!');
    }
}
```

| Method | Description |
|--------|-------------|
| `$context->recordFailure(string $ruleName, string $key)` | Record a failure signal. `$ruleName` must match a configured fail2ban rule name. `$key` is the discriminator (e.g., IP address). |
| `$context->getResult()` | Returns the `FirewallResult` from the pre-handler evaluation |
| `$context->hasRecordedSignals()` | Whether any failure signals have been recorded |
| `$context->getRecordedFailures()` | Returns all recorded `RecordedFailure` objects |

::: tip
Use the null-safe operator (`$context?->recordFailure(...)`) so your handler works safely both with and without the middleware in the stack -- useful in unit tests where the middleware may not be present.
:::

### Why Use RequestContext?

| Approach | Pros | Cons |
|----------|------|------|
| **Pre-handler filter** (path/method) | Simple, no handler changes | Counts all attempts, not just failures |
| **Prior middleware + header** | Can signal actual failures | Requires extra middleware, complex flow |
| **RequestContext API** | Signals actual failures from handler | Requires handler integration |

RequestContext is the most accurate approach because it only increments the fail2ban counter when your application confirms a failure (wrong password, invalid token, etc.). Successful logins are never counted.

## Allow2Ban {#allow2ban}

Allow2Ban is a **dedicated section** (`$config->allow2ban`) with its own API. It is the inverse of Fail2Ban: instead of counting only filtered "bad" requests, it counts **every request** for a given key and bans once the threshold is exceeded. Think of it as "n requests and you're out."

### How It Works

```text
Request --> Is key already banned? --> Yes --> 403 Forbidden
                    |
                    No
                    |
                    v
            Increment request counter
                    |
                    v
            Counter >= threshold? --> No --> Continue to throttle rules
                    |
                    Yes
                    |
                    v
            BAN key for configured duration --> 403 Forbidden
```

There is no filter -- every request matching the key extractor is counted.

### Configuration

```php
$config->allow2ban->add(
    string $name,
    int $threshold,
    int $period,
    int $banSeconds,
    Closure $key
): Allow2BanSection
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$name` | `string` | Unique rule identifier |
| `$threshold` | `int` | Number of requests before ban (must be >= 1) |
| `$period` | `int` | Time window for counting requests in seconds (must be >= 1) |
| `$banSeconds` | `int` | Ban duration in seconds (must be >= 1) |
| `$key` | `Closure` | `fn(ServerRequestInterface): ?string` -- return key to track, or `null` to skip |

::: tip
Note the parameter name difference: Fail2Ban uses `$ban`, Allow2Ban uses `$banSeconds`. Both accept duration in seconds.
:::

### High-Volume Request Banning

Ban any IP that sends an excessive number of requests:

```php
use Flowd\Phirewall\KeyExtractors;

// Ban any IP that sends more than 100 requests in 60 seconds, for 1 hour
$config->allow2ban->add(
    name: 'high-volume-ban',
    threshold: 100,
    period: 60,
    banSeconds: 3600,
    key: KeyExtractors::ip(),
);
```

### API Key Abuse Protection

Ban API keys that exceed expected usage. Unlike rate limiting (which returns 429 and lets the client retry), Allow2Ban **bans** the key entirely -- a stronger response for abuse:

```php
use Flowd\Phirewall\KeyExtractors;

// Ban any API key that makes more than 1000 requests in 60 seconds
$config->allow2ban->add(
    name: 'api-key-abuse',
    threshold: 1000,
    period: 60,
    banSeconds: 300,   // 5 minute ban
    key: KeyExtractors::header('X-Api-Key'),
);
```

### Unauthenticated Endpoint Abuse

Ban clients that repeatedly access authenticated endpoints without credentials:

```php
use Flowd\Phirewall\KeyExtractors;

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
| **Filter** | Required -- only matching requests are counted | No filter -- all requests for the key are counted |
| **Trigger** | Repeated "bad" requests matching the filter | Exceeding a total request volume |
| **Use case** | Brute force, credential stuffing, scanner blocking | Volume abuse, DDoS mitigation, API abuse |
| **Event** | `Fail2BanBanned` | `Allow2BanBanned` |
| **Ban parameter** | `$ban` | `$banSeconds` |

## Events

When a key is banned, an event is dispatched through your PSR-14 event dispatcher. Fail2Ban and Allow2Ban each dispatch their own event type.

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
use Flowd\Phirewall\KeyExtractors;

// Layer 1: Safelist trusted traffic
$config->safelists->add('health', fn($req) => $req->getUri()->getPath() === '/health');

// Layer 2: Blocklist known bad actors
$config->blocklists->knownScanners();

// Layer 3: Fail2Ban for brute force (counts POST to /login)
$config->fail2ban->add('login',
    threshold: 5, period: 300, ban: 3600,
    filter: fn($req) => $req->getMethod() === 'POST'
        && $req->getUri()->getPath() === '/login',
    key: KeyExtractors::ip()
);

// Layer 4: Allow2Ban for volume abuse
$config->allow2ban->add('volume-abuse',
    threshold: 200, period: 60, banSeconds: 1800,
    key: KeyExtractors::ip()
);

// Layer 5: Rate limiting as backstop
$config->throttles->add('global',
    limit: 100, period: 60,
    key: KeyExtractors::ip()
);
```

## Best Practices

1. **Use specific filters.** A broad filter like `fn() => true` can lead to false bans. Prefer precise filters tied to specific request characteristics (path, method, headers).

2. **Set reasonable thresholds.** Too low and you risk banning legitimate users. Too high and attackers have more attempts. Start with 5-10 for login protection, 50-200 for Allow2Ban volume limits.

3. **Consider ban duration carefully.** Short bans (5-15 minutes) deter casual attackers while minimizing impact on legitimate users. Long bans (1-24 hours) are better for persistent automated attacks.

4. **Combine with rate limiting.** Even before the ban threshold is reached, [rate limiting](/features/rate-limiting) slows down attackers. Use throttles as a softer first response (429) and bans as the hard response (403).

5. **Monitor with events.** Always set up logging or alerting for `Fail2BanBanned` and `Allow2BanBanned` events so you know when bans are occurring and can detect false positives.

6. **Use RequestContext for accuracy.** When you need to ban based on actual application failures (not just request patterns), use the [RequestContext API](#post-handler-signaling-with-requestcontext) to signal failures from your handler.

7. **Use infrastructure mirroring.** For the most effective defense, mirror bans to Apache `.htaccess` or your web server so banned IPs are blocked before reaching PHP. See [Infrastructure Adapters](/advanced/infrastructure).

8. **Choose the right mechanism.** Use Fail2Ban when you need a filter to detect specific bad behavior. Use Allow2Ban when you want a blanket volume limit with a ban (not just rate limiting).
