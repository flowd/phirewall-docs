---
outline: deep
---

# Common Attacks

Ready-to-use Phirewall configurations for defending against common web application attacks. Each recipe is self-contained: copy what you need and adapt it to your application.

## Brute Force Login

Protect login endpoints with layered rate limiting and fail2ban.

### Post-Handler Failure Signaling (recommended)

The accurate way to ban on *real* failed logins is to record the failure **after** your handler has verified the credentials, using [RequestContext](/features/fail2ban#post-handler-signaling-with-requestcontext). The fail2ban rule's filter never matches on its own (`fn() => false`), so nothing is blocked pre-handler; your handler decides what counts as a failure and records it, and the middleware processes the recorded signal once the handler returns. This pattern is demonstrated in [`examples/27-request-context.php`](https://github.com/flowd/phirewall/blob/main/examples/27-request-context.php). To count login attempts with a request-inspectable filter instead (banning after a generous threshold, since successful attempts count too), [`examples/02-brute-force-protection.php`](https://github.com/flowd/phirewall/blob/main/examples/02-brute-force-protection.php) uses Allow2Ban with a filter.

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Context\RequestContext;
use Flowd\Phirewall\Store\RedisCache;
use Psr\Http\Message\ServerRequestInterface;

$config = new Config(new RedisCache($redis));

// Ban after 3 verified failures in 5 minutes for 1 hour.
// The filter never matches; failures are signaled by the handler.
$config->fail2ban->add('login-failures',
    threshold: 3, period: 300, ban: 3600,
    filter: fn(ServerRequestInterface $req): bool => false,
);

// In your login handler, AFTER checking credentials:
if (!$this->authenticate($username, $password)) {
    $context = $request->getAttribute(RequestContext::ATTRIBUTE_NAME);
    // recordFailure's key is optional; with none, the rule resolves the
    // discriminator itself (here the client IP).
    $context?->recordFailure('login-failures');
}
```

Only genuine failures are counted, so a user who logs in correctly on the first try is never one attempt closer to a ban.

### Login Endpoint Throttle

Add a rate limit specifically on the login path to slow down attackers:

```php
use Flowd\Phirewall\Config\ClosureRequestMatcher;
use Flowd\Phirewall\Config\Rule\ThrottleRule;

// A null key defaults to the resolved client IP (proxy-aware via the Config's
// IP resolver); the scope filter restricts the throttle to the login path.
$config->throttles->addRule(new ThrottleRule(
    'login-throttle',
    limit: 10,
    period: 60,
    keyExtractor: null,
    scope: new ClosureRequestMatcher(
        fn(ServerRequestInterface $req): bool => $req->getUri()->getPath() === '/login'
    ),
));
```

### Credential Stuffing (Per-Username)

Throttle per username to prevent attackers from testing many passwords against a single account:

```php
$config->throttles->add('account-throttle',
    limit: 5,
    period: 60,
    key: function (ServerRequestInterface $req): ?string {
        if ($req->getMethod() !== 'POST' || $req->getUri()->getPath() !== '/login') {
            return null;
        }
        // Key on the submitted credential read from the request body, not a
        // client-settable header: an attacker could rotate or omit X-Username
        // to dodge the per-account limit entirely.
        $body = (array) $req->getParsedBody();
        $username = $body['username'] ?? $body['email'] ?? null;
        return $username !== null ? 'user:' . strtolower(trim((string) $username)) : null;
    },
);
```

## SQL Injection

Block common SQL injection patterns using OWASP CRS rules.

::: tip OWASP CRS is a separate package
The SecRule engine and CRS presets ship in the companion package. Install it first:
`composer require flowd/phirewall-preset-owasp-crs`. See [OWASP CRS](/features/owasp-crs) for details.
:::

```php
use Flowd\Phirewall\Config\Rule\BlocklistRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;
use Flowd\PhirewallPresetOwaspCrs\Engine\SecRuleLoader;

$rules = SecRuleLoader::fromString(<<<'CRS'
# UNION SELECT attacks
SecRule ARGS "@rx (?i)\bunion\b.*\bselect\b" \
    "id:942100,phase:2,deny,msg:'SQL Injection: UNION SELECT'"

# SELECT FROM attacks
SecRule ARGS "@rx (?i)\bselect\b.*\bfrom\b" \
    "id:942110,phase:2,deny,msg:'SQL Injection: SELECT FROM'"

# Boolean-based blind injection
SecRule ARGS "@rx (?i)('\s*(or|and)\s*'|'\s*=\s*')" \
    "id:942120,phase:2,deny,msg:'SQL Injection: Boolean-based'"

# Stacked queries (DROP, DELETE, INSERT, UPDATE)
SecRule ARGS "@rx (?i);\s*(drop|delete|insert|update|create|alter|truncate)\b" \
    "id:942130,phase:2,deny,msg:'SQL Injection: Stacked query'"

# Comment sequences
SecRule ARGS "@rx (--\s*$|/\*|\*/)" \
    "id:942140,phase:2,deny,msg:'SQL Injection: Comment sequence'"

# Time-based blind injection
SecRule ARGS "@rx (?i)\b(benchmark|sleep|waitfor)\s*\(" \
    "id:942150,phase:2,deny,msg:'SQL Injection: Time-based'"

# Hex encoding
SecRule ARGS "@rx (?i)0x[0-9a-f]{4,}" \
    "id:942160,phase:2,deny,msg:'SQL Injection: Hex encoding'"

# Database enumeration
SecRule ARGS "@rx (?i)information_schema" \
    "id:942170,phase:2,deny,msg:'SQL Injection: DB enumeration'"
CRS);

$config->blocklists->addRule(new BlocklistRule('sqli', new CoreRuleSetMatcher($rules)));
```

::: tip
For a full overview of OWASP rule syntax and operators, see the [OWASP CRS](/features/owasp-crs) page.
:::

## Cross-Site Scripting (XSS)

Block XSS payloads in request parameters:

```php
$rules = SecRuleLoader::fromString(<<<'CRS'
# Script tags
SecRule ARGS "@rx (?i)<script[^>]*>" \
    "id:941100,phase:2,deny,msg:'XSS: Script tag'"

# Event handlers (onload, onerror, onclick, etc.)
SecRule ARGS "@rx (?i)\bon(load|error|click|mouseover|focus|blur|change|submit)\s*=" \
    "id:941110,phase:2,deny,msg:'XSS: Event handler'"

# JavaScript protocol
SecRule ARGS "@rx (?i)javascript\s*:" \
    "id:941120,phase:2,deny,msg:'XSS: JavaScript protocol'"

# Data URI with base64
SecRule ARGS "@rx (?i)data\s*:[^,]*;base64" \
    "id:941130,phase:2,deny,msg:'XSS: Data URI'"

# iframe injection
SecRule ARGS "@rx (?i)<iframe[^>]*>" \
    "id:941140,phase:2,deny,msg:'XSS: iframe injection'"

# Object/embed tags
SecRule ARGS "@rx (?i)<(object|embed|applet)[^>]*>" \
    "id:941150,phase:2,deny,msg:'XSS: Object/embed tag'"
CRS);

$config->blocklists->addRule(new BlocklistRule('xss', new CoreRuleSetMatcher($rules)));
```

## Remote Code Execution (RCE)

Block PHP code injection and obfuscation techniques:

```php
$rules = SecRuleLoader::fromString(<<<'CRS'
# PHP dangerous functions
SecRule ARGS "@rx (?i)(eval|exec|system|shell_exec|passthru|popen|proc_open)\s*\(" \
    "id:933100,phase:2,deny,msg:'RCE: PHP dangerous function'"

# PHP obfuscation functions
SecRule ARGS "@rx (?i)(base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(" \
    "id:933110,phase:2,deny,msg:'RCE: PHP obfuscation'"

# Backtick execution
SecRule ARGS "@rx `[^`]+`" \
    "id:933120,phase:2,deny,msg:'RCE: Backtick execution'"
CRS);

$config->blocklists->addRule(new BlocklistRule('rce', new CoreRuleSetMatcher($rules)));
```

## Path Traversal

Block directory traversal attempts in both the URI and request parameters:

```php
$rules = SecRuleLoader::fromString(<<<'CRS'
# Basic path traversal
SecRule REQUEST_URI "@rx \.\.[\\/]" \
    "id:930100,phase:2,deny,msg:'Path Traversal'"

# URL-encoded path traversal
SecRule REQUEST_URI "@rx (?i)(%2e%2e[%2f%5c]|%2e%2e[\\/])" \
    "id:930110,phase:2,deny,msg:'Encoded Path Traversal'"

# Path traversal in parameters
SecRule ARGS "@rx \.\.[\\/]" \
    "id:930120,phase:2,deny,msg:'Path Traversal in parameter'"
CRS);

$config->blocklists->addRule(new BlocklistRule('path-traversal', new CoreRuleSetMatcher($rules)));
```

Or use a simple blocklist closure:

```php
$config->blocklists->add('path-traversal', function ($req): bool {
    $input = urldecode($req->getUri()->getPath() . '?' . $req->getUri()->getQuery());
    return preg_match('~\.\.[\\\\/]~', $input) === 1;
});
```

## Scanner and Tool Detection

### Built-In Scanner Blocking

Block known attack tools (sqlmap, nikto, nuclei, etc.) with a single call:

```php
$config->blocklists->knownScanners();
```

The default list covers 24 tools (26 substring patterns). Extend or replace it:

```php
use Flowd\Phirewall\Matchers\KnownScannerMatcher;

// Add your own patterns alongside defaults
$config->blocklists->knownScanners('scanners', [
    ...KnownScannerMatcher::DEFAULT_PATTERNS,
    'my-internal-scanner',
]);

// Or use only your own list
$config->blocklists->knownScanners('custom-scanners', ['tool-a', 'tool-b']);
```

### Suspicious Headers

Block requests missing standard browser headers that real browsers always send:

```php
// Block requests missing Accept, Accept-Language, or Accept-Encoding
$config->blocklists->suspiciousHeaders();
```

Custom required headers (e.g., for API endpoints):

```php
$config->blocklists->suspiciousHeaders('api-headers', ['Authorization', 'X-API-Key']);
```

### Scanner Path Probing

Block requests to common vulnerability scanning targets:

```php
$config->blocklists->add('scanner-paths', function ($req): bool {
    $blockedPaths = [
        '/admin-panel', '/admin-login', '/phpmyadmin', '/phpinfo.php',
        '/.env', '/.git', '/.svn', '/.htaccess',
        '/server-status', '/server-info',
        '/actuator', '/debug', '/console',
    ];

    $path = strtolower($req->getUri()->getPath());
    foreach ($blockedPaths as $blockedPath) {
        if (str_starts_with($path, $blockedPath)) {
            return true;
        }
    }
    return false;
});
```

## DDoS and Rate Abuse

### Multi-Window Rate Limiting

Catch both bursts and sustained abuse with multiple time windows:

```php
// 3 req/s burst limit + 100 req/min sustained limit
$config->throttles->multi('api', [
    1  => 3,    // Burst protection
    60 => 100,  // Sustained limit
]);
```

### Sliding Window

Prevent the "double burst" problem at fixed-window boundaries:

```php
$config->throttles->sliding('api',
    limit: 100,
    period: 60,
);
```

### Tiered Rate Limiting

Apply different limits based on subscription tier:

```php
// Anonymous callers fall back to their client IP; resolve it through the
// trusted-proxy resolver instead of the raw REMOTE_ADDR peer address.
$proxy = new TrustedProxyResolver(['10.0.0.0/8', '172.16.0.0/12']);

$config->throttles->add('api',
    limit: fn(ServerRequestInterface $req): int => match ($req->getAttribute('plan')) {
        'enterprise' => 10000,
        'pro' => 1000,
        'free' => 100,
        default => 50,
    },
    period: 60,
    key: fn(ServerRequestInterface $req): ?string =>
        $req->getAttribute('userId') ?? $proxy->resolve($req),
);
```

::: tip Read tier and identity from request attributes, not headers
`plan` and `userId` are PSR-7 request **attributes** that your authentication layer sets after verifying the principal: `$request = $request->withAttribute('plan', $user->plan)`. Attributes are server-side only and never part of the incoming request, so a client cannot forge them the way it could an `X-Plan` header. Place the middleware that sets them before Phirewall in the pipeline.
:::

### Write Operation Limits

Apply stricter limits to mutating operations:

```php
use Flowd\Phirewall\Config\ClosureRequestMatcher;
use Flowd\Phirewall\Config\Rule\ThrottleRule;

// A null key defaults to the resolved client IP; the scope filter restricts the
// throttle to mutating methods.
$config->throttles->addRule(new ThrottleRule(
    'write-ops',
    limit: 50,
    period: 60,
    keyExtractor: null,
    scope: new ClosureRequestMatcher(
        fn(ServerRequestInterface $req): bool =>
            in_array($req->getMethod(), ['POST', 'PUT', 'PATCH', 'DELETE'], true)
    ),
));
```

### Allow2Ban for High-Volume Abuse

Ban IPs that exceed a request threshold, regardless of request type:

```php
$config->allow2ban->add('volume-ban',
    threshold: 500,
    period: 60,
    banSeconds: 3600,
);
```

## API Abuse

### API Endpoint Throttling

Rate-limit API traffic per client IP, the value a caller cannot forge (behind a proxy, configure proxy trust once with `$config->setIpResolver((new TrustedProxyResolver([...]))->resolve(...))` and rules key on the resolved client IP by default):

```php
$config->throttles->add('api',
    limit: 1000,
    period: 60,
);
```

::: warning Header keys are client-controlled
A throttle, fail2ban, or allow2ban rule keyed on a request header (`X-Api-Key`, `X-User-Id`, …) is only as trustworthy as that header. A client can rotate or drop the header to land in a fresh counter on every request and never reach the threshold (a trivial bypass). Key such rules on a value the client cannot freely change: the client IP (keyless rules key on the resolved client IP by default; set proxy trust with `$config->setIpResolver((new TrustedProxyResolver([...]))->resolve(...))`), the authenticated principal your auth layer sets *after* verifying it, or a composite of both. When you must key on a credential-bearing header, use `KeyExtractors::hashedHeader('X-Api-Key')`: the raw value otherwise reaches the ban registry and event payloads (and your logs) in cleartext.
:::

### Expensive Endpoint Protection

Apply stricter limits to resource-intensive endpoints:

```php
// Anonymous callers fall back to their client IP; resolve it through the
// trusted-proxy resolver instead of the raw REMOTE_ADDR peer address.
$proxy = new TrustedProxyResolver(['10.0.0.0/8', '172.16.0.0/12']);

$config->throttles->add('export',
    limit: 10,
    period: 3600,
    key: function (ServerRequestInterface $req) use ($proxy): ?string {
        if (str_starts_with($req->getUri()->getPath(), '/api/export')) {
            return $req->getAttribute('userId') ?? $proxy->resolve($req);
        }
        return null;
    },
);
```

### Track and Alert on Suspicious Patterns

Monitor request patterns without blocking, alerting when thresholds are exceeded:

```php
$config->tracks->add('sensitive-endpoints',
    period: 300,
    filter: fn($req): bool => str_starts_with($req->getUri()->getPath(), '/api/admin'),
    limit: 50,
);
```

When the count reaches 50, a `TrackHit` event is dispatched with `thresholdReached: true`. See [Track & Notifications](/advanced/track-notifications) for details.

## Production Setup

Combine all layers into a single production configuration:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\ClosureRequestMatcher;
use Flowd\Phirewall\Config\Rule\SafelistRule;
use Flowd\Phirewall\Config\Rule\ThrottleRule;
use Flowd\Phirewall\Http\TrustedProxyResolver;
use Flowd\Phirewall\Matchers\TrustedBotMatcher;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Config\Rule\BlocklistRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;
use Flowd\PhirewallPresetOwaspCrs\Engine\SecRuleLoader;
use Flowd\Phirewall\Store\RedisCache;
use Psr\Http\Message\ServerRequestInterface;
use Nyholm\Psr7\Factory\Psr17Factory;

$config = new Config(new RedisCache($redis));
$config->setKeyPrefix('prod');
$config->enableRateLimitHeaders();

// Trusted proxy for correct client IP resolution
$proxy = new TrustedProxyResolver(['10.0.0.0/8', '172.16.0.0/12']);
$config->setIpResolver($proxy->resolve(...));

// ── Layer 1: Safelists ─────────────────────────────────────────────────
$config->safelists->add('health',
    fn($req): bool => $req->getUri()->getPath() === '/health'
);
$config->safelists->addRule(new SafelistRule('trusted-bots', new TrustedBotMatcher(cache: new RedisCache($redis))));
$config->safelists->ip('office', ['203.0.113.0/24']);

// ── Layer 2: Blocklists ────────────────────────────────────────────────
$config->blocklists->knownScanners();
$config->blocklists->suspiciousHeaders();
$config->blocklists->add('scanner-paths', function ($req): bool {
    $path = strtolower($req->getUri()->getPath());
    foreach (['/admin-panel', '/.env', '/.git', '/phpmyadmin'] as $blocked) {
        if (str_starts_with($path, $blocked)) return true;
    }
    return false;
});

// ── Layer 3: OWASP Rules ──────────────────────────────────────────────
$rules = SecRuleLoader::fromString(<<<'CRS'
SecRule ARGS "@rx (?i)\bunion\b.*\bselect\b" "id:942100,phase:2,deny,msg:'SQLi'"
SecRule ARGS "@rx (?i)('\s*(or|and)\s*'|'\s*=\s*')" "id:942110,phase:2,deny,msg:'SQLi'"
SecRule ARGS "@rx (?i)<script[^>]*>" "id:941100,phase:2,deny,msg:'XSS'"
SecRule ARGS "@rx (?i)\bon(load|error|click)\s*=" "id:941110,phase:2,deny,msg:'XSS'"
SecRule ARGS "@rx (?i)(eval|exec|system|shell_exec)\s*\(" "id:933100,phase:2,deny,msg:'RCE'"
SecRule REQUEST_URI "@rx \.\.[\\/]" "id:930100,phase:2,deny,msg:'Path Traversal'"
CRS);
$config->blocklists->addRule(new BlocklistRule('owasp', new CoreRuleSetMatcher($rules)));

// ── Layer 4: Fail2Ban ─────────────────────────────────────────────────
// The filter never matches pre-handler; your login handler signals each
// verified failure with $context->recordFailure('login-brute-force').
// See Brute Force Login above.
$config->fail2ban->add('login-brute-force',
    threshold: 5, period: 300, ban: 3600,
    filter: fn($req): bool => false,
);

// ── Layer 5: Throttling ───────────────────────────────────────────────
$config->throttles->multi('api', [1 => 5, 60 => 200]);
// Null key defaults to the resolved client IP (the resolver set above);
// the scope filter restricts the throttle to the login path.
$config->throttles->addRule(new ThrottleRule(
    'login',
    limit: 10,
    period: 60,
    keyExtractor: null,
    scope: new ClosureRequestMatcher(fn($req): bool => $req->getUri()->getPath() === '/login'),
));

// ── Layer 6: Allow2Ban ────────────────────────────────────────────────
$config->allow2ban->add('volume-ban',
    threshold: 500, period: 60, banSeconds: 3600,
);

// ── PSR-17 Responses ──────────────────────────────────────────────────
$psr17 = new Psr17Factory();
$config->usePsr17Responses($psr17, $psr17);

$middleware = new Middleware($config, $psr17);
```

## Evaluation Order

Phirewall evaluates rules in this order. The first matching rule determines the outcome:

```text
Track → Safelist → Blocklist → Fail2Ban → Throttle → Allow2Ban → Pass
```

| Layer | Purpose | Response |
|-------|---------|----------|
| Track | Observe and count (never blocks) | - |
| Safelist | Bypass all remaining checks | 200 (pass-through) |
| Blocklist | IP lists, OWASP rules, patterns | 403 |
| Fail2Ban | Block every filter match; ban after repeated matches | 403 |
| Throttle | Rate limiting (fixed, sliding, multi) | 429 |
| Allow2Ban | Count (all or filtered), ban after threshold | 403 |
| Pass | No rule matched | 200 (pass-through) |

## Best Practices

1. **Layer your defenses.** No single rule catches everything. Combine blocklists, OWASP rules, fail2ban, and rate limiting.

2. **Safelist your health checks.** Internal monitoring endpoints should bypass all firewall rules to avoid false alerts.

3. **Configure proxy trust on the Config.** If your application runs behind a load balancer or CDN, set `$config->setIpResolver((new TrustedProxyResolver([...]))->resolve(...))` so rate limits and bans apply to the real client IP; keyless rules then key on the resolved client IP automatically. Avoid keying rules on the raw `REMOTE_ADDR` peer address directly - behind a proxy it collapses every client onto the proxy's address. If you need the raw peer for a specific purpose, read `$request->getServerParams()['REMOTE_ADDR']` directly. See [Client IP Behind Proxies](/getting-started#client-ip-behind-proxies).

4. **Start with logging, then enforce.** Use [Track rules](/advanced/track-notifications) to observe traffic patterns before enabling blocking rules.

5. **Tune for your application.** Every application has different traffic patterns. Monitor [diagnostics](/advanced/observability) and adjust thresholds based on real data.

6. **Ban repeat OWASP offenders correctly.** An OWASP blocklist match is blocked (`403`) before fail2ban runs, so a separate fail2ban rule never sees it. To also ban a persistent attacker, use the OWASP CRS fail2ban preset (a fail2ban rule whose filter is the CRS matcher itself, so it blocks each match and bans repeat offenders) or mirror blocklist hits to the edge with an [infrastructure adapter](/advanced/infrastructure).

7. **Keep rule IDs unique.** Follow the OWASP convention: `942xxx` for SQLi, `941xxx` for XSS, `933xxx` for RCE, `930xxx` for path traversal.
