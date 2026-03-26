---
outline: deep
---

# Common Attacks

Ready-to-use Phirewall configurations for defending against common web application attacks. Each recipe is self-contained -- copy what you need and adapt it to your application.

## Brute Force Login

Protect login endpoints with layered rate limiting and fail2ban.

### Fail2Ban on Login Failures

Ban IPs after repeated failed login attempts. The `filter` predicate determines what counts as a failure:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\RedisCache;
use Psr\Http\Message\ServerRequestInterface;

$config = new Config(new RedisCache($redis));

// Ban after 5 failed logins in 5 minutes for 1 hour
$config->fail2ban->add('login-brute-force',
    threshold: 5,
    period: 300,
    ban: 3600,
    filter: fn(ServerRequestInterface $req): bool =>
        $req->getMethod() === 'POST'
        && $req->getUri()->getPath() === '/login'
        && $req->getHeaderLine('X-Login-Failed') === '1',
    key: KeyExtractors::ip(),
);
```

Your login handler sets the `X-Login-Failed` header on failed attempts before the response is returned.

### Post-Handler Failure Signaling

For more precise control, use [RequestContext](/features/fail2ban#post-handler-signaling-with-requestcontext) to signal failures only after verifying credentials:

```php
use Flowd\Phirewall\Context\RequestContext;

$config->fail2ban->add('login-failures',
    threshold: 3, period: 300, ban: 3600,
    filter: fn($req): bool => false, // Never counts automatically
    key: KeyExtractors::ip(),
);

// In your login handler:
if (!$this->authenticate($username, $password)) {
    $context = $request->getAttribute(RequestContext::ATTRIBUTE_NAME);
    $ip = $request->getServerParams()['REMOTE_ADDR'] ?? 'unknown';
    $context?->recordFailure('login-failures', $ip);
}
```

### Login Endpoint Throttle

Add a rate limit specifically on the login path to slow down attackers:

```php
$config->throttles->add('login-throttle',
    limit: 10,
    period: 60,
    key: function (ServerRequestInterface $req): ?string {
        if ($req->getUri()->getPath() === '/login') {
            return $req->getServerParams()['REMOTE_ADDR'] ?? null;
        }
        return null; // Skip for other endpoints
    },
);
```

### Credential Stuffing (Per-Username)

Throttle per username to prevent attackers from testing many passwords against a single account:

```php
$config->throttles->add('account-throttle',
    limit: 5,
    period: 60,
    key: function (ServerRequestInterface $req): ?string {
        if ($req->getUri()->getPath() === '/login' && $req->getMethod() === 'POST') {
            $username = $req->getHeaderLine('X-Username');
            return $username !== '' ? $username : null;
        }
        return null;
    },
);
```

## SQL Injection

Block common SQL injection patterns using OWASP CRS rules.

```php
use Flowd\Phirewall\Owasp\SecRuleLoader;

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

$config->blocklists->owasp('sqli', $rules);
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

$config->blocklists->owasp('xss', $rules);
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

$config->blocklists->owasp('rce', $rules);
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

$config->blocklists->owasp('path-traversal', $rules);
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

The default list covers ~25 tools. Extend or replace it:

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
], KeyExtractors::ip());
```

### Sliding Window

Prevent the "double burst" problem at fixed-window boundaries:

```php
$config->throttles->sliding('api',
    limit: 100,
    period: 60,
    key: KeyExtractors::ip(),
);
```

### Tiered Rate Limiting

Apply different limits based on subscription tier:

```php
$config->throttles->add('api',
    limit: fn(ServerRequestInterface $req): int => match ($req->getHeaderLine('X-Plan')) {
        'enterprise' => 10000,
        'pro' => 1000,
        'free' => 100,
        default => 50,
    },
    period: 60,
    key: fn($req): ?string =>
        $req->getHeaderLine('X-User-Id') ?: $req->getServerParams()['REMOTE_ADDR'] ?? null,
);
```

### Write Operation Limits

Apply stricter limits to mutating operations:

```php
$config->throttles->add('write-ops',
    limit: 50, period: 60,
    key: function (ServerRequestInterface $req): ?string {
        if (in_array($req->getMethod(), ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            return $req->getServerParams()['REMOTE_ADDR'] ?? null;
        }
        return null;
    },
);
```

### Allow2Ban for High-Volume Abuse

Ban IPs that exceed a request threshold, regardless of request type:

```php
$config->allow2ban->add('volume-ban',
    threshold: 500,
    period: 60,
    banSeconds: 3600,
    key: KeyExtractors::ip(),
);
```

## API Abuse

### API Key Throttling

Rate-limit by API key for authenticated endpoints:

```php
$config->throttles->add('api-key',
    limit: 1000,
    period: 60,
    key: KeyExtractors::header('X-Api-Key'),
);
```

### Expensive Endpoint Protection

Apply stricter limits to resource-intensive endpoints:

```php
$config->throttles->add('export',
    limit: 10,
    period: 3600,
    key: function (ServerRequestInterface $req): ?string {
        if (str_starts_with($req->getUri()->getPath(), '/api/export')) {
            return $req->getHeaderLine('X-User-Id')
                ?: $req->getServerParams()['REMOTE_ADDR'] ?? null;
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
    key: KeyExtractors::ip(),
    limit: 50,
);
```

When the count reaches 50, a `TrackHit` event is dispatched with `thresholdReached: true`. See [Track & Notifications](/advanced/track-notifications) for details.

## Comprehensive Production Setup

Combine all layers into a production-ready configuration:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\TrustedProxyResolver;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Owasp\SecRuleLoader;
use Flowd\Phirewall\Store\RedisCache;
use Psr\Http\Message\ServerRequestInterface;
use Nyholm\Psr7\Factory\Psr17Factory;

$config = new Config(new RedisCache($redis));
$config->setKeyPrefix('prod');
$config->enableRateLimitHeaders();

// Trusted proxy for correct client IP resolution
$proxy = new TrustedProxyResolver(['10.0.0.0/8', '172.16.0.0/12']);
$config->setIpResolver(KeyExtractors::clientIp($proxy));

// ── Layer 1: Safelists ─────────────────────────────────────────────────
$config->safelists->add('health',
    fn($req): bool => $req->getUri()->getPath() === '/health'
);
$config->safelists->trustedBots(cache: new RedisCache($redis));
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
$config->blocklists->owasp('owasp', $rules);

// ── Layer 4: Fail2Ban ─────────────────────────────────────────────────
$config->fail2ban->add('login-brute-force',
    threshold: 5, period: 300, ban: 3600,
    filter: fn($req): bool => $req->getHeaderLine('X-Login-Failed') === '1',
    key: KeyExtractors::ip(),
);

// ── Layer 5: Throttling ───────────────────────────────────────────────
$config->throttles->multi('api', [1 => 5, 60 => 200], KeyExtractors::ip());
$config->throttles->add('login', limit: 10, period: 60, key: function ($req): ?string {
    return $req->getUri()->getPath() === '/login'
        ? ($req->getServerParams()['REMOTE_ADDR'] ?? null)
        : null;
});

// ── Layer 6: Allow2Ban ────────────────────────────────────────────────
$config->allow2ban->add('volume-ban',
    threshold: 500, period: 60, banSeconds: 3600,
    key: KeyExtractors::ip(),
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
| Track | Observe and count (never blocks) | -- |
| Safelist | Bypass all remaining checks | 200 (pass-through) |
| Blocklist | IP lists, OWASP rules, patterns | 403 |
| Fail2Ban | Ban after repeated filtered failures | 403 |
| Throttle | Rate limiting (fixed, sliding, multi) | 429 |
| Allow2Ban | Ban after exceeding request threshold | 403 |
| Pass | No rule matched | 200 (pass-through) |

## Best Practices

1. **Layer your defenses.** No single rule catches everything. Combine blocklists, OWASP rules, fail2ban, and rate limiting.

2. **Safelist your health checks.** Internal monitoring endpoints should bypass all firewall rules to avoid false alerts.

3. **Use `clientIp()` behind proxies.** If your application runs behind a load balancer or CDN, configure a `TrustedProxyResolver` so rate limits and bans apply to the real client IP.

4. **Start with logging, then enforce.** Use [Track rules](/advanced/track-notifications) to observe traffic patterns before enabling blocking rules.

5. **Tune for your application.** Every application has different traffic patterns. Monitor [diagnostics](/advanced/observability) and adjust thresholds based on real data.

6. **Combine OWASP with fail2ban.** Use OWASP rules to detect attack payloads, and fail2ban to ban repeat offenders who trigger multiple rules.

7. **Keep rule IDs unique.** Follow the OWASP convention: `942xxx` for SQLi, `941xxx` for XSS, `933xxx` for RCE, `930xxx` for path traversal.
