---
outline: deep
---

# Safelists & Blocklists

Safelists and blocklists are the first line of defense. They run before rate limiting and Fail2Ban, making them the fastest way to allow or deny traffic.

## How They Work

```text
Request --> Safelist check --> Blocklist check --> (Fail2Ban, Throttle, ...)
                |                    |
                v                    v
           Bypass all            403 Forbidden
           other rules
```

Safelists are evaluated first. If a safelist matches, the request is immediately allowed and no other rules are checked. Blocklists are evaluated next. If a blocklist matches, the request is immediately denied with a `403 Forbidden` response.

## Safelists

### Closure-Based Rules

Use `$config->safelists->add()` to define rules that allow trusted traffic to bypass all other checks.

```php
$config->safelists->add(string $name, Closure $callback): SafelistSection
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$name` | `string` | Unique rule identifier |
| `$callback` | `Closure` | `fn(ServerRequestInterface): bool` -- return `true` to safelist |

```php
// Health check endpoint
$config->safelists->add('health',
    fn($req) => $req->getUri()->getPath() === '/health'
);

// Internal monitoring
$config->safelists->add('metrics',
    fn($req) => $req->getUri()->getPath() === '/metrics'
);

// Multiple paths
$config->safelists->add('public-assets', function ($req): bool {
    $path = $req->getUri()->getPath();
    return str_starts_with($path, '/css/')
        || str_starts_with($path, '/js/')
        || str_starts_with($path, '/images/');
});
```

### IP / CIDR Safelisting

Use the convenience method `$config->safelists->ip()` to safelist requests from specific IP addresses or CIDR ranges. This handles IPv4, IPv6, and CIDR notation without writing a closure.

```php
$config->safelists->ip(
    string $name,
    string|array $ipOrCidr,
    ?callable $ipResolver = null
): SafelistSection
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$name` | `string` | Unique rule identifier |
| `$ipOrCidr` | `string\|list<string>` | Single IP/CIDR or array of IPs/CIDRs |
| `$ipResolver` | `?callable` | Override the [global IP resolver](#ip-resolution) for this rule |

```php
// Single IP
$config->safelists->ip('office', '203.0.113.10');

// Multiple IPs
$config->safelists->ip('office-ips', ['203.0.113.10', '203.0.113.11']);

// CIDR ranges
$config->safelists->ip('internal', '10.0.0.0/8');

// Mixed IPs and CIDRs
$config->safelists->ip('trusted', [
    '10.0.0.0/8',        // Internal network
    '172.16.0.0/12',     // Docker
    '192.168.0.0/16',    // Private ranges
    '203.0.113.50',      // Partner server
]);

// IPv6 support
$config->safelists->ip('ipv6-loopback', '::1');
```

### Trusted Bot Verification

Safelist verified search engine bots via reverse DNS verification. See [Bot Detection](/features/bot-detection) for full details.

```php
$config->safelists->trustedBots(
    string $name = 'trusted-bots',
    array $additionalBots = [],
    ?callable $ipResolver = null,
    ?CacheInterface $cache = null
): SafelistSection
```

```php
// Safelist Google, Bing, Baidu, DuckDuckGo, Yandex, and Apple bots
$config->safelists->trustedBots();

// Add custom bots on top of the built-in list
$config->safelists->trustedBots('bots', [
    ['ua' => 'mypartnerbot', 'hostname' => '.partner.example.com'],
]);
```

::: warning
Without a PSR-16 cache, each request with a bot-like User-Agent triggers blocking DNS lookups. In production, always provide a cache:

```php
$config->safelists->trustedBots(cache: $cache);
```
:::

### Custom Safelist Rules

For full control, use `addRule()` with a `SafelistRule` object directly:

```php
use Flowd\Phirewall\Config\Rule\SafelistRule;

$config->safelists->addRule(new SafelistRule($name, $requestMatcher));
```

::: tip
When a safelist matches, Phirewall dispatches a `SafelistMatched` event. If `$config->enableResponseHeaders()` is active, an `X-Phirewall-Safelist` response header with the rule name is also added. This is useful for debugging.
:::

## Blocklists

### Closure-Based Rules

Use `$config->blocklists->add()` to define rules that reject malicious requests.

```php
$config->blocklists->add(string $name, Closure $callback): BlocklistSection
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$name` | `string` | Unique rule identifier |
| `$callback` | `Closure` | `fn(ServerRequestInterface): bool` -- return `true` to block |

```php
// Block admin panel probes
$config->blocklists->add('scanner-probe',
    fn($req) => str_starts_with($req->getUri()->getPath(), '/admin-panel')
);

// Block phpMyAdmin probes
$config->blocklists->add('pma-probe',
    fn($req) => str_contains($req->getUri()->getPath(), 'phpmyadmin')
);

// Block path traversal attempts
$config->blocklists->add('path-traversal', function ($req): bool {
    $input = urldecode($req->getUri()->getPath() . '?' . $req->getUri()->getQuery());
    return preg_match('~\.\.[\\\\/]~', $input) === 1;
});
```

### IP / CIDR Blocklisting

Block requests from specific IP addresses or CIDR ranges with the `ip()` convenience method.

```php
$config->blocklists->ip(
    string $name,
    string|array $ipOrCidr,
    ?callable $ipResolver = null
): BlocklistSection
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$name` | `string` | Unique rule identifier |
| `$ipOrCidr` | `string\|list<string>` | Single IP/CIDR or array of IPs/CIDRs |
| `$ipResolver` | `?callable` | Override the [global IP resolver](#ip-resolution) for this rule |

```php
// Block a single IP
$config->blocklists->ip('attacker', '1.2.3.4');

// Block multiple IPs
$config->blocklists->ip('bad-actors', ['1.2.3.4', '5.6.7.8']);

// Block CIDR ranges
$config->blocklists->ip('tor-exits', [
    '185.220.100.0/24',
    '185.220.101.0/24',
]);

// Block IPv6
$config->blocklists->ip('ipv6-block', '2001:db8::/32');
```

### Known Scanner Detection

Block requests from known vulnerability scanners, attack tools, and exploit frameworks by matching User-Agent strings.

```php
$config->blocklists->knownScanners(
    string $name = 'known-scanners',
    ?array $patterns = null
): BlocklistSection
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$name` | `string` | Rule identifier (default: `'known-scanners'`) |
| `$patterns` | `?list<string>` | UA substrings to block. `null` uses the built-in list |

The built-in list covers: sqlmap, nikto, nmap, masscan, zmeu, havij, acunetix, nessus, openvas, w3af, dirbuster, gobuster, wfuzz, hydra, medusa, burpsuite, skipfish, whatweb, metasploit, nuclei, ffuf, feroxbuster, joomscan, and wpscan.

```php
// Use defaults -- blocks 24+ known attack tools
$config->blocklists->knownScanners();

// Add custom patterns on top of defaults
use Flowd\Phirewall\Matchers\KnownScannerMatcher;

$config->blocklists->knownScanners('scanners', [
    ...KnownScannerMatcher::DEFAULT_PATTERNS,
    'my-internal-scanner',
    'custom-tool',
]);

// Use only your own list (replaces defaults entirely)
$config->blocklists->knownScanners('custom-only', ['my-scanner', 'other-tool']);
```

### Suspicious Headers Detection

Block requests missing standard HTTP headers that real browsers typically send. Many attack tools and scrapers omit headers like `Accept`, `Accept-Language`, or `Accept-Encoding`.

```php
$config->blocklists->suspiciousHeaders(
    string $name = 'suspicious-headers',
    array $requiredHeaders = []
): BlocklistSection
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$name` | `string` | Rule identifier (default: `'suspicious-headers'`) |
| `$requiredHeaders` | `list<string>` | Headers that must be present. Empty uses defaults |

Default required headers: `Accept`, `Accept-Language`, `Accept-Encoding`.

```php
// Use defaults
$config->blocklists->suspiciousHeaders();

// Custom required headers
$config->blocklists->suspiciousHeaders('headers', [
    'Accept',
    'Accept-Language',
    'Accept-Encoding',
    'User-Agent',
]);
```

::: warning
Some legitimate clients (API tools, embedded browsers, privacy extensions) may omit these headers. Use this rule with care and consider safelisting known API clients.
:::

### File-Backed IP Blocklist

For simple IP-only blocklists managed via a file, use `fileIp()`. This returns a `FileIpBlocklistStore` that you can use to add and remove IPs programmatically.

```php
$config->blocklists->fileIp(
    string $name,
    string $filePath,
    ?callable $ipResolver = null
): FileIpBlocklistStore
```

The file is reloaded automatically when its modification time changes, so external tools can update it without restarting your application.

```php
$store = $config->blocklists->fileIp('banned-ips', '/var/lib/phirewall/banned.txt');

// Add IPs programmatically
$store->add('1.2.3.4');

// Add multiple IPs at once
$store->addAll(['5.6.7.8', '9.10.11.12']);

// Add with TTL (auto-expires)
$store->addWithTtl('203.0.113.50', 3600);       // Expires in 1 hour
$store->addAllWithTtl(['1.2.3.4'], 86400);       // Expires in 24 hours

// Clean up expired entries (run via cron)
$store->pruneExpired();
```

The file format is one entry per line, with optional expiry and timestamp fields separated by `|`:

```text
1.2.3.4
5.6.7.8|1711929600
10.0.0.0/8||1711843200
203.0.113.50|1711929600|1711843200
```

### OWASP Core Rule Set

Register OWASP CRS rules as a blocklist to detect SQL injection, XSS, and other attacks:

```php
use Flowd\Phirewall\Owasp\SecRuleLoader;

$rules = SecRuleLoader::fromString(<<<'CRS'
SecRule ARGS "@rx (?i)\bunion\b.*\bselect\b" "id:942100,phase:2,deny,msg:'SQLi'"
SecRule ARGS "@rx (?i)<script[^>]*>" "id:941100,phase:2,deny,msg:'XSS'"
CRS);

$config->blocklists->owasp('owasp', $rules);
```

See [OWASP CRS](/features/owasp-crs) for full details on loading rules from files and directories.

## Pattern Backends

For dynamic, data-driven blocklists, use pattern backends instead of hardcoded closures. Pattern backends support IP addresses, CIDR ranges, path patterns, header patterns, and regex matching -- all with optional expiration.

### In-Memory Pattern Blocklist

The one-step `patternBlocklist()` method creates a backend and registers it as a blocklist rule in a single call.

```php
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;

$backend = $config->blocklists->patternBlocklist('blocked-ranges', [
    new PatternEntry(PatternKind::CIDR, '10.0.0.0/8'),
    new PatternEntry(PatternKind::CIDR, '172.16.0.0/12'),
    new PatternEntry(PatternKind::IP, '203.0.113.50'),
    new PatternEntry(
        kind: PatternKind::HEADER_REGEX,
        value: '/sqlmap|nikto|nmap/i',
        target: 'User-Agent',
    ),
]);

// Add more entries later
$backend->append(new PatternEntry(PatternKind::IP, '203.0.113.51'));
```

### File-Backed Pattern Blocklist

Persist patterns to a file so they survive restarts and can be shared across processes.

```php
$backend = $config->blocklists->filePatternBlocklist('dynamic-blocks',
    '/var/lib/phirewall/blocks.txt'
);

// Add entries (persisted to file with flock for safe concurrency)
$backend->append(new PatternEntry(
    kind: PatternKind::IP,
    value: '203.0.113.100',
    expiresAt: time() + 3600,  // Auto-expires after 1 hour
));
```

### Two-Step Registration

When you need to share a backend between multiple rules or keep a reference for later modification, use the two-step approach:

```php
// Step 1: Register the backend
$backend = $config->blocklists->inMemoryPatternBackend('scanners', [
    new PatternEntry(
        kind: PatternKind::HEADER_REGEX,
        value: '/sqlmap|nikto|nmap|masscan|burp|dirbuster/i',
        target: 'User-Agent',
    ),
]);

// Step 2: Create a blocklist rule that reads from it
$config->blocklists->fromBackend('block-scanners', 'scanners');
```

### Available Pattern Kinds

| Kind | Description | Example Value |
|------|-------------|---------------|
| `PatternKind::IP` | Exact IP match | `192.168.1.100` |
| `PatternKind::CIDR` | CIDR range match (IPv4/IPv6) | `10.0.0.0/8` |
| `PatternKind::PATH_EXACT` | Exact path match | `/admin` |
| `PatternKind::PATH_PREFIX` | Path prefix match | `/api/` |
| `PatternKind::PATH_REGEX` | Path regex match | `/^\/user\/\d+$/` |
| `PatternKind::HEADER_EXACT` | Exact header value (requires `target`) | `BadBot/1.0` |
| `PatternKind::HEADER_REGEX` | Header value regex (requires `target`) | `/bot\|crawler/i` |
| `PatternKind::REQUEST_REGEX` | Full request (path + query + headers) regex | `/sql.*injection/i` |

::: tip
Prefer `PATH_PREFIX` over `PATH_REGEX` when possible. Prefix matching is significantly faster than regex evaluation.
:::

### Pattern Entry Constructor

```php
new PatternEntry(
    kind: PatternKind::CIDR,           // Pattern type (required)
    value: '10.0.0.0/8',               // Pattern value (required)
    target: null,                       // Target field (for header_exact / header_regex)
    expiresAt: time() + 3600,          // Unix timestamp or null (permanent)
    addedAt: time(),                   // When added (auto-set if null)
    metadata: ['reason' => 'Abuse'],   // Optional metadata for diagnostics
);
```

### Temporary Blocks with Expiration

```php
$backend = $config->blocklists->filePatternBlocklist('temp-blocks',
    '/var/lib/phirewall/temp.txt'
);

// Block for 1 hour
$backend->append(new PatternEntry(
    kind: PatternKind::IP,
    value: '203.0.113.100',
    expiresAt: time() + 3600,
    metadata: ['reason' => 'Rate limit abuse'],
));

// Block an entire range for 24 hours
$backend->append(new PatternEntry(
    kind: PatternKind::CIDR,
    value: '198.51.100.0/24',
    expiresAt: time() + 86400,
    metadata: ['reason' => 'DDoS source'],
));

// Clean up expired entries periodically (e.g., via cron)
$backend->pruneExpired();
```

### Loading from External Threat Feeds

```php
$threatIps = file('https://example.com/threat-ips.txt', FILE_IGNORE_NEW_LINES);
$entries = array_map(
    fn($ip) => new PatternEntry(PatternKind::IP, trim($ip)),
    array_filter($threatIps)
);

$config->blocklists->patternBlocklist('threat-intel', $entries);
```

## IP Resolution {#ip-resolution}

Both `safelists->ip()` and `blocklists->ip()` respect the global IP resolver set on the Config object. This is important when your application runs behind a reverse proxy or load balancer.

```php
use Flowd\Phirewall\Http\TrustedProxyResolver;
use Flowd\Phirewall\KeyExtractors;

// Set a global IP resolver for all IP-aware matchers
$proxy = new TrustedProxyResolver(['10.0.0.0/8']);
$config->setIpResolver(KeyExtractors::clientIp($proxy));

// Now all ip() calls use the real client IP, not the proxy IP
$config->safelists->ip('office', '203.0.113.10');
$config->blocklists->ip('attacker', '1.2.3.4');
```

You can also override the resolver per rule:

```php
$customResolver = fn($req) => $req->getHeaderLine('CF-Connecting-IP') ?: null;

$config->safelists->ip('cloudflare-office', '203.0.113.10', ipResolver: $customResolver);
```

::: warning
Never trust `X-Forwarded-For` without configuring trusted proxies. An attacker can spoof this header to bypass IP-based rules.
:::

## Evaluation Order

The complete evaluation order within Phirewall is:

| Order | Layer | Action on Match |
|-------|-------|-----------------|
| 1 | Track | Count (passive, never blocks) |
| 2 | **Safelist** | **Allow** -- bypass all remaining checks |
| 3 | **Blocklist** | **Block** -- 403 Forbidden |
| 4 | Fail2Ban | Block -- 403 Forbidden |
| 5 | Throttle | Block -- 429 Too Many Requests |
| 6 | Pass | Request reaches your application |

::: warning
Rules within each layer are evaluated in the order they were added. Place more specific rules before general ones if ordering matters.
:::

## Custom Response Bodies

Customize the 403 response returned for blocked requests:

```php
use Flowd\Phirewall\Config\Response\ClosureBlocklistedResponseFactory;
use Nyholm\Psr7\Response;

$config->blocklistedResponseFactory = new ClosureBlocklistedResponseFactory(
    function (string $rule, string $type, $req) {
        return new Response(
            403,
            ['Content-Type' => 'application/json'],
            json_encode(['error' => 'Forbidden', 'rule' => $rule])
        );
    }
);
```

See [PSR-17 Factories](/advanced/psr17) for full details on response customization.

## Choosing Between Approaches

| Feature | `add()` (closure) | `ip()` / `knownScanners()` | Pattern Backend |
|---------|--------------------|-----------------------------|-----------------|
| Setup | Custom logic | One-liner | Structured entries |
| Storage | None (code only) | None (code only) | File or memory |
| Dynamic entries | No | No | Yes |
| Expiration | No | No | Yes |
| External updates | No | No | Yes (file backend) |
| Pattern types | Any (custom code) | IP/CIDR or UA | All predefined kinds |
| Best for | Complex matching | Quick IP/scanner rules | Dynamic, data-driven blocklists |

## Best Practices

1. **Safelist before you blocklist.** Always safelist health checks, monitoring endpoints, and internal IPs first to ensure essential traffic is never accidentally blocked.

2. **Use `ip()` for static IP rules.** The convenience methods are faster and less error-prone than writing closures that parse `REMOTE_ADDR` manually. They also respect the global IP resolver.

3. **Enable `knownScanners()` in production.** It is lightweight (substring matching on User-Agent) and blocks the most common automated attack tools.

4. **Use pattern backends for dynamic lists.** If entries change at runtime, use `patternBlocklist()` or `filePatternBlocklist()` rather than closures with hardcoded arrays.

5. **Set expiration on temporary blocks.** Always set `expiresAt` when blocking IPs temporarily, and run `pruneExpired()` periodically to clean up.

6. **Keep closures fast.** Blocklist callbacks run on every request. Avoid I/O, database queries, or expensive operations inside them.

7. **Name rules descriptively.** Rule names appear in response headers, events, and diagnostics. Use names like `scanner-probe` or `scanner-ua` rather than generic identifiers.
