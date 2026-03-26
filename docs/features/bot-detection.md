---
outline: deep
---

# Bot Detection

Phirewall provides three specialized matchers for bot and scanner detection: **Known Scanner Blocking**, **Suspicious Headers Detection**, and **Trusted Bot Verification**. Each is available as a one-liner convenience method on the blocklist or safelist section.

## Known Scanner Blocking

The `knownScanners()` method blocks requests whose User-Agent matches known attack tools and vulnerability scanners. It ships with a curated default list covering 25+ well-known tools.

### Quick Setup

```php
// Block all known scanners with default patterns
$config->blocklists->knownScanners();
```

That single line blocks User-Agents containing patterns like `sqlmap`, `nikto`, `nuclei`, `burpsuite`, `metasploit`, and more.

### Configuration

```php
$config->blocklists->knownScanners(
    string $name = 'known-scanners',
    ?array $patterns = null
): BlocklistSection
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$name` | `string` | Unique rule identifier (default: `'known-scanners'`) |
| `$patterns` | `list<string>\|null` | UA substrings to block (case-insensitive). `null` uses defaults. |

### Default Patterns

The built-in `KnownScannerMatcher::DEFAULT_PATTERNS` list includes:

| Category | Tools |
|----------|-------|
| **SQL Injection** | `sqlmap`, `havij` |
| **Web Scanners** | `nikto`, `acunetix`, `nessus`, `openvas`, `w3af`, `skipfish`, `whatweb`, `nuclei` |
| **Directory Bruteforcers** | `dirbuster`, `gobuster`, `ffuf`, `feroxbuster`, `wfuzz` |
| **Network Scanners** | `nmap`, `masscan` |
| **Credential Attackers** | `hydra`, `medusa` |
| **CMS Scanners** | `wpscan`, `joomscan` |
| **Exploit Frameworks** | `metasploit`, `msfconsole`, `burpsuite`, `burp suite` |
| **General** | `zmeu` |

### Extending the Default List

Add your own patterns on top of the defaults by merging with `DEFAULT_PATTERNS`:

```php
use Flowd\Phirewall\Matchers\KnownScannerMatcher;

$config->blocklists->knownScanners('scanners', [
    ...KnownScannerMatcher::DEFAULT_PATTERNS,
    'my-internal-scanner',
    'custom-tool',
]);
```

### Using Only Custom Patterns

Replace the defaults entirely with your own list:

```php
$config->blocklists->knownScanners('custom-scanners', [
    'my-tool',
    'other-tool',
]);
```

::: warning
When you pass a custom list, the defaults are **replaced**, not merged. If you want to keep the defaults, explicitly spread `KnownScannerMatcher::DEFAULT_PATTERNS` into your array.
:::

### What It Catches

Known scanners are blocked immediately at the blocklist layer with a `403 Forbidden` response. The matching is case-insensitive substring matching against the `User-Agent` header.

```text
sqlmap/1.7.8#stable       --> BLOCKED (matches 'sqlmap')
Mozilla/5.0 Nikto/2.1.6   --> BLOCKED (matches 'nikto')
nuclei/3.0.0 (scan)       --> BLOCKED (matches 'nuclei')
Mozilla/5.0 Chrome/120.0  --> allowed (no match)
curl/7.85.0               --> allowed (no match)
```

::: tip
`curl` is intentionally **not** in the default list. While it is commonly used for scripting, it is also a legitimate tool used by developers, monitoring systems, and API clients. If you want to block it, add it to a custom pattern list.
:::

## Suspicious Headers Detection

The `suspiciousHeaders()` method blocks requests that are missing standard HTTP headers real browsers always send. Attack tools and scrapers often omit headers like `Accept`, `Accept-Language`, and `Accept-Encoding`.

### Quick Setup

```php
// Block requests missing standard browser headers
$config->blocklists->suspiciousHeaders();
```

### Configuration

```php
$config->blocklists->suspiciousHeaders(
    string $name = 'suspicious-headers',
    array $requiredHeaders = []
): BlocklistSection
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$name` | `string` | Unique rule identifier (default: `'suspicious-headers'`) |
| `$requiredHeaders` | `list<string>` | Headers that must be present. Empty array uses defaults. |

### Default Required Headers

When no custom headers are specified, the following are required:

- `Accept` -- specifies acceptable response content types
- `Accept-Language` -- specifies acceptable languages
- `Accept-Encoding` -- specifies acceptable compression

Every modern browser sends all three. Their absence strongly suggests an automated tool.

### Custom Required Headers

Require different headers for specific use cases, such as API endpoints:

```php
// Require API authentication headers
$config->blocklists->suspiciousHeaders('api-headers', [
    'Authorization',
    'X-API-Key',
]);
```

### How It Works

The matcher checks each required header in order. If **any** required header is missing (empty string), the request is blocked:

```text
Browser (Accept + Accept-Language + Accept-Encoding) --> allowed
Scraper (Accept + Accept-Encoding, no Accept-Language) --> BLOCKED
Bot (no browser headers at all) --> BLOCKED
```

::: warning
Some legitimate clients may not send all standard headers: API clients, embedded browsers, privacy-focused tools, health-check probes, and webhooks from third-party services. Place this rule **after** safelists to ensure those clients can still pass through. Consider using `$config->safelists` to safelist known API paths or internal IPs before applying this check.
:::

## Trusted Bot Verification (rDNS)

The `trustedBots()` method safelists verified search engine bots using **reverse DNS (rDNS) verification**. This prevents fake bots -- anyone can send `Googlebot` as a User-Agent, but only Google's real crawlers have IPs that resolve to `*.googlebot.com`.

### Quick Setup

```php
// Safelist verified search engine bots
$config->safelists->trustedBots(cache: $cache);
```

### Configuration

```php
$config->safelists->trustedBots(
    string $name = 'trusted-bots',
    array $additionalBots = [],
    ?callable $ipResolver = null,
    ?CacheInterface $cache = null
): SafelistSection
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$name` | `string` | Unique rule identifier (default: `'trusted-bots'`) |
| `$additionalBots` | `list<array{ua: string, hostname: string}>` | Extra bots to recognize |
| `$ipResolver` | `callable\|null` | Custom IP resolver. Defaults to config's global IP resolver. |
| `$cache` | `CacheInterface\|null` | PSR-16 cache for DNS results (highly recommended) |

### Verification Flow

The rDNS verification follows a strict four-step process:

```text
1. User-Agent matches a known bot pattern?
   |-- No  --> skip (not a bot)
   |-- Yes --> continue

2. Reverse DNS: resolve IP -> hostname
   |-- e.g., 66.249.66.1 -> crawl-66-249-66-1.googlebot.com

3. Hostname ends with expected suffix?
   |-- e.g., .googlebot.com
   |-- No  --> skip (fake bot)
   |-- Yes --> continue

4. Forward-confirm: hostname -> IPs, check IP matches
   |-- crawl-66-249-66-1.googlebot.com -> 66.249.66.1 ✓
```

Both IPv4 and IPv6 are supported. Forward confirmation uses both `gethostbynamel()` (A records) and `dns_get_record()` (AAAA records).

### Built-In Verified Bots

| Bot | UA Pattern | Hostname Suffix |
|-----|-----------|-----------------|
| Googlebot | `googlebot` | `.googlebot.com` |
| Google Inspection Tool | `google-inspectiontool` | `.googlebot.com` |
| Bingbot | `bingbot` | `.search.msn.com` |
| MSNBot | `msnbot` | `.search.msn.com` |
| Baiduspider | `baiduspider` | `.baidu.com` |
| DuckDuckBot | `duckduckbot` | `.duckduckgo.com` |
| Yandexbot | `yandexbot` | `.yandex.com` |
| Yandex (alternate) | `yandex.com/bots` | `.yandex.com` |
| Slurp (Yahoo) | `slurp` | `.yahoo.net` |
| Applebot | `applebot` | `.applebot.apple.com` |

### Adding Custom Bots

Add your organization's internal crawlers:

```php
$config->safelists->trustedBots('custom-bots', [
    ['ua' => 'mycompany-crawler', 'hostname' => '.crawler.mycompany.com'],
    ['ua' => 'internal-monitor', 'hostname' => '.monitoring.mycompany.com'],
], cache: $cache);
```

::: danger
The hostname suffix **must** start with a dot (e.g., `.googlebot.com`, not `googlebot.com`). This prevents subdomain spoofing -- without the leading dot, an attacker controlling `evil-googlebot.com` could pass verification.
:::

### Caching DNS Results

DNS lookups are blocking I/O operations. **Always provide a PSR-16 cache in production** to avoid latency:

```php
$config->safelists->trustedBots(cache: $cache);
```

| Cache Behavior | TTL |
|----------------|-----|
| Positive results (verified bot) | 86,400 seconds (24 hours) |
| Negative results (failed verification) | 300 seconds (5 minutes) |

Negative results use a shorter TTL so transient DNS failures recover quickly without permanently blocking a real bot.

::: warning
Without a cache, **every request** with a bot-like User-Agent triggers blocking DNS lookups (`gethostbyaddr` + `gethostbynamel`/`dns_get_record`). This will significantly increase latency. Always pass a cache in production.
:::

## Scanner Path Blocking

Block requests to paths that legitimate users would never visit. These are honeypot-like indicators of scanning activity:

```php
$config->blocklists->add('scanner-paths', function ($req): bool {
    $path = strtolower($req->getUri()->getPath());

    $scannerPaths = [
        // Common admin panels
        '/admin-panel', '/admin-login', '/xmlrpc.php',
        // Database tools
        '/phpmyadmin', '/pma', '/mysqladmin',
        // Sensitive files
        '/.env', '/.git', '/.svn', '/.htaccess',
        // Debug endpoints
        '/phpinfo.php', '/info.php', '/test.php',
        // Shell uploads
        '/shell.php', '/c99.php', '/r57.php',
    ];

    foreach ($scannerPaths as $scannerPath) {
        if (str_starts_with($path, $scannerPath)) {
            return true;
        }
    }

    // Block backup file extensions
    return (bool) preg_match('/\.(bak|backup|old|orig|save|swp|~)$/i', $path);
});
```

::: tip
For more comprehensive attack pattern detection beyond path matching, consider using the [OWASP Core Rule Set](/features/owasp-crs) integration which detects SQL injection, XSS, and other attacks in request payloads.
:::

## Combining All Three

Use all three matchers together for comprehensive bot management:

```php
use Flowd\Phirewall\KeyExtractors;

// 1. Safelist verified search engine bots (they bypass all other rules)
$config->safelists->trustedBots(cache: $cache);

// 2. Block known attack tools
$config->blocklists->knownScanners();

// 3. Block requests missing standard browser headers
$config->blocklists->suspiciousHeaders();

// 4. Block scanner path probes
$config->blocklists->add('scanner-paths', function ($req): bool {
    $path = strtolower($req->getUri()->getPath());
    foreach (['/.env', '/.git', '/admin-panel', '/phpmyadmin'] as $probe) {
        if (str_starts_with($path, $probe)) {
            return true;
        }
    }
    return false;
});

// 5. Ban persistent scanners that keep trying
$config->fail2ban->add('persistent-scanner',
    threshold: 5, period: 60, ban: 86400,
    filter: fn($req) => true,
    key: KeyExtractors::ip()
);

// 6. Rate limit everything else
$config->throttles->add('global',
    limit: 60, period: 60,
    key: KeyExtractors::ip()
);
```

This layered approach ensures:
- **Real search engine bots** pass through immediately (verified via rDNS)
- **Known attack tools** are blocked at the blocklist layer
- **Primitive scrapers** missing browser headers are blocked
- **Scanner probes** to sensitive paths are blocked
- **Persistent probers** that evade the above are banned by [Fail2Ban](/features/fail2ban)
- **All other traffic** is rate limited as a backstop

### Evaluation Order

```text
Request
   |
   v
Safelists (trustedBots) --> match? --> ALLOW immediately
   |
   No match
   |
   v
Blocklists (knownScanners, suspiciousHeaders) --> match? --> 403 BLOCK
   |
   No match
   |
   v
Fail2Ban / Allow2Ban --> banned? --> 403 BLOCK
   |
   Not banned
   |
   v
Throttles --> over limit? --> 429 TOO MANY REQUESTS
   |
   Under limit
   |
   v
ALLOW (pass to handler)
```

## Best Practices

1. **Layer your defenses.** Use multiple strategies together: User-Agent blocking, path blocking, header analysis, and Fail2Ban for persistence.

2. **Verify before you safelist.** Never safelist bots based solely on their User-Agent. Always verify with rDNS using `trustedBots()` for search engine bots.

3. **Always cache DNS lookups.** Pass a PSR-16 cache to `trustedBots()` to avoid blocking DNS calls on every request.

4. **Safelist before blocklist.** Place `trustedBots()` on the safelist so verified search engine bots pass through before `knownScanners()` or `suspiciousHeaders()` can block them.

5. **Don't rely on User-Agent alone.** Sophisticated attackers rotate User-Agents to look like browsers. Combine UA-based detection with header analysis, rate limiting, and [Fail2Ban](/features/fail2ban) for defense in depth.

6. **Safelist your API clients.** If your application serves both browser and API traffic, safelist API paths or known client IPs before applying `suspiciousHeaders()`, since API clients typically don't send browser headers.

7. **Monitor false positives.** Use [events and logging](/advanced/observability) to track which rules are triggering and watch for false positives -- especially with `suspiciousHeaders()`, which may catch some legitimate clients.

8. **Combine with OWASP CRS.** For deep packet inspection beyond User-Agent matching, enable the [OWASP Core Rule Set](/features/owasp-crs) to detect SQL injection, XSS, and other attacks in request payloads.
