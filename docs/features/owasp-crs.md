---
outline: deep
---

# OWASP Core Rule Set

Phirewall includes a built-in OWASP CRS (Core Rule Set) engine that parses and evaluates ModSecurity-compatible `SecRule` directives. This provides web application firewall (WAF) capabilities for detecting SQL injection, XSS, remote code execution, path traversal, and other common attack vectors.

## Quick Start

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Owasp\SecRuleLoader;
use Flowd\Phirewall\Store\InMemoryCache;

$config = new Config(new InMemoryCache());

$rules = SecRuleLoader::fromString(<<<'CRS'
SecRule ARGS "@rx (?i)\bunion\b.*\bselect\b" "id:942100,phase:2,deny,msg:'SQL Injection'"
SecRule ARGS "@rx (?i)<script[^>]*>" "id:941100,phase:2,deny,msg:'XSS'"
CRS);

$config->blocklists->owasp('owasp', $rules);
```

## Loading Rules

### From a String

Inline rules for simple configurations:

```php
use Flowd\Phirewall\Owasp\SecRuleLoader;

$rules = SecRuleLoader::fromString(<<<'CRS'
SecRule ARGS "@rx (?i)\bunion\b.*\bselect\b" "id:942100,phase:2,deny,msg:'SQL Injection'"
SecRule ARGS "@rx (?i)<script[^>]*>" "id:941100,phase:2,deny,msg:'XSS'"
CRS);
```

### From a File

Load rules from a `.conf` file:

```php
$rules = SecRuleLoader::fromFile('/etc/phirewall/owasp-custom.conf');
```

### From Multiple Files

Load and merge multiple rule files (all must be in the same directory):

```php
$rules = SecRuleLoader::fromFiles([
    '/etc/phirewall/rules/sqli.conf',
    '/etc/phirewall/rules/xss.conf',
    '/etc/phirewall/rules/rce.conf',
]);
```

### From a Directory

Load all rule files in a directory (processed in sorted order):

```php
// Load all files
$rules = SecRuleLoader::fromDirectory('/etc/phirewall/rules/');

// Load only .conf files
$rules = SecRuleLoader::fromDirectory('/etc/phirewall/rules/',
    fn(string $path): bool => str_ends_with($path, '.conf')
);
```

### With Parse Report

Get statistics about parsing results:

```php
$report = SecRuleLoader::fromStringWithReport($rulesText);
$rules = $report['rules'];    // CoreRuleSet
$parsed = $report['parsed'];  // int - Successfully parsed rules
$skipped = $report['skipped']; // int - Lines that were skipped
```

## SecRuleLoader API

| Method | Parameters | Description |
|--------|-----------|-------------|
| `fromString()` | `string $rulesText, ?string $contextFolder` | Parse rules from a string |
| `fromFile()` | `string $filePath` | Load rules from a single file |
| `fromFiles()` | `list<string> $paths` | Load and merge multiple files |
| `fromDirectory()` | `string $dir, ?callable $filter` | Load all files in a directory |
| `fromStringWithReport()` | `string $rulesText` | Parse with statistics |

## Supported SecRule Syntax

Phirewall supports a subset of the ModSecurity SecRule language:

### Variables

| Variable | Description |
|----------|-------------|
| `ARGS` | All request parameters (query string + body) |
| `ARGS_NAMES` | Names of all request parameters |
| `REQUEST_URI` | Full request URI including query string |
| `REQUEST_METHOD` | HTTP method (GET, POST, etc.) |
| `QUERY_STRING` | Raw query string |
| `REQUEST_FILENAME` | Request path without query string |
| `REQUEST_HEADERS` | All request header values |
| `REQUEST_HEADERS_NAMES` | Names of all request headers |
| `REQUEST_COOKIES` | All cookie values |
| `REQUEST_COOKIES_NAMES` | Names of all cookies |

### Operators

| Operator | Syntax | Description |
|----------|--------|-------------|
| `@rx` | `@rx pattern` | PCRE regular expression match |
| `@contains` | `@contains text` | Case-insensitive substring match |
| `@streq` | `@streq text` | Case-insensitive exact string match |
| `@startswith` | `@startswith text` | Case-insensitive prefix match |
| `@beginswith` | `@beginswith text` | Alias for `@startswith` |
| `@endswith` | `@endswith text` | Case-insensitive suffix match |
| `@pm` | `@pm word1 word2` | Phrase match (case-insensitive, any of the listed words) |
| `@pmFromFile` | `@pmFromFile file.txt` | Phrase match from a file (one phrase per line) |

### Actions

| Action | Description |
|--------|-------------|
| `id:N` | Rule ID (required, must be unique) |
| `phase:N` | Processing phase (currently informational) |
| `deny` | Block the request (required for the rule to trigger blocking) |
| `block` | Alias for `deny` -- both trigger blocking |
| `msg:'text'` | Human-readable description for logging |

### Line Continuation

Rules can span multiple lines using backslash continuation:

```
SecRule ARGS "@rx (?i)\bunion\b.*\bselect\b" \
    "id:942100,phase:2,deny,msg:'SQL Injection'"
```

### Comments

Lines starting with `#` are ignored:

```
# SQL Injection rules
SecRule ARGS "@rx (?i)\bunion\b.*\bselect\b" "id:942100,phase:2,deny,msg:'SQLi'"
```

## Managing Rules

### Disabling Rules

Disable specific rules that cause false positives:

```php
$rules = SecRuleLoader::fromString(/* ... */);

// Disable a specific rule by ID
$rules->disable(941110); // XSS Event Handler (too aggressive for some apps)

$config->blocklists->owasp('owasp', $rules);
```

### Re-enabling Rules

```php
$rules->enable(941110);
```

### Checking Rule State

```php
if ($rules->isEnabled(941110)) {
    echo "Rule 941110 is active";
}
```

### Listing Rule IDs

```php
$ids = $rules->ids(); // Returns list<int> of all rule IDs
```

### Getting a Specific Rule

```php
$rule = $rules->getRule(942100);
```

## OWASP Diagnostics Header

Enable the diagnostics header to see which OWASP rule matched:

```php
$config->enableResponseHeaders();
$config->enableOwaspDiagnosticsHeader();
```

When an OWASP rule blocks a request, the response includes:

```
X-Phirewall: blocklist
X-Phirewall-Matched: owasp
X-Phirewall-Owasp-Rule: 942100
```

::: info
`X-Phirewall` and `X-Phirewall-Matched` require `enableResponseHeaders()`. The `X-Phirewall-Owasp-Rule` header is controlled independently by `enableOwaspDiagnosticsHeader()`.
:::

::: warning
Disable the diagnostics header in production. It reveals which security rules are in place, which could help attackers craft evasion payloads.
:::

## Common Rule Sets

### SQL Injection (SQLi)

```
SecRule ARGS "@rx (?i)(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b)" \
    "id:942100,phase:2,deny,msg:'SQL Injection'"
SecRule ARGS "@rx ('\s*(or|and)\s*'|'\s*=\s*')" \
    "id:942120,phase:2,deny,msg:'SQL Quote Injection'"
SecRule ARGS "@rx (?i)(drop|alter|create|truncate)\s+(table|database)" \
    "id:942130,phase:2,deny,msg:'SQL DDL Injection'"
```

### Cross-Site Scripting (XSS)

```
SecRule ARGS "@rx (?i)<script[^>]*>" \
    "id:941100,phase:2,deny,msg:'XSS Script Tag'"
SecRule ARGS "@rx (?i)\bon\w+\s*=" \
    "id:941110,phase:2,deny,msg:'XSS Event Handler'"
SecRule ARGS "@rx (?i)javascript\s*:" \
    "id:941120,phase:2,deny,msg:'XSS JavaScript Protocol'"
```

### Remote Code Execution (RCE)

```
SecRule ARGS "@rx (?i)(eval|exec|system|shell_exec|passthru)\s*\(" \
    "id:933100,phase:2,deny,msg:'PHP Code Injection'"
SecRule ARGS "@rx (?i)(base64_decode|gzinflate|str_rot13)\s*\(" \
    "id:933110,phase:2,deny,msg:'PHP Obfuscation'"
```

### Path Traversal

```
SecRule REQUEST_URI "@rx \.\.\/" \
    "id:930100,phase:2,deny,msg:'Path Traversal'"
SecRule REQUEST_URI "@rx (?i)(%2e%2e%2f|%2e%2e/)" \
    "id:930110,phase:2,deny,msg:'Encoded Path Traversal'"
```

## Production Configuration

A comprehensive rule set for production:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Owasp\SecRuleLoader;
use Flowd\Phirewall\Store\RedisCache;
use Predis\Client as PredisClient;

$redis = new PredisClient(getenv('REDIS_URL') ?: 'redis://localhost:6379');
$config = new Config(new RedisCache($redis));

$rules = SecRuleLoader::fromString(<<<'CRS'
# ── SQL Injection ──────────────────────────────────────────
SecRule ARGS "@rx (?i)(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b)" \
    "id:942100,phase:2,deny,msg:'SQL Injection'"
SecRule ARGS "@rx ('\s*(or|and)\s*'|'\s*=\s*')" \
    "id:942120,phase:2,deny,msg:'SQL Quote Injection'"

# ── XSS ───────────────────────────────────────────────────
SecRule ARGS "@rx (?i)<script[^>]*>" \
    "id:941100,phase:2,deny,msg:'XSS Script Tag'"
SecRule ARGS "@rx (?i)\bon\w+\s*=" \
    "id:941110,phase:2,deny,msg:'XSS Event Handler'"
SecRule ARGS "@rx (?i)javascript\s*:" \
    "id:941120,phase:2,deny,msg:'XSS JavaScript Protocol'"

# ── Remote Code Execution ─────────────────────────────────
SecRule ARGS "@rx (?i)(eval|exec|system|shell_exec|passthru)\s*\(" \
    "id:933100,phase:2,deny,msg:'PHP Code Injection'"
SecRule ARGS "@rx (?i)(base64_decode|gzinflate|str_rot13)\s*\(" \
    "id:933110,phase:2,deny,msg:'PHP Obfuscation'"

# ── Path Traversal ────────────────────────────────────────
SecRule REQUEST_URI "@rx \.\.\/" \
    "id:930100,phase:2,deny,msg:'Path Traversal'"
SecRule REQUEST_URI "@rx (?i)(%2e%2e%2f|%2e%2e/)" \
    "id:930110,phase:2,deny,msg:'Encoded Path Traversal'"
CRS);

// Disable rules that cause false positives in your application
// $rules->disable(941110); // XSS Event Handler

$config->blocklists->owasp('owasp', $rules);
```

## File-Based Rule Management

For larger deployments, manage rules in files:

```php
// Load from a directory of .conf files
$rules = SecRuleLoader::fromDirectory('/etc/phirewall/rules/',
    fn(string $path): bool => str_ends_with($path, '.conf')
);

// Check parsing results
$report = SecRuleLoader::fromStringWithReport(
    file_get_contents('/etc/phirewall/rules/custom.conf')
);
echo "Parsed: {$report['parsed']}, Skipped: {$report['skipped']}\n";
```

### @pmFromFile Support

The `@pmFromFile` operator loads phrase lists from external files. The file path is resolved relative to the rule file's directory:

```
# rules/sqli.conf
SecRule ARGS "@pmFromFile sqli-keywords.txt" "id:942200,phase:2,deny,msg:'SQLi keyword'"
```

```
# rules/sqli-keywords.txt
union select
drop table
insert into
```

::: warning
`@pmFromFile` includes path traversal protection. Paths containing `..` are rejected to prevent loading files outside the rules directory.
:::

## Performance

### Caching

OWASP rules are compiled once when loaded and cached internally. Regular expressions are compiled on first use and phrase lists are pre-processed for efficient matching. There is no need to cache the `CoreRuleSet` externally.

### Operator Performance

| Operator | Relative Cost | Notes |
|----------|:------------:|-------|
| `@streq` | Low | Simple string comparison |
| `@contains` | Low | Substring search |
| `@startswith` / `@endswith` | Low | Prefix/suffix check |
| `@pm` | Medium | Case-insensitive phrase matching (pre-compiled) |
| `@rx` | High | PCRE regex (compiled on first use, cached) |

::: tip
Use `@pm` for simple keyword matching and `@rx` for complex patterns. `@pm` is significantly faster for lists of words.
:::

## Best Practices

1. **Start with a minimal rule set.** Add rules incrementally and test each addition against your application's normal traffic to identify false positives.

2. **Use unique rule IDs.** Each rule must have a unique `id`. Use the OWASP convention: 9xxxxx for attack categories (942xxx for SQLi, 941xxx for XSS, etc.).

3. **Combine with fail2ban.** Use OWASP rules to detect attacks and fail2ban to ban repeat offenders:

    ```php
    $config->blocklists->owasp('owasp', $rules);
    $config->fail2ban->add('persistent-attacker',
        threshold: 5, period: 60, ban: 86400,
        filter: fn($req) => true,
        key: KeyExtractors::ip()
    );
    ```

4. **Log matched rules.** Use the [observability](/advanced/observability) system to log which rules are triggering and tune accordingly.

5. **Keep rules in version control.** Store rule files alongside your application code and deploy them together.
