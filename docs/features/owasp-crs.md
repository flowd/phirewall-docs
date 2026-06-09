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
| `fromString()` | `string $rulesText, ?string $contextFolder = null, ?int $maxValuesPerCrsVariable = null` | Parse rules from a string |
| `fromFile()` | `string $filePath, ?int $maxValuesPerCrsVariable = null` | Load rules from a single file |
| `fromFiles()` | `list<string> $paths, ?int $maxValuesPerCrsVariable = null` | Load and merge multiple files |
| `fromDirectory()` | `string $dir, ?callable $filter = null, ?int $maxValuesPerCrsVariable = null` | Load all files in a directory |
| `fromStringWithReport()` | `string $rulesText, ?int $maxValuesPerCrsVariable = null` | Parse with statistics |

## Per-Variable Value Cap (CPU-DoS Guard)

Every `SecRuleLoader` factory accepts an optional trailing `?int $maxValuesPerCrsVariable`. It bounds how many collected values a single CRS variable (such as `ARGS`) may contribute to evaluation, so an attacker cannot drive up per-request WAF cost by submitting thousands of parameters, headers, or cookies. The cap is **per variable**, not aggregate.

```php
use Flowd\Phirewall\Owasp\SecRuleLoader;

// Cap each CRS variable at 5000 collected values.
$rules = SecRuleLoader::fromFile('/etc/phirewall/owasp.conf', maxValuesPerCrsVariable: 5000);
$rules = SecRuleLoader::fromString($rulesText, maxValuesPerCrsVariable: 5000);
```

- **Default (`null`):** twice PHP's `max_input_vars`, falling back to `2000` (`RequestVariableValues::DEFAULT_MAX_VALUES_PER_CRS_VARIABLE`) when `max_input_vars` is unset or non-positive. Doubling `max_input_vars` sizes the budget to the parameter count the runtime actually accepts (variables such as `ARGS` emit both a name and a value per parameter), so a request PHP can fully parse is never falsely truncated.
- **Fail-closed:** when a variable's values are truncated at the cap, the affected deny rules fail **closed** (the request is blocked) rather than evaluating a partial value set. An attacker therefore cannot pad a payload past the cap to slip past a deny rule.
- **Explicit non-positive value throws:** passing an explicit cap below `1` raises `\InvalidArgumentException`, because a non-positive cap would fail every deny rule closed and block all traffic.

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
| `REQUEST_FILENAME` | Basename (final path segment), without query string |
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
| `block` | Alias for `deny`, both trigger blocking |
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
`@pmFromFile` paths are resolved relative to the rule file's directory, and `..` traversal segments are rejected. Treat SecRule files as trusted operator configuration; never build rule text from untrusted input, since the operand selects which file is read.
:::

## Architecture

The OWASP CRS engine uses a strategy pattern to keep rule evaluation extensible and maintainable. Each `CoreRule` delegates two concerns to dedicated strategy classes:

- **Variable collectors** (`VariableCollectorInterface`) extract target values from the PSR-7 request
- **Operator evaluators** (`OperatorEvaluatorInterface`) match those values against the rule's pattern

```text
SecRule ARGS "@rx (?i)union.*select" "id:942100,phase:2,deny,msg:'SQLi'"
       ^^^^  ^^^                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
       |     |                       Actions (parsed into a map)
       |     Operator --> OperatorEvaluatorFactory --> RegexEvaluator
       Variable --------> VariableCollectorFactory --> ArgsCollector
```

When a rule is constructed, the factories resolve the variable names and operator into concrete strategy instances. On each request, `CoreRule::matches()` collects values via the variable collectors and passes them to the operator evaluator.

### Variable Collectors

Each CRS variable maps to a `VariableCollectorInterface` implementation:

| Variable | Collector Class | Source |
|----------|----------------|--------|
| `ARGS` | `ArgsCollector` | Query params + parsed body (names and values) |
| `ARGS_NAMES` | `ArgsNamesCollector` | Query param + body parameter names |
| `REQUEST_URI` | `RequestUriCollector` | Full URI including query string |
| `REQUEST_METHOD` | `RequestMethodCollector` | HTTP method |
| `QUERY_STRING` | `QueryStringCollector` | Raw query string |
| `REQUEST_FILENAME` | `RequestFilenameCollector` | Basename (final path segment), without query string |
| `REQUEST_HEADERS` | `RequestHeadersCollector` | All header values |
| `REQUEST_HEADERS_NAMES` | `RequestHeadersNamesCollector` | Header names |
| `REQUEST_COOKIES` | `RequestCookiesCollector` | All cookie values |
| `REQUEST_COOKIES_NAMES` | `RequestCookiesNamesCollector` | Cookie names |

### Operator Evaluators

Each CRS operator maps to an `OperatorEvaluatorInterface` implementation:

| Operator | Evaluator Class | Behavior |
|----------|----------------|----------|
| `@rx` | `RegexEvaluator` | PCRE match with auto-delimiters and Unicode mode; values exceeding 8 KiB are skipped (not matched) |
| `@contains` | `ContainsEvaluator` | Case-insensitive substring search |
| `@streq` | `StringEqualEvaluator` | Case-insensitive exact match |
| `@startswith` / `@beginswith` | `StartsWithEvaluator` | Case-insensitive prefix match |
| `@endswith` | `EndsWithEvaluator` | Case-insensitive suffix match |
| `@pm` | `PhraseMatchEvaluator` | Multi-phrase case-insensitive match |
| `@pmFromFile` | `PhraseMatchFromFileEvaluator` | Phrase match from file with path traversal protection |

Unsupported operators resolve to `UnsupportedOperatorEvaluator`, which never matches (safe no-op).

::: warning ReDoS protection: 8 KiB length guard on `@rx`
`RegexEvaluator` skips any value whose byte length exceeds 8,192 bytes; the value is treated as non-matching. This is an intentional trade-off: running PCRE on unbounded attacker-controlled input risks catastrophic backtracking that can freeze the PHP process (ReDoS). Skipping overlength values mirrors the behavior of standard WAFs such as ModSecurity's `SecRequestBodyLimit`.

In practice, legitimate request values (query parameters, header values, cookie values) are rarely larger than a few kilobytes. If you are matching multi-megabyte request bodies via `@rx`, consider pre-processing them before passing to the firewall.
:::

### Adding Custom Operators

Implement `OperatorEvaluatorInterface` and register it in `OperatorEvaluatorFactory`:

```php
namespace Flowd\Phirewall\Owasp\Operator;

final readonly class IpMatchEvaluator implements OperatorEvaluatorInterface
{
    /** @param list<string> $cidrs */
    public function __construct(private array $cidrs) {}

    /** @param list<string> $values */
    public function evaluate(array $values): bool
    {
        foreach ($values as $value) {
            // Check if $value falls within any CIDR range
            if ($this->matchesCidr($value)) {
                return true;
            }
        }
        return false;
    }

    private function matchesCidr(string $ip): bool
    {
        // CIDR matching logic
    }
}
```

### Adding Custom Variables

Implement `VariableCollectorInterface` and register it in `VariableCollectorFactory`:

```php
namespace Flowd\Phirewall\Owasp\Variable;

use Psr\Http\Message\ServerRequestInterface;

final readonly class RequestBodyCollector implements VariableCollectorInterface
{
    /** @return list<string> */
    public function collect(ServerRequestInterface $serverRequest): array
    {
        $body = (string) $serverRequest->getBody();
        return $body !== '' ? [$body] : [];
    }
}
```

## Performance

### Caching

Each operator evaluator and variable collector is instantiated once per rule at construction time and reused across requests. Regular expressions are compiled on first use (with PCRE's internal JIT cache), phrase lists from `@pmFromFile` are loaded and cached per file path, and all other operators use simple string operations with no additional overhead. There is no need to cache the `CoreRuleSet` externally.

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
    );
    ```

4. **Log matched rules.** Use the [observability](/advanced/observability) system to log which rules are triggering and tune accordingly.

5. **Keep rules in version control.** Store rule files alongside your application code and deploy them together.
