---
outline: deep
---

# OWASP Core Rule Set

OWASP CRS support lives in a separate companion package,
[`flowd/phirewall-preset-owasp-crs`](https://github.com/flowd/phirewall-preset-owasp-crs).
It provides a ModSecurity-compatible `SecRule` engine - parsing and evaluating
`SecRule` directives for detecting SQL injection, XSS, remote code execution, path
traversal, and other common attack vectors - plus ready-made, per-paranoia-level CRS
presets you can drop into a `Config`.

::: info Extracted in 0.6
The SecRule engine used to ship inside the core `flowd/phirewall` package under the
`Flowd\Phirewall\Owasp\` namespace. As of 0.6 it lives in the companion package under
`Flowd\PhirewallPresetOwaspCrs\Engine\`, and the `$config->blocklists->owasp()`
shortcut was removed - register a `CoreRuleSetMatcher` as a normal blocklist rule
instead (shown throughout this page).
:::

## Installation

```bash
composer require flowd/phirewall-preset-owasp-crs
```

## Quick Start

The fastest way to get CRS protection is the bundled presets, which ship a
pre-filtered, per-paranoia-level snapshot of the OWASP CRS rules:

```php
use Flowd\Phirewall\Config;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\Presets;
use Flowd\Phirewall\Store\InMemoryCache;

$config = new Config(new InMemoryCache());

// Block requests whose accumulated CRS anomaly score reaches the threshold (default 5).
$config = $config->with(Presets::blocklist(ParanoiaLevel::Level1));
```

Want to also ban repeat offenders? Use the Fail2Ban preset instead. It blocks
the same scoring requests with `403` and additionally **bans** the client key
once it produced `threshold` such requests within `period` seconds. A banned
attacker is then blocked by a cheap ban lookup (the CRS engine no longer runs
for them), and the ban is observable via `Fail2BanBanned` and mirrorable to
your web server:

```php
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\Presets;

$config = $config->with(
    Presets::fail2ban(ParanoiaLevel::Level1, threshold: 5, period: 600, ban: 3600),
);
```

See the [package README](https://github.com/flowd/phirewall-preset-owasp-crs) for the
preset API, paranoia-level guidance, and how the bundled rules are imported and kept
up to date.

## Anomaly Scoring

Since preset package 0.5, evaluation follows the CRS anomaly-scoring model instead of
blocking on the first match: every matching rule contributes its `severity` score
(CRITICAL 5, ERROR 4, WARNING 3, NOTICE 2; rules without a recognizable severity are
scored as CRITICAL), and the request is blocked once the accumulated score **reaches**
the threshold (`score >= threshold`, default 5, the CRS standard inbound threshold).

In practice most bundled rules are CRITICAL and still block on their own; the
WARNING-level rules (for example the `942430` restricted-character checks, a classic
source of false positives on marketing parameters) no longer block alone - two of them
together do. `anomalyThreshold: 1` restores block-on-first-match behaviour:

```php
$config = $config->with(Presets::blocklist(ParanoiaLevel::Level1, anomalyThreshold: 1));
```

Three decisions bypass the threshold and block immediately (fail closed): a variable
truncated at the collection cap, a single value longer than the per-value inspection
limit (default 2048 bytes, see [Per-Value Length Cap](#per-value-length-cap)), and a
value that triggers a PCRE engine error.
Scores never accumulate across requests; the Fail2Ban preset counts a request toward
the ban whenever CRS blocks it - when its score reaches the threshold or the request
fails closed.

A request blocked on its anomaly score - or by a rule-level fail-closed outcome (a
capped variable, an oversized value, or a PCRE subject error) - carries
`owasp_anomaly_score`, `owasp_anomaly_threshold`, `owasp_rule_ids` (comma-separated)
and `owasp_rule_id` (first match); it also carries `msg`, `owasp_matched_variable`
(the target the first matching rule fired on, e.g. `REQUEST_HEADERS:User-Agent` -
the member name keeps the casing the client sent), `owasp_matched_value` (the
value the rule fired on - readable so the match can be understood; sanitized,
length-bounded and `[redacted]` for credential targets such as cookie values and
`Authorization`-type headers) and `owasp_log_data` when the first matching rule
provides them, and `owasp_fail_closed` on a fail-closed block
(there `owasp_matched_variable` names the variable that failed closed). A
block from an engine-internal fault under a fail-closed policy (`useFailOpen(false)`)
instead carries only `owasp_anomaly_threshold` and `owasp_fail_closed`.

**Fail-open policy.** An unexpected engine-internal fault during evaluation - for example a
value manipulator that throws - is governed by the firewall's fail-open setting. Under the
default fail-open policy the fault propagates to the core's error handling and the request is
allowed (a `FirewallError` event is dispatched); when the firewall is configured fail-closed
(fail-open disabled), the matcher blocks the request instead. This is separate from the
rule-level fail-closed decisions above, which always block regardless of the policy.

## Tuning False Positives

### Target Exclusions

Marketing and tracking parameters (`utm_*`, `fbclid`, ...) regularly carry values that
look like attack payloads to CRS rules. Instead of disabling whole rules, exclude the
parameter from inspection - globally, per rule id (CRS `SecRuleUpdateTargetById`
style) or per rule tag. Both presets accept a `configure` closure that receives the
matcher before the first request:

```php
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;

$config = $config->with(Presets::blocklist(
    ParanoiaLevel::Level1,
    configure: static function (CoreRuleSetMatcher $matcher): void {
        $matcher->excludeTarget('ARGS:/^utm_/');            // all rules ignore utm_* values
        $matcher->excludeTarget('ARGS_NAMES:/^utm_/');      // ... and the utm_* parameter names
        $matcher->excludeTargetById(942431, 'ARGS:fbclid'); // one rule ignores one parameter
        $matcher->excludeTargetByTag('attack-sqli', 'ARGS:comment');
    },
));
```

Selector forms: bare variable (`ARGS`), exact name (`ARGS:utm_source`) or name pattern
(`ARGS:/^utm_/`). Header names match case-insensitively, argument and cookie names
case-sensitively. Exclusions are runtime tuning: they never enter the compiled-data
cache and cannot lift the collection cap. They also do not rewrite the raw
`QUERY_STRING`/`REQUEST_URI` values - the few rules inspecting those still see the
full string; use `disable($ruleId)`, a manipulator, or a bare-variable exclusion
naming the variable that rule actually inspects
(`excludeTargetById(920260, 'REQUEST_URI')`, but `excludeTargetById(931110,
'QUERY_STRING')` since 931110 inspects the query string). A selector naming a
variable the rule does not target is accepted but silently does nothing.

::: tip Use the CRS 4 tags
A tag that no loaded rule carries makes a tag-scoped exclusion a silent no-op - the
classic case is a CRS 3 tag (`OWASP_CRS/WEB_ATTACK/SQL_INJECTION`) against the
bundled CRS 4 snapshot, whose tags are `attack-sqli` and friends. With a PSR-3
logger on the matcher, such a tag logs a `warning` once the rules are loaded;
this covers `excludeTargetByTag()` and the tag-scoped CRS exclusion syntax alike.
:::

### Conditional Exclusions: Validate the Value First

Every exclude method accepts a `when:` condition - the selected entry is only
excluded while the condition approves its value. That turns a blanket exclusion into
a validated one: a parameter is skipped when it provably carries a legitimate value
and stays fully inspected otherwise. The classic case is a signed token that trips
character-class rules:

```php
$matcher->excludeTargetByTag(
    'attack-sqli',
    'ARGS:token',
    when: static fn (string $variable, ?string $name, string $value): bool
        => $jwtValidator->isValid($value),
);
```

The condition receives `(string $variable, ?string $name, string $value,
ServerRequestInterface $request)` - the same argument order as a manipulator -
and returns `true` to exclude; a closure declaring fewer parameters ignores the
rest. The request enables context-dependent validation (per-host issuers,
path-scoped rules, comparing against another header). Implement
`TargetExclusionConditionInterface` for a reusable validator. It runs only for
entries the selector matches, and its exceptions propagate like manipulator
exceptions, governed by the failure policy (`useFailOpen()`).

::: warning Validate strictly
Everything the condition approves is invisible to the rules in scope. Verify the
signature and parse the full format - a shape-only check ("looks like a JWT")
invites attackers to wrap payloads in that shape.
:::

### CRS Rule-Exclusion Syntax

`applyRuleExclusions()` and `applyRuleExclusionsFromFile()` - on `CoreRuleSet` and
`CoreRuleSetMatcher` (queued until the rules load, validated eagerly) - accept the
CRS rule-exclusion syntax, so existing ModSecurity tuning files can be reused:

```php
$config = $config->with(Presets::blocklist(
    ParanoiaLevel::Level1,
    configure: static function (CoreRuleSetMatcher $matcher): void {
        $matcher->applyRuleExclusions(<<<'CONF'
            # Configure-time directives: apply once, to the rules already loaded
            SecRuleRemoveById 942440 "942430-942432"
            SecRuleUpdateTargetById 942100 "!ARGS:search"
            SecRuleUpdateTargetByTag attack-sqli "!ARGS:/^utm_/"

            # Runtime exclusion rule: evaluated before the scoring rules on every
            # request; its ctl: exclusions apply only to requests it matches.
            SecRule REQUEST_URI "@beginsWith /api/webhooks/" \
                "id:10001,phase:1,pass,nolog,\
                ctl:ruleRemoveTargetByTag=attack-sqli;ARGS:payload"
            CONF);
    },
));
```

Supported forms: `SecRuleRemoveById` (ids and `from-to` ranges), `SecRuleRemoveByTag`
(exact tag, not a regex), `SecRuleUpdateTargetById` / `SecRuleUpdateTargetByTag`
(negated `!TARGET` removals only), and runtime `SecRule` exclusions with
`ctl:ruleRemoveById`, `ctl:ruleRemoveByTag`, `ctl:ruleRemoveTargetById` or
`ctl:ruleRemoveTargetByTag`.

Anything the engine cannot evaluate faithfully fails eagerly with an
`InvalidArgumentException` instead of arming a weaker or dead exclusion: chained
rules, unsupported condition operators or variables, target additions and malformed
directives all throw. Unknown directives (`SecMarker`, ...) and other `ctl:` options
(`ctl:ruleEngine`, ...) are skipped. Like every exclusion this is runtime tuning and
never enters the compiled-data cache.

::: tip Prefer `when:` over `ctl:` shape checks
A runtime exclusion's condition can only pattern-match (`@rx` and friends), so it
can check that a value *looks like* a JWT but not that it *is* one - an attacker can
wrap a payload in the approved shape. When the value can be validated in PHP, prefer
a conditional exclusion (`when:`) that verifies the signature.
:::

### Manipulators (advanced)

A manipulator transforms collected values before rules match against them - the escape
hatch when excluding a whole parameter is too broad. Returning an empty string removes
the value from inspection:

```php
$matcher->addManipulator(
    static fn (string $variable, ?string $name, string $value): string
        => $name === 'fbclid' ? '' : $value,
);
$matcher->addManipulatorById(942431, $manipulator); // scoped to one rule
```

Closure manipulators receive the request as an optional fourth argument
`(string $variable, ?string $name, string $value, ServerRequestInterface $request)` -
the same order as a `when:` exclusion condition; declare it when the
transformation depends on request context. The three-parameter
`RequestValueManipulatorInterface` is unchanged.

Manipulators run after exclusions; global manipulator results are computed once
per variable per request and shared across all rules, per-rule manipulators
specialize from that shared result.

::: warning Manipulators weaken detection
Whatever a manipulator removes or rewrites is invisible to every rule it applies to -
including real attack payloads hidden inside the removed content. Prefer target
exclusions; keep manipulators as narrow as possible. Exceptions thrown by a
manipulator propagate.
:::

### Match Logging

Pass a PSR-3 logger to either preset (or to `CoreRuleSetMatcher`) to log every rule
match at `info` level - **including sub-threshold matches on requests that pass**.
Those entries are the tuning signal: watch them to find false-positive patterns before
scores ever accumulate to a block, then add a target exclusion. Blocked requests
additionally log a `warning` with total score, threshold and all matched rule ids.

```php
$config = $config->with(Presets::blocklist(ParanoiaLevel::Level1, logger: $logger));
```

The per-match log context carries `rule_id`, `severity`, `anomaly_score`,
`paranoia_level`, `matched_variable` (e.g. `ARGS:utm_content`), `matched_value`
(the value the rule fired on; `[redacted]` for credential targets), `msg`, `fail_closed`,
`method`, `path` and `log_data` - the rule's CRS `logdata:` template expanded with the
matched data (`%{TX.0}`, `%{MATCHED_VAR_NAME}`, `%{MATCHED_VAR}`); the warning context
carries `total_score`, `anomaly_threshold`, `rule_ids`, `fail_closed`, `method` and
`path`. Attacker-controlled context values are sanitized and length-bounded.

When the matched target carries a credential - a cookie or an `Authorization`, `Cookie`,
`Proxy-Authorization`, `X-Api-Key` or `X-Auth-Token` header - the value (and its `%{TX.n}`
captures) is replaced with `[redacted]`, so secrets never reach the log or the
`owasp_log_data` metadata. The target name (`%{MATCHED_VAR_NAME}`, e.g.
`REQUEST_COOKIES:session`) is kept, so a redacted match still tells you which parameter to
exclude.

## Writing Your Own Rules

You are not limited to the bundled CRS snapshot - the SecRule engine can parse and
evaluate any ModSecurity-style ruleset you provide. Load rules and register them as a
blocklist rule via a `CoreRuleSetMatcher`:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\Rule\BlocklistRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;
use Flowd\PhirewallPresetOwaspCrs\Engine\SecRuleLoader;
use Flowd\Phirewall\Store\InMemoryCache;

$config = new Config(new InMemoryCache());

$rules = SecRuleLoader::fromString(<<<'CRS'
SecRule ARGS "@rx (?i)\bunion\b.*\bselect\b" "id:942100,phase:2,deny,msg:'SQL Injection'"
SecRule ARGS "@rx (?i)<script[^>]*>" "id:941100,phase:2,deny,msg:'XSS'"
CRS);

$config->blocklists->addRule(new BlocklistRule('owasp', new CoreRuleSetMatcher($rules)));
```

## Loading Rules

### From a String

Inline rules for simple configurations:

```php
use Flowd\PhirewallPresetOwaspCrs\Engine\SecRuleLoader;

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

### Per-Variable Value Cap

Every factory accepts an optional `$maxValuesPerCrsVariable`: a positive-int cap on how many values are collected per CRS variable per request. It bounds the evaluation cost of count-unbounded, attacker-controlled variables such as `ARGS` (a CPU-DoS guard). The default (`null`) derives the cap from twice PHP's `max_input_vars`, falling back to 2000 when the directive is unset or non-positive, so a request PHP can fully parse is never falsely truncated. When a variable *is* truncated at the cap, rules targeting it fail closed and treat the request as a match, so padding a payload past the cap cannot evade a rule. A value `< 1` throws `InvalidArgumentException`.

### Per-Value Length Cap

The count cap above bounds *how many* values are collected. A second cap bounds
*how long a single value* may be: a collected value longer than
`CoreRule::MAX_INSPECTABLE_VALUE_LENGTH` (default **2048 bytes**) is treated as
un-inspectable, and the rule **fails closed** (blocks) - the same contract as the
count cap. One mechanism covers three concerns at once:

- **Evasion.** A payload placed past the limit (`?q=` + 9 KB of filler + `UNION SELECT …`) can no longer slip through - the oversized value blocks instead of being partially inspected.
- **ReDoS.** No value longer than the cap ever reaches the regex engine, so worst-case `@rx` backtracking is bounded by the cap, not by the request size.
- **Unbounded scan.** The phrase/substring operators (`@contains`, `@pm`, `@pmFromFile`, …) never scan an arbitrarily large value.

Tune it per rule set with `CoreRuleSet::setMaxInspectableValueLength(int $bytes)`
or `CoreRuleSetMatcher::setMaxInspectableValueLength(int $bytes)` (the latter is
reachable through the presets' `configure:` closure and queued until the rules
load). Both validate `$bytes >= 1` and return `$this` for chaining:

```php
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;

$config = $config->with(Presets::blocklist(
    ParanoiaLevel::Level1,
    configure: static fn (CoreRuleSetMatcher $matcher) => $matcher->setMaxInspectableValueLength(8192),
));
```

Choosing the value is a trade-off:

- **Lower** (e.g. 1024) - **pro:** tighter worst-case regex time and a smaller per-value CPU budget. **con:** more false-positive blocks, because a value over the cap is blocked even when it is harmless.
- **Higher** (e.g. 8192) - **pro:** fewer false positives on legitimately large single values, notably long tokens in a `Cookie` or `Authorization` header and base64 fields. **con:** a larger subject reaches the regex engine, so the worst-case backtracking cost the cap bounds grows with it (roughly cubic for the pathological CRS XSS patterns).

The default of 2048 balances the two: it bounds a pathological `@rx` subject to
roughly a second of worst-case work while passing typical request values. Raise
it if your application legitimately sends large single fields or tokens; lower it
for a stricter CPU bound when your traffic has no large single fields.

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

Collection variables also accept **named selectors**: `REQUEST_HEADERS:User-Agent`
inspects only that header, and negated selectors such as `!REQUEST_HEADERS:Cookie` or
`!ARGS_NAMES:/^utm_/` exclude members from the rule's bare selector of the same
variable. Selectors of unsupported variables (`XML:/*`, `REQUEST_BODY`) collect
nothing; the rule evaluates against its supported targets only.

### Operators

| Operator | Syntax | Description |
|----------|--------|-------------|
| `@rx` | `@rx pattern` | PCRE regular expression match |
| `@contains` | `@contains text` | Case-insensitive substring match |
| `@streq` | `@streq text` | Case-insensitive exact string match |
| `@beginsWith` | `@beginsWith text` | Case-insensitive prefix match |
| `@startsWith` | `@startsWith text` | Alias for `@beginsWith` (phirewall extension; not a ModSecurity operator) |
| `@endsWith` | `@endsWith text` | Case-insensitive suffix match |
| `@pm` | `@pm word1 word2` | Phrase match (case-insensitive substring match against any of the listed phrases) |
| `@pmFromFile` | `@pmFromFile file.txt` | Phrase match from a file (one phrase per line) |

Operator names themselves are matched case-insensitively (`@beginswith` parses
just as well); this page uses the canonical ModSecurity casing.

The string operators (`@streq`, `@contains`, `@beginsWith`, `@endsWith`) match
case-insensitively. In ModSecurity these operators are case-sensitive and case
folding comes from a `t:lowercase` transformation on the target; because this engine
ignores transformations, folding case in the operators reproduces that common CRS
pattern. A rule that genuinely wanted case-sensitive matching without `t:lowercase`
is matched case-insensitively instead (a safe over-match, never an under-match).

### Actions

| Action | Description |
|--------|-------------|
| `id:N` | Rule ID (required, must be unique) |
| `phase:N` | Processing phase (currently informational) |
| `deny` | Make the rule score/block (required for the rule to participate) |
| `block` | Alias for `deny` |
| `msg:'text'` | Human-readable description for logging and metadata |
| `severity:'LEVEL'` | Anomaly score contribution: CRITICAL 5, ERROR 4, WARNING 3, NOTICE 2 (missing/unknown scores as CRITICAL) |
| `logdata:'template'` | Log template expanded on a match (`%{TX.0}`, `%{MATCHED_VAR_NAME}`, `%{MATCHED_VAR}`) |
| `tag:'name'` | Rule tags (repeatable); `paranoia-level/N` sets the level, tags drive `excludeTargetByTag()` |
| `ctl:ruleRemove*` | Honored only in exclusion text applied via [`applyRuleExclusions()`](#crs-rule-exclusion-syntax); ignored in normal rule loading |

Unlisted actions (`t:`, `setvar:`, `chain`, ...) are ignored during normal rule
loading; a rule whose evaluation would depend on them (e.g. a chained rule) is
dropped at import of the bundled snapshot.

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

### Tuning the Bundled Snapshot

The presets from the [Quick Start](#quick-start) accept a `configure` closure for
[exclusions and manipulators](#tuning-false-positives). For full manual control, load
the bundled snapshot as a mutable `CoreRuleSet` via `Presets::coreRuleSet()` and wire
it yourself:

```php
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\Presets;

$rules = Presets::coreRuleSet(ParanoiaLevel::Level2)
    ->excludeTarget('ARGS:/^utm_/');
$rules->disable(942430); // restricted SQL character anomaly, if it false-positives for your app

$config->blocklists->addRule(new BlocklistRule('owasp', new CoreRuleSetMatcher($rules)));
```

`Presets::crsVersion()` returns the upstream CRS release tag the bundled rules were
imported from, so you can log or alert on the snapshot your deployment is running.

### Disabling Rules

Disable specific rules that cause false positives:

```php
$rules = SecRuleLoader::fromString(/* ... */);

// Disable a specific rule by ID
$rules->disable(941110); // XSS Event Handler (too aggressive for some apps)

$config->blocklists->addRule(new BlocklistRule('owasp', new CoreRuleSetMatcher($rules)));
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

Enable response and diagnostic headers to see which OWASP rule matched:

```php
$config->enableResponseHeaders();
$config->enableDiagnosticsHeaders();
```

When the accumulated anomaly score blocks a request, the response includes:

```
X-Phirewall: blocklist
X-Phirewall-Matched: owasp
X-Phirewall-Owasp-Rule: 942430,942431
X-Phirewall-Owasp-Score: 6/5
```

`X-Phirewall-Owasp-Rule` lists every matched rule id (capped at 10, then `,+N`);
`X-Phirewall-Owasp-Score` is `score/threshold`.

::: info
`X-Phirewall` and `X-Phirewall-Matched` require `enableResponseHeaders()`. The `X-Phirewall-Owasp-Rule` header is controlled independently by `enableDiagnosticsHeaders()` (`enableOwaspDiagnosticsHeader()` is a deprecated alias): the CRS matcher declares it via the generic `diagnostic_headers` metadata key on its `MatchResult`, so it also appears when the matcher is used as a Fail2Ban filter.
:::

::: info
`X-Phirewall-Matched` carries the name of the blocklist rule that matched. In the manual examples above that name is `owasp`; if you register the OWASP CRS through the preset engine, the rule is named `preset.owasp-crs.blocklist`, so that is the value you will see.
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

For production, use the bundled OWASP CRS preset - a filtered, tested snapshot of the full
Core Rule Set covering every attack category - rather than hand-written rules. Pair it with a
compiled-data cache so the rules are parsed once per deployment instead of on every request,
and a PSR-3 logger so you can watch sub-threshold matches before they ever block:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\RedisCache;
use Flowd\Phirewall\Support\CompiledDataCache;
use Flowd\PhirewallPresetOwaspCrs\Presets;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Predis\Client as PredisClient;

$redis = new PredisClient(getenv('REDIS_URL') ?: 'redis://localhost:6379');
$config = new Config(new RedisCache($redis));
$config->setCompiledDataCache(new CompiledDataCache('/var/cache/phirewall'));

$config = $config->with(Presets::blocklist(
    ParanoiaLevel::Level1,     // start low; raise only after tuning
    anomalyThreshold: 5,       // the CRS standard inbound threshold
    logger: $logger,           // sub-threshold matches are the tuning signal
));
```

Start at paranoia level 1 with the default threshold, watch the log for false-positive
patterns, add [target exclusions](#target-exclusions), and only then raise the paranoia
level - see [Tuning False Positives](#tuning-false-positives).

Hand-writing a SecRule set (see [Writing Your Own Rules](#writing-your-own-rules)) is only
for narrow, app-specific checks the CRS does not cover. Do not reimplement SQLi/XSS/RCE
detection by hand: a naive pattern such as `@rx (?i)<script[^>]*>` misses the large majority
of real payloads that the maintained CRS catches.

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

Tuning belongs in its own file: keep your
[CRS rule exclusions](#crs-rule-exclusion-syntax) next to the application and
apply them with `applyRuleExclusionsFromFile()` - the file is read eagerly, so
a missing, unreadable or malformed tuning file fails at configuration time, not
on the first request:

```php
$config = $config->with(Presets::blocklist(
    ParanoiaLevel::Level1,
    configure: static fn (CoreRuleSetMatcher $matcher) =>
        $matcher->applyRuleExclusionsFromFile('/etc/phirewall/crs-exclusions.conf'),
));
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
`@pmFromFile` confines the operand to the rules directory. Directory traversal (`..`), absolute paths, and stream-wrapper schemes (`file://`, `php://`, ...) are all rejected, so a rule cannot load a file from outside its directory. An operand that cannot be safely resolved fails closed - the rule blocks - rather than being silently skipped, so a misconfigured `@pmFromFile` cannot quietly disable protection.
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

When a rule is constructed, the factories resolve the variable names and operator into concrete strategy instances. On each request, `CoreRuleSet::evaluate()` collects values via the variable collectors (applying exclusions and manipulators), passes them to the operator evaluators and accumulates the matching rules' severity scores into a `RuleSetEvaluation`.

### Variable Collectors

Each CRS variable maps to a `VariableCollectorInterface` implementation:

| Variable | Collector Class | Source |
|----------|----------------|--------|
| `ARGS` | `ArgsCollector` | Query params + parsed body (names and values) |
| `ARGS_NAMES` | `ArgsNamesCollector` | Query param + body parameter names |
| `REQUEST_URI` | `RequestUriCollector` | Full URI including query string |
| `REQUEST_METHOD` | `RequestMethodCollector` | HTTP method |
| `QUERY_STRING` | `QueryStringCollector` | Raw query string |
| `REQUEST_FILENAME` | `RequestFilenameCollector` | URI path without query string |
| `REQUEST_HEADERS` | `RequestHeadersCollector` | All header values |
| `REQUEST_HEADERS_NAMES` | `RequestHeadersNamesCollector` | Header names |
| `REQUEST_COOKIES` | `RequestCookiesCollector` | All cookie values |
| `REQUEST_COOKIES_NAMES` | `RequestCookiesNamesCollector` | Cookie names |

### Operator Evaluators

Each CRS operator maps to an `OperatorEvaluatorInterface` implementation:

| Operator | Evaluator Class | Behavior |
|----------|----------------|----------|
| `@rx` | `RegexEvaluator` | PCRE match with auto-delimiters and Unicode mode; a subject-induced PCRE engine error fails closed. Oversized values are bounded upstream by the [per-value length cap](#per-value-length-cap), so the evaluator no longer truncates. |
| `@contains` | `ContainsEvaluator` | Case-insensitive substring search |
| `@streq` | `StringEqualEvaluator` | Case-insensitive exact match |
| `@beginsWith` / `@startsWith` | `StartsWithEvaluator` | Case-insensitive prefix match |
| `@endsWith` | `EndsWithEvaluator` | Case-insensitive suffix match |
| `@pm` | `PhraseMatchEvaluator` | Multi-phrase case-insensitive match |
| `@pmFromFile` | `PhraseMatchFromFileEvaluator` | Phrase match from file with path traversal protection |

Unsupported operators resolve to `UnsupportedOperatorEvaluator`, which never matches (safe no-op).

::: warning ReDoS protection: per-value length cap + fail-closed
Catastrophic `@rx` backtracking (which can freeze the PHP process) is bounded by the [per-value length cap](#per-value-length-cap): a value longer than `CoreRule::MAX_INSPECTABLE_VALUE_LENGTH` (default 2048 bytes) never reaches the regex engine - the rule fails closed instead of matching a head window. A subject that still triggers a PCRE engine error *within* the limit (invalid UTF-8 under `/u`, backtrack/recursion limit) also fails closed, so a malformed payload can never silently disable a rule.

Earlier versions truncated an oversized value to an 8 KiB head and matched only that head. That left the 8 KiB head as the peak backtracking-cost point *and* let a payload evade by sitting past the head. The current fail-closed cap replaces that behavior, and its length is configurable - see [Per-Value Length Cap](#per-value-length-cap) for the trade-off between a tighter CPU bound and false-positive blocks on large legitimate values.
:::

### Adding Custom Operators

Implement `OperatorEvaluatorInterface` and register it in `OperatorEvaluatorFactory`:

```php
namespace Flowd\PhirewallPresetOwaspCrs\Engine\Operator;

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
namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

use Psr\Http\Message\ServerRequestInterface;

final readonly class RequestBodyCollector implements VariableCollectorInterface
{
    /** @return list<array{name: ?string, value: string}> */
    public function collect(ServerRequestInterface $serverRequest): array
    {
        $body = (string) $serverRequest->getBody();
        return $body !== '' ? [['name' => null, 'value' => $body]] : [];
    }
}
```

Each entry carries the member name it belongs to (parameter, cookie or header name)
so selectors and exclusions can address it; unnamed variables use `name: null`.

## Performance

### Caching

Each operator evaluator and variable collector is instantiated once per rule at construction time and reused across requests. Regular expressions are compiled on first use (with PCRE's internal JIT cache), phrase lists from `@pmFromFile` are loaded and cached per file path, and all other operators use simple string operations with no additional overhead.

What *is* worth caching is the one-time cost of **parsing** the rule files into the `CoreRuleSet` - several milliseconds that, under PHP-FPM, would otherwise be paid on every request. Build the matcher with the lazy factory and give the `Config` a compiled-data cache; the parsed rules are then served from an OPcache-backed artifact and re-parsed only when a rule file changes:

```php
use Flowd\Phirewall\Config\Rule\BlocklistRule;
use Flowd\Phirewall\Support\CompiledDataCache;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;

$config->setCompiledDataCache(new CompiledDataCache('/path/to/var/cache/phirewall'));

$matcher = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1);
$matcher->disable(941110); // toggles before the first request are queued
$config->blocklists->addRule(new BlocklistRule('owasp', $matcher));
```

`Presets::blocklist()` and `Presets::fail2ban()` already build lazily, so they pick up the cache automatically. A matcher constructed eagerly with an already parsed `CoreRuleSet` keeps parsing at construction and ignores the cache. See [Presets › Caching expensive preset data](/advanced/presets#caching-expensive-preset-data).

### Operator Performance

| Operator | Relative Cost | Notes |
|----------|:------------:|-------|
| `@streq` | Low | Simple string comparison |
| `@contains` | Low | Substring search |
| `@startsWith` / `@endsWith` | Low | Prefix/suffix check |
| `@pm` | Medium | Case-insensitive phrase matching (pre-compiled) |
| `@rx` | High | PCRE regex (compiled on first use, cached) |

::: tip
Use `@pm` for simple keyword matching and `@rx` for complex patterns. `@pm` is significantly faster for lists of words.
:::

### PCRE JIT

Every `@rx` operator - and every other regex in Phirewall, from path and header filters to the bot presets - runs through PCRE, and PHP enables PCRE's just-in-time compiler by default (`pcre.jit=1`). Keep it enabled: without JIT each pattern falls back to the interpreter, which is noticeable when a full paranoia level evaluates on every request.

Two things can switch the JIT off silently:

- The `pcre.jit` ini setting was disabled.
- The PCRE library of the PHP build has no JIT support at all (`PCRE_JIT_SUPPORT` is `false`). This happens in some hardened environments that disallow the executable memory the JIT needs.

Make sure both hold in the environment your application actually runs in. Each PHP SAPI loads its own ini files, so the web server's PHP can be configured differently than the CLI.

## Best Practices

1. **Start with a minimal rule set.** Add rules incrementally and test each addition against your application's normal traffic to identify false positives.

2. **Use unique rule IDs.** Each rule must have a unique `id`. Use the OWASP convention: 9xxxxx for attack categories (942xxx for SQLi, 941xxx for XSS, etc.).

3. **Ban clients that keep probing.** When CRS is registered as a **blocklist** rule (the Quick Start above), an OWASP match is blocked (403) *before* Fail2Ban and Allow2Ban run, so neither counts it: a client sending only CRS-matching payloads is blocked on every request but never accumulates a ban inside Phirewall. (The **CRS fail2ban preset** is different: there the CRS match *is* the Fail2Ban filter, so it counts toward a ban directly - use it if you want repeat offenders banned without extra wiring.) To turn repeated CRS matches into a ban while keeping CRS as a blocklist, mirror the blocklist hits to your web server with an [infrastructure adapter](/advanced/infrastructure) (`blockOnBlocklist: true`), so the probing IP is rejected at the edge on its next request:

    ```php
    use Flowd\Phirewall\Infrastructure\InfrastructureBanListener;

    // Mirror every OWASP block to the web server, so a repeat offender is
    // rejected before reaching PHP on subsequent requests.
    $listener = new InfrastructureBanListener(
        infrastructureBlocker: $adapter,
        nonBlockingRunner: $runner,
        blockOnBlocklist: true,
    );
    ```

    The listener only mirrors once it is registered with your PSR-14 event dispatcher; see the [infrastructure adapter](/advanced/infrastructure) page for the full wiring.

    An Allow2Ban volume cap is a separate, blunter guard: it counts the requests that *pass* the OWASP layer and bans a client that crosses a hard request ceiling, independent of any CRS match.

    ```php
    $config->allow2ban->add('volume-cap',
        threshold: 100, period: 60, banSeconds: 86400,
    );
    ```

4. **Log matched rules.** Use the [observability](/advanced/observability) system to log which rules are triggering and tune accordingly.

5. **Keep rules in version control.** Store rule files alongside your application code and deploy them together.
