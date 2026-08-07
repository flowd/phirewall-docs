# Performance

Phirewall runs on every request, so its cost matters. This page shows what a
`decide()` call costs in isolation, what that means under load, and what is
left of it inside a real application. The short version: a typical rule set
costs single-digit **microseconds** per request, OWASP CRS costs a
**millisecond or two**, and a blocked request is cheaper than a served one.

## Engine cost per request

Measured with the engine alone: 20,000 `decide()` calls per scenario after
warmup, `InMemoryCache` store, PHP 8.5 with OPcache and PCRE JIT, Apple
M-series laptop. The rule set is the Quick Start shape: one safelist, the
known-scanners blocklist, one path blocklist, one fail2ban, one allow2ban,
one throttle.

| Scenario | Outcome | Cost per request | Requests/sec (one core) |
|----------|---------|-----------------:|------------------------:|
| No rules at all (engine floor) | pass | 1.6 us | 640,000 |
| 6 rules, nothing matches (normal traffic) | pass | 8.1 us | 123,000 |
| 6 rules, safelist match (early exit) | safelisted | 1.4 us | 740,000 |
| 6 rules, blocklist match: scanner UA | blocked (403) | 1.9 us | 520,000 |
| 6 rules, blocklist match: path | blocked (403) | 3.2 us | 316,000 |
| 6 rules, fail2ban match below threshold | blocked (403) | 7.8 us | 129,000 |
| 6 rules, key already banned | blocked (403) | 5.2 us | 193,000 |
| 6 rules, throttle exceeded | throttled (429) | 8.7 us | 115,000 |

Two things stand out:

- **The expensive case is normal traffic**, because a request that matches
  nothing is checked against every rule. Matches exit early and are cheaper.
- **Attackers are the cheap case.** A blocklist match costs 2 to 3 us, and a
  banned key is decided by a single store lookup. The requests you block never
  reach your application, so under attack the firewall saves far more time
  than it costs.

Absolute numbers depend on your hardware and PHP build. Reproduce them on
your own machine with the bundled benchmarks:

```bash
XDEBUG_MODE=off php examples/20-rule-benchmarks.php   # rule scenarios
XDEBUG_MODE=off php examples/13-benchmarks.php        # store backends
```

## Store cost

The table above uses the in-process `InMemoryCache`. The counter rules
(fail2ban, allow2ban, throttle, track) are the ones that talk to the
[store](/features/storage): every request pays one ban lookup per ban-capable
rule, and requests a counter rule matches additionally pay a counter write.
The same scenarios per store, measured inside a Docker setup where Redis and
MariaDB run as separate containers:

| Scenario (6 rules) | InMemory | APCu | Redis | PDO/MySQL |
|--------------------|---------:|-----:|------:|----------:|
| Nothing matches (2 ban lookups) | 6 us | 6 us | 111 us | 110 us |
| Throttle counting a request | 8 us | 8 us | 213 us | 667 us |
| fail2ban match (403, counter write) | 5 us | 6 us | 160 us | 661 us |
| Key already banned (403) | 4 us | 4 us | 52 us | 55 us |

How to read it: APCu behaves like in-memory - shared counters on one server
at no measurable cost. The network stores pay roughly 50 us per round trip,
so reads (ban lookups, the every-request cost) sit around 0.1 ms for both.
Writes separate them: a Redis counter update is one round trip (~0.2 ms),
MySQL pays transaction and durability overhead (~0.7 ms). Even the worst
case - every request writing a counter through PDO/MySQL - stays under one
millisecond. Since bans decide on the read path, an attack wave hits the
cheap lookup, not the write.

## OWASP CRS cost

The [CRS preset](/features/owasp-crs) evaluates a few hundred ModSecurity
rules per request, most of them regular expressions over your request
parameters, so its cost scales with the number and size of arguments:

| Request shape (paranoia level 1, no match) | Cost per request |
|--------------------------------------------|-----------------:|
| GET without parameters | ~0.1 ms |
| GET with 3 query parameters | ~1.0 ms |
| POST with 8 form fields | ~2.4 ms |
| SQL injection attempt (matches, early exit) | ~0.4 ms |

Parsing the rule files costs a few milliseconds once; with the
[compiled data cache](/features/owasp-crs#caching) that price is paid on the
first request after a deployment, not on every request. Combining CRS with a
fail2ban preset also pays off here: once a probing client is banned, the CRS
engine no longer runs for it - the request is rejected by the cheap
banned-key lookup from the table above.

## What that means under load

Cost per request times requests per second gives the CPU share the firewall
needs. For the two typical setups:

| Sustained load | 6 rules (~8 us) | CRS PL1 (~1 ms) |
|----------------|----------------:|----------------:|
| 10 req/s | 0.008% of one core | 1% of one core |
| 100 req/s | 0.08% of one core | 10% of one core |
| 1,000 req/s | 0.8% of one core | one full core |

Rule-of-thumb: counting rules are free at any realistic load; give CRS a
thought once you serve hundreds of uncached requests per second, and scope it
to the routes that need it if you do.

## Inside a real application

Measured end to end on a TYPO3 site (Docker, Apache + mod_php 8.4, cached
page, median of 400 requests per run), once per store:

| Scenario | APCu | Redis | PDO/MySQL |
|----------|-----:|------:|----------:|
| Firewall middleware removed | 9.1 ms | | |
| Firewall active, 6 rules, nothing matches | 9.6 ms | 9.9 ms | 10.0 ms |
| Blocklist match (scanner user agent, 403) | 6.7 ms | | |
| Banned key (403) | 5.4 ms | 6.4 ms | 5.9 ms |

The no-match overhead on a cached page is well under a millisecond, and the
store differences drown in run-to-run noise - even with every ban lookup
going through MySQL. On uncached pages the overhead disappears entirely next
to rendering time. And the blocked cases respond *faster* than the page
itself: the request is stopped in the middleware before routing, rendering,
or content queries run.

## Keeping it fast

- **OPcache on** (it is on virtually every production setup): the firewall is
  plain PHP and profits like the rest of your code.
- **PCRE JIT on** (`pcre.jit=1`, the PHP default): every regex filter and the
  CRS `@rx` operators rely on it. See
  [PCRE JIT](/features/owasp-crs#pcre-jit).
- **Compiled data cache** for preset packages, so CRS and bad-IP data are not
  re-parsed per request. See
  [Caching expensive preset data](/advanced/presets#caching-expensive-preset-data).
- **Pick the store deliberately**: APCu for a single server (as fast as
  in-memory), Redis when counters and bans must be shared (~0.1 ms of ban
  lookups per request, ~0.2 ms per counter write). PDO/MySQL works without
  extra infrastructure and stays under a millisecond even on counter writes,
  but it puts firewall traffic on your database.
- **Scope expensive rules.** A throttle with a `scope` filter skips its
  counter work for requests outside the scope, and CRS can be registered for
  the routes that actually take user input.
