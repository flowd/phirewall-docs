---
outline: deep
---

# Trusted Bots

Trusted bots are the beneficial crawlers you *want* visiting your site: search-engine
indexers such as Googlebot, Bingbot, Baidu, DuckDuckBot, Yandex, Yahoo (Slurp), and
Applebot. Letting them through keeps your pages indexed and discoverable. They are the
opposite of the crawlers you curb (aggressive scrapers and AI training bots).

The companion package [`flowd/phirewall-preset-bots`](/features/bot-presets) deliberately
**excludes** these search engines, because blocking them de-indexes your site. That package
does the opposite job: blocking AI crawlers and throttling aggressive SEO crawlers. Use it to
restrict unwanted traffic, and use the `TrustedBotMatcher` described here to recognise and
protect the wanted crawlers.

## The spoofing problem

A `User-Agent` header is forgeable. Any client can send `Googlebot` in its `User-Agent`, so
matching a trusted bot on the User-Agent alone is not a security control - it hands every
scraper a free pass.

`TrustedBotMatcher` solves this with **reverse + forward DNS verification**. For a request
claiming to be Googlebot it performs a reverse DNS lookup on the client IP, checks that the
resulting hostname ends in a trusted suffix (`.googlebot.com`), then performs a forward lookup
on that hostname and confirms it resolves back to the same IP. A genuine Googlebot request
passes all three steps; a spoofed one fails the rDNS check.

## Safelisting verified bots

Wire `TrustedBotMatcher` on the safelist to let verified crawlers bypass the rest of the
firewall:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\Rule\SafelistRule;
use Flowd\Phirewall\Matchers\TrustedBotMatcher;
use Flowd\Phirewall\Store\InMemoryCache;

$cache  = new InMemoryCache();          // use RedisCache in production
$config = new Config($cache);

$config->safelists->addRule(new SafelistRule(
    'trusted-bots',
    new TrustedBotMatcher(cache: $cache),
));
```

## Rate-limiting verified bots

Safelisting gives verified crawlers unlimited access. If a crawler is well-behaved but you
still want a ceiling on its request rate, throttle it instead of safelisting it.

Build a throttle whose key closure returns a key only for verified bots and `null` otherwise.
A `null` key skips the rule, so the limit applies exclusively to real, DNS-verified crawlers
and never touches ordinary visitors:

```php
use Flowd\Phirewall\Http\TrustedProxyResolver;

// Pass the IP resolver explicitly: standalone match() falls back to the
// REMOTE_ADDR peer, which behind a proxy is the proxy and never verifies a
// crawler. Reuse the resolver you registered via setIpResolver().
$proxyResolver = new TrustedProxyResolver(['10.0.0.0/8', '172.16.0.0/12']);

$trustedBots = new TrustedBotMatcher(
    cache: $cache,
    ipResolver: $proxyResolver->resolve(...),
);

$config->throttles->add(
    'trusted-bot-rate',
    limit: 60,
    period: 60,
    key: fn($request): ?string =>
        $trustedBots->match($request)->isMatch() ? 'trusted-bot' : null,
);
```

Calling `match()` on a matcher you hold yourself does **not** autowire the Config's IP resolver;
only `TrustedBotMatcher` instances registered as safelist or blocklist rules receive it during
evaluation. For a standalone `match()` in a throttle key closure, pass `ipResolver:` explicitly
(as above) so rDNS verification runs against the real client IP behind a proxy.

`match()` returns a `MatchResult`; check it with `->isMatch()`. The key you return decides how
the limit is bucketed:

- A constant like `'trusted-bot'` shares one bucket across every verified crawler (a global
  cap on all trusted bots combined).
- The client IP gives each verified crawler IP its own cap. The raw `REMOTE_ADDR` peer address
  is the connecting peer; behind a proxy or CDN that is the proxy's address. Keep proxy trust
  configured in one place: reuse the resolver instance you registered via `setIpResolver()` and
  return `$resolver->resolve($request)` from the key closure to bucket on the real client. Read
  `$request->getServerParams()['REMOTE_ADDR']` directly if you need the raw peer address.
- A per-bot token gives each crawler family a separate cap.

## Custom bots

To recognise your own crawlers, pass additional entries as the first `TrustedBotMatcher`
argument. Each entry pairs a User-Agent token with the hostname suffix its IPs must resolve to:

```php
new TrustedBotMatcher(
    [['ua' => 'mycompany-crawler', 'hostname' => '.crawler.mycompany.com']],
    cache: $cache,
);
```

The hostname suffix must start with a dot. The leading dot anchors the match to the domain
boundary, so `evil-crawler.mycompany.com.attacker.test` cannot pose as a subdomain of
`.crawler.mycompany.com`.

## DNS caching

Every verification does a reverse and a forward DNS lookup. Pass a PSR-16 cache so those
lookups are memoised: successful results are cached for 24 hours by default and negative
results for 5 minutes. Without a cache, every request from a candidate bot triggers live DNS
calls on the request path.

## Ordering

Place the trusted-bot safelist **before** your blocklists and throttles. Safelist rules run
first, so a verified crawler passes through before a scanner or suspicious-header rule can
catch it. If the blocklist ran first, a legitimate crawler could be blocked before
verification ever happened.
