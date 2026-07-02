---
outline: deep
---

# Bot & AI Crawler Presets

Block AI crawlers and rate-limit aggressive SEO crawlers. Shipped as the companion package
[`flowd/phirewall-preset-bots`](https://github.com/flowd/phirewall-preset-bots) - `PortableConfig`
presets you materialize with `Config::with()`.

## Installation

```bash
composer require flowd/phirewall-preset-bots
```

## Usage

```php
use Flowd\Phirewall\Config;
use Flowd\PhirewallPresetBots\Presets;

$config = (new Config($cache))->with(
    Presets::blockAiCrawlers(),                 // 403 for AI/LLM crawlers
    Presets::throttleSeoCrawlers(limit: 60, period: 60),  // rate-limit SEO crawlers per IP
);
```

| Preset | Effect |
| --- | --- |
| `Presets::blockAiCrawlers()` | Blocks requests whose `User-Agent` matches a known AI/LLM crawler. |
| `Presets::throttleAiCrawlers(limit, period)` | Rate-limits AI crawlers per client IP; keeps the site indexable. |
| `Presets::throttleSeoCrawlers(limit, period)` | Rate-limits aggressive SEO/marketing crawlers per client IP. |

The matched tokens are curated in `CrawlerCatalog` (GPTBot, ClaudeBot, CCBot, PerplexityBot,
Bytespider, Meta-ExternalAgent, and more for AI; AhrefsBot, SemrushBot, DotBot, and more for
SEO). General search and link-preview agents (Googlebot, bingbot, Applebot, facebookexternalhit)
are deliberately excluded, as are robots.txt-only opt-out tokens like `Google-Extended`.

## Limits

- **User-Agent matching is policy enforcement, not a security control.** It stops crawlers that
  send a truthful `User-Agent`; a hostile scraper can send anything. Use the
  [OWASP CRS](/features/owasp-crs) and [rate limiting](/features/rate-limiting) presets for
  hostile traffic.
- **Throttles key on the resolved client IP.** These presets use `PortableConfig::keyIp()`, which late-binds
  to the evaluating `Config`'s IP resolver (falling back to `REMOTE_ADDR` when none is set). Behind a proxy or CDN,
  set the resolver once on your config and every preset throttle keys on the correct client IP automatically:
  ```php
  $config->setIpResolver((new \Flowd\Phirewall\Http\TrustedProxyResolver(['10.0.0.1']))->resolve(...));
  ```
  Without a configured resolver, all clients behind the proxy bucket together on the proxy address.
- The catalogue is opinionated; override a rule by name to keep a crawler you value.
