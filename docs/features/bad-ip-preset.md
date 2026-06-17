---
outline: deep
---

# Bad-IP Blocklist Preset

Block requests from known malicious IP addresses. Shipped as the companion package
[`flowd/phirewall-preset-bad-ips`](https://github.com/flowd/phirewall-preset-bad-ips), which
bundles a public-domain snapshot of the [stamparm/ipsum](https://github.com/stamparm/ipsum)
threat feed and exposes it as a `PortableConfig` blocklist.

## Installation

```bash
composer require flowd/phirewall-preset-bad-ips
```

## Usage

```php
use Flowd\Phirewall\Config;
use Flowd\PhirewallPresetBadIps\Presets;

$config = (new Config($cache))->with(Presets::blocklist());
```

| Preset | Effect |
| --- | --- |
| `Presets::blocklist()` | Blocks requests whose client IP is in the bundled snapshot. |
| `Presets::track(period)` | Counts matches without blocking, to measure false positives first. |

## Updating the list

The snapshot is stamparm/ipsum `levels/3.txt` (addresses on at least three source blacklists),
public domain under The Unlicense. Refresh it with `bin/badip-import` (or the scheduled
`Bad-IP Update` workflow, which opens a pull request). A higher level means fewer false
positives:

```bash
bin/badip-import --level=4
```

## Limits

- **The blocklist keys on `REMOTE_ADDR`.** Behind a proxy or CDN, configure a trusted client-IP
  resolver on the `Config`, or it sees the proxy instead of the client.
- **A bundled snapshot goes stale** between refreshes, and a shared host or CGNAT address can be
  listed for one offender. Prefer a higher level, try `track()` first, and combine with your own
  allowlist by overriding the rule by name.
