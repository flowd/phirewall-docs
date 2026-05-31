---
outline: deep
---

# Presets

Presets are ready-to-use rule bundles for recurring scenarios, so you don't have to hand-write the same rules each time. Each preset is defined internally as a [`PortableConfig`](/advanced/portable-config) — plain, inspectable, serializable data — and exposed two ways:

- a factory returning a live `Config` (e.g. `Presets::apiRateLimiting($cache)`), and
- an accessor returning the underlying `PortableConfig` (e.g. `Presets::apiRateLimitingPortable()`), so you can serialize, diff, sign, or layer it.

Because presets ARE `Config`s, they layer with your own rules through [`Config::compose()` / `mergedWith()`](/advanced/config-composition), and every rule is namespaced `preset.<area>.*` so override-by-name is predictable.

## Usage

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Preset\Presets;

// A preset on its own (a Config requires a PSR-16 cache):
$config = Presets::apiRateLimiting($cache);

// Inspect / serialize the underlying portable schema:
$schema = Presets::apiRateLimitingPortable()->toArray();

// Layer a preset under your own Config — your rules win by name:
$config = Presets::loginProtection($cache)->mergedWith($myConfig);

// Stack several presets, then your overrides last:
$config = Config::compose(
    Presets::scannerBlocking($cache),
    Presets::sensitivePathBlocking($cache),
    Presets::apiRateLimiting($cache),
    $myConfig,
);
```

Both factory forms accept an optional PSR-14 event dispatcher as a second argument (`Presets::apiRateLimiting($cache, $dispatcher)`), so preset rules emit the same [observability events](/advanced/observability) as hand-written ones.

## Shipped presets

| Preset | Rules (namespaced `preset.<area>.*`) |
|--------|--------------------------------------|
| `apiRateLimiting()` | Per-client sliding-window throttles scoped to the `/api` prefix: `preset.api.burst` (20 req/1s) and `preset.api.sustained` (300 req/60s), keyed on client IP. |
| `loginProtection()` | `preset.login.throttle` (10 attempts/60s per IP on `/login`, sliding) and `preset.login.bruteforce` fail2ban (ban the IP for 15 min after 5 failures in 15 min). |
| `scannerBlocking()` | `preset.scanner.known-tools` (known scanner/exploit User-Agents) and `preset.scanner.suspicious-headers` (requests missing the standard browser `Accept` / `Accept-Language` / `Accept-Encoding` headers). |
| `sensitivePathBlocking()` | `preset.sensitive-path.probes` — pattern blocklist for `/.git`, `/.svn`, `/.hg`, `/.env*`, `/.aws/credentials`, `/.htpasswd`, `/.htaccess`, `/.DS_Store`. |

Each preset also has a `…Portable()` accessor returning the `PortableConfig`, and the generic `Presets::portable($name)` / `Presets::config($name, $cache)` resolve a preset by one of the `Presets::names()` constants.

## Conventions and overrides

- `apiRateLimiting()` scopes its throttles to the `/api` path prefix; `loginProtection()` scopes its login throttle to `/login`.
- The login fail2ban (`preset.login.bruteforce`) is **driven exclusively** by your login handler calling `$context->recordFailure(Presets::LOGIN_FAILURE_RULE)` after a failed authentication; that recorded-signal path bans on the rule's IP key and bypasses the filter. The rule uses a deliberately never-match filter so it cannot be tripped by any spoofable/forgeable request property — a forged marker header would otherwise let an attacker drive failures for an arbitrary client and, behind a shared proxy/CDN, ban everyone. See [Request Context](/advanced/request-context).
- Override any rule by composing the preset with your own `Config` that redefines the rule by the same name (later layer wins), or by rebuilding the `…Portable()` schema.
- IP-keyed rules resolve the client from `REMOTE_ADDR`. Behind a load balancer or CDN, layer your own throttle keyed on a trusted client IP (see `KeyExtractors::clientIp()` with a [`TrustedProxyResolver`](/getting-started#client-ip-behind-proxies)) or on the authenticated principal, overriding the preset rule by name.

> **Note:** `scannerBlocking()`'s `suspicious-headers` rule is the more aggressive of the two — some legitimate API clients, privacy tools, and embedded browsers also omit `Accept-*` headers. Drop or override it by name if your traffic includes non-browser clients.

## Versioning and update checks

`Presets::VERSION` identifies the bundled rule catalogue and is bumped whenever a preset's rule set changes in a way integrators should review. `Presets::version()` is a convenience accessor for the same value.

To surface "a newer ruleset is available", implement the `PresetUpdateChecker` interface against a source you trust and compare against `Presets::VERSION`:

```php
interface PresetUpdateChecker
{
    public function latestVersion(string $preset): ?string;
    public function isOutdated(string $preset, string $currentVersion): bool;
}
```

**Phirewall hardcodes no remote endpoint and performs no network I/O.** The shipped `NullPresetUpdateChecker` never reports an update (`latestVersion()` returns `null`, `isOutdated()` returns `false`). Wiring an actual source — a Packagist release feed, an internal config service, a versioned JSON document behind HTTPS, … — is the integrator's job: implement the interface and inject it where you build your `Config`.

## Example

See [`examples/31-presets.php`](https://github.com/flowd/phirewall/blob/main/examples/31-presets.php) for standalone use, inspecting a preset as portable data, composing a preset with a user `Config` (overriding a rule by name), and the version / update-check seam.

## Related pages

- [Config Composition](/advanced/config-composition) — how presets layer with your own rules.
- [Portable Config](/advanced/portable-config) — the data format every preset is built on.
- [Fail2Ban & Allow2Ban](/features/fail2ban) — the brute-force mechanism behind `loginProtection()`.
