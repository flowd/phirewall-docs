---
outline: deep
---

# Presets

Presets are ready-to-use rule bundles for recurring scenarios, so you don't have to hand-write the same rules each time. Each preset is a [`PortableConfig`](/advanced/portable-config) — plain, inspectable, serializable data you can diff, sign, or layer — returned by an accessor (e.g. `Presets::apiRateLimiting()`).

Materialize one or several onto your own cache with [`Config::combine()`](/advanced/config-composition); presets are pure data and never receive a cache. Every rule is namespaced `preset.<area>.*`, so a later layer that redefines it by name overrides predictably.

## Usage

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Preset\Presets;

// A preset on its own — combine it onto a Config you build with your cache:
$config = (new Config($cache))->combine(Presets::apiRateLimiting());

// Inspect / serialize the underlying portable schema:
$schema = Presets::apiRateLimiting()->toArray();

// Stack several presets, then your own rules last (later layers win by name):
$config = (new Config($cache))->combine(
    Presets::scannerBlocking(),
    Presets::sensitivePathBlocking(),
    Presets::apiRateLimiting(),
    $myPortable,
);
```

Preset rules emit the same [observability events](/advanced/observability) as hand-written ones — wire your PSR-14 dispatcher into the `Config` you combine onto (`new Config($cache, $dispatcher)`).

## Shipped presets

| Preset | Rules (namespaced `preset.<area>.*`) |
|--------|--------------------------------------|
| `apiRateLimiting()` | Per-client sliding-window throttles scoped to the `/api` prefix: `preset.api.burst` (20 req/1s) and `preset.api.sustained` (300 req/60s), keyed on client IP. |
| `loginProtection()` | `preset.login.throttle` (10 attempts/60s per IP on `/login`, sliding) and `preset.login.bruteforce` fail2ban (ban the IP for 15 min after 5 failures in 15 min). |
| `scannerBlocking()` | `preset.scanner.known-tools` (known scanner/exploit User-Agents) and `preset.scanner.suspicious-headers` (requests missing the standard browser `Accept` / `Accept-Language` / `Accept-Encoding` headers). |
| `sensitivePathBlocking()` | `preset.sensitive-path.probes` — pattern blocklist for `/.git`, `/.svn`, `/.hg`, `/.env*`, `/.aws/credentials`, `/.htpasswd`, `/.htaccess`, `/.DS_Store`. |

Resolve any preset by name with `Presets::get($name)` (a `PortableConfig`), passing one of the `Presets::names()` constants.

## Conventions and overrides

- `apiRateLimiting()` scopes its throttles to the `/api` path prefix; `loginProtection()` scopes its login throttle to `/login`.
- The login fail2ban (`preset.login.bruteforce`) is **driven exclusively** by your login handler calling `$context->recordFailure(Presets::LOGIN_FAILURE_RULE)` after a failed authentication; that recorded-signal path bans on the rule's IP key and bypasses the filter. The rule uses a deliberately never-match filter so it cannot be tripped by any spoofable/forgeable request property — a forged marker header would otherwise let an attacker drive failures for an arbitrary client and, behind a shared proxy/CDN, ban everyone. See [Request Context](/advanced/request-context).
- Override any rule by combining the preset with your own portable rules that redefine the rule by the same name (later layer wins), or by rebuilding the preset's schema.
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
