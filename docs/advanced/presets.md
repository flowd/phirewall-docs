---
outline: deep
---

# Presets

Presets are ready-to-use rule bundles for recurring scenarios, so you don't have to hand-write the same rules each time. Each preset is a [`PortableConfig`](/advanced/portable-config) returned by an accessor (e.g. `Presets::scannerBlocking()`): plain, inspectable, serializable data you can diff, sign, or layer. Every preset is a `ConfigLayer`, so it composes through the same `Config::with()` call as any other layer.

Apply one or several onto your own cache with [`Config::with()`](/advanced/config-composition); presets are pure data and never receive a cache. Every rule is namespaced `preset.<area>.*`, so a later layer that redefines it by name overrides predictably.

## Usage

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Preset\Presets;

// A preset on its own; apply it onto a Config you build with your cache:
$config = (new Config($cache))->with(Presets::scannerBlocking());

// Inspect / serialize the underlying portable schema:
$schema = Presets::scannerBlocking()->toArray();

// Stack several presets, then your own rules last (later layers win by name):
$config = (new Config($cache))->with(
    Presets::scannerBlocking(),
    Presets::sensitivePathBlocking(),
    $myPortable,
);
```

Preset rules emit the same [observability events](/advanced/observability) as hand-written ones; wire your PSR-14 dispatcher into the `Config` you apply onto (`new Config($cache, $dispatcher)`).

## Shipped presets

| Preset | Rules (namespaced `preset.<area>.*`) |
|--------|--------------------------------------|
| `scannerBlocking()` | `preset.scanner.known-tools` (known scanner/exploit User-Agents) and `preset.scanner.suspicious-headers` (requests missing the standard browser `Accept` / `Accept-Language` / `Accept-Encoding` headers). |
| `sensitivePathBlocking()` | `preset.sensitive-path.probes`: pattern blocklist for `/.git`, `/.svn`, `/.hg`, `/.env*`, `/.aws/credentials`, `/.htpasswd`, `/.htaccess`, `/.DS_Store`. |

Resolve any preset by name with `Presets::get($name)` (a `PortableConfig`), passing one of the `Presets::names()` constants.

## Conventions and overrides

- The shipped presets target signals that are universal across applications (scanner User-Agents, missing browser headers, well-known sensitive paths), so they assume nothing about your routing. A preset you build yourself is a `PortableConfig`, so it can key on whatever fits your environment, including routes your own apps standardize.
- Override any rule by applying the preset with your own portable rules that redefine the rule by the same name (later layer wins), or by rebuilding the preset's schema.

> **Note:** `scannerBlocking()`'s `suspicious-headers` rule is the more aggressive of the two: some legitimate API clients, privacy tools, and embedded browsers also omit `Accept-*` headers. Drop or override it by name if your traffic includes non-browser clients.

## Versioning and update checks

`Presets::VERSION` identifies the bundled rule catalogue and is bumped whenever a preset's rule set changes in a way integrators should review. `Presets::version()` is a convenience accessor for the same value.

Phirewall ships **no** update-check mechanism and performs **no** network I/O. To surface "a newer ruleset is available", compare `Presets::VERSION` against a release feed you trust (Packagist, an internal config service, a versioned JSON document behind HTTPS, and so on) with `version_compare()`:

```php
use Flowd\Phirewall\Preset\Presets;

// $latestFromYourFeed comes from a source YOU control and trust.
if (version_compare(Presets::VERSION, $latestFromYourFeed, '<')) {
    // A newer preset catalogue is available; review and upgrade phirewall.
}
```

Fetching `$latestFromYourFeed` is the integrator's job; phirewall hardcodes no remote endpoint.

## Example

See [`examples/31-presets.php`](https://github.com/flowd/phirewall/blob/main/examples/31-presets.php) for standalone use, inspecting a preset as portable data, composing a preset with a user `Config` (overriding a rule by name), and comparing `Presets::VERSION` against your own release feed with `version_compare()`.

## Related pages

- [Config Composition](/advanced/config-composition) - how presets layer with your own rules.
- [Portable Config](/advanced/portable-config) - the data format every preset is built on.
- [Fail2Ban & Allow2Ban](/features/fail2ban) - the brute-force ban mechanism.
