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

## Caching expensive preset data

This section only matters when you build a preset that parses a large data source on construction - a rule-set file, an IP feed. The shipped presets parse no such sources and need no cache. Because a `Config` is built on every request under PHP-FPM, such parsing would run per request; `Flowd\Phirewall\Support\CompiledDataCache` removes that cost with a two-level cache for `var_export`-able plain data:

```php
use Flowd\Phirewall\Support\CompiledDataCache;

// The underlying primitive; in a preset matcher the instance
// arrives via CompiledDataCacheAware instead (see below).
$cache = new CompiledDataCache($cacheDirectory);
$sourceFiles = glob($rulesPath . '/*.conf') ?: [];

$ruleData = $cache->load(
    'my-preset-rules',                          // developer-defined identifier
    $sourceFiles,                               // newest mtime invalidates the cache
    fn(): array => parseRuleFiles($sourceFiles) // runs only on a cache miss
);
// $ruleData is the plain array your preset builds its matchers from.
```

The first level memoizes per process, so a warm PHP-FPM worker pays no parsing cost after its first request. The second level persists a compiled PHP artifact in the given directory and loads it via `include`, so OPcache serves it from shared memory even for cold workers. Editing a source file rebuilds on the next request; long-running workers (FrankenPHP, RoadRunner, Swoole) can additionally drop the in-process level with `CompiledDataCache::clearProcessCache()` when a deployment does not change the source mtimes.

The cache stores only plain arrays: cache the parsed data your objects are built from, not the objects themselves, and rebuild the objects from the returned array on each load. A builder returning anything but scalars, `null`, or nested arrays makes `load()` throw an `InvalidArgumentException` - unlike the silently degrading cache failures (an unwritable directory, a corrupt artifact), this surfaces a programming error instead of reviving objects through `__set_state()`.

The artifact is executed as PHP, so the directory needs the same trust as a compiled DI container: use a framework cache directory outside the web root, writable by the PHP-FPM user - for example `var/cache/phirewall` in TYPO3 or Symfony, `storage/framework/phirewall` in Laravel.

Wiring is a single integrator step:

```php
$config->setCompiledDataCache(new CompiledDataCache($cacheDirectory));
```

The cache travels as Config infrastructure (composition inherits it from the base layer, like the PSR-16 store). A preset matcher that builds its data lazily implements `Flowd\Phirewall\Matchers\CompiledDataCacheAware`; the `Firewall` hands the cache to every aware matcher, filter, and throttle scope before evaluation - mirroring how `ClientIpResolverAware` late-binds the IP resolver. Without a configured cache nothing is injected and the matcher builds its data directly, so caching stays an opt-in feature with no per-package wiring.

## Example

See [`examples/31-presets.php`](https://github.com/flowd/phirewall/blob/main/examples/31-presets.php) for standalone use, inspecting a preset as portable data, composing a preset with a user `Config` (overriding a rule by name), and comparing `Presets::VERSION` against your own release feed with `version_compare()`.

## Related pages

- [Config Composition](/advanced/config-composition) - how presets layer with your own rules.
- [Portable Config](/advanced/portable-config) - the data format every preset is built on.
- [Fail2Ban & Allow2Ban](/features/fail2ban) - the brute-force ban mechanism.
