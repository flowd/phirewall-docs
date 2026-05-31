---
outline: deep
---

# Config Composition

Real deployments rarely have a single source of firewall rules. A vendor ships a baseline, an environment (staging vs. production) adds its own rules, a tenant overrides a few, and a single deployment applies a last-minute tweak. `Config::compose()` (and the fluent `Config::mergedWith()`) merges these layers into one effective `Config` — **without mutating any input** — so each layer can be owned, versioned, and shipped independently, often as a [`PortableConfig`](/advanced/portable-config).

## Usage

```php
use Flowd\Phirewall\Config;

// Each layer is built independently — frequently rebuilt from a PortableConfig.
$vendorBaseline   = $vendorPortable->toConfig($cache);   // shared product defaults
$environmentLayer = $envPortable->toConfig($cache);      // staging vs. production
$tenantLayer      = $tenantPortable->toConfig($cache);   // per-customer policy
$deploymentTweak  = (new Config($cache))->setFailOpen(false);

// Later layers win. These two calls are equivalent:
$effective = $vendorBaseline->mergedWith($environmentLayer, $tenantLayer, $deploymentTweak);
$effective = Config::compose($vendorBaseline, $environmentLayer, $tenantLayer, $deploymentTweak);
```

`compose()` is static and reads as "base first, overlays after"; `mergedWith()` is the instance form for when you already hold the base. Both return a fresh `Config`; the base and every overlay are left untouched.

| Form | Signature | Reads as |
|------|-----------|----------|
| `Config::compose(...$configs)` | static, variadic | base first, overlays after |
| `$base->mergedWith(...$overlays)` | instance, variadic | overlays applied onto `$base` |

## Merge semantics

Overlays are applied left to right, so **later sources win**.

| Aspect | Rule |
|--------|------|
| **Rules** (safelists, blocklists, throttles, fail2ban, allow2ban, tracks) | Merged **by name** within each section. A later same-named rule **replaces** the earlier one in place (base ordering preserved); genuinely new names are appended. A union, never duplicates. |
| **Pattern backends** | Merged by name with the same later-wins rule. |
| **`enabled`** | **Last layer wins (fail-safe)**: the composed value is the `enabled` state of the highest-priority (last) layer. An explicit `enable()` / `disable()` / `setEnabled()` on the winning layer always takes effect, so an ambiguous composition is never left silently disabled. |
| **Other scalar / object options** (`keyPrefix`, `failOpen`, the response-header toggles, the IP resolver, the discriminator normalizer, the response factories) | **Last explicit value wins**: the value comes from the last layer whose value differs from the field default. A layer that left an option at its default never clobbers an explicit choice from an earlier layer. |
| **Infrastructure** (PSR-16 cache, PSR-14 event dispatcher, clock) | Inherited from the **base** layer; overlays do not override it. |

### Why "last explicit value wins"?

A `Config` does not track which options were *set* versus *left at their default*. Composition therefore treats "still at the field default" as "no opinion": only a value that differs from the default counts as an explicit choice that can override an earlier layer. This is what lets a thin overlay add a single rule without silently resetting the baseline's `keyPrefix` or `failOpen` policy back to the defaults.

### Limitation: an overlay cannot reset a toggle to its default

Because "default-valued" is read as "no opinion", an overlay **cannot turn a toggle back off** once an earlier layer turned it on. If the vendor baseline calls `enableResponseHeaders()` (changing the toggle from its `false` default to `true`), a tenant overlay that leaves the toggle at `false` will *not* switch it back off — its `false` is indistinguishable from "unspecified", so the baseline's explicit `true` wins. The same applies to `failOpen` and the other boolean toggles. (`enabled` is the deliberate exception — see its row above — it uses last-layer-wins, so a later layer *can* re-assert it.)

If you need a later layer to *force* a non-default option back to the default, do not rely on composition: build the final `Config` and set the option explicitly after composing, e.g. `Config::compose(...)->setFailOpen(true)`.

## Example

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;

$effective = $vendorBaseline->mergedWith($environmentOverlay, $tenantOverlay, $deploymentTweak);

// Rules unioned by name, base ordering preserved:
$effective->blocklists->rules();   // ['scanners' (tenant wins), 'bad-net', 'admin-probe', ...]
$effective->allow2ban->rules();    // ['volume-cap'] contributed by the tenant overlay

// Last-explicit-wins options:
$effective->getKeyPrefix();          // 'deploy-eu-1'  (last layer that set it)
$effective->isFailOpen();            // false          (only the deployment layer set it)
$effective->responseHeadersEnabled(); // true          (set by the environment overlay)

$firewall = new Firewall($effective);
```

See [`examples/30-config-composition.php`](https://github.com/flowd/phirewall/blob/main/examples/30-config-composition.php) for a full vendor → environment → tenant → deployment walkthrough that prints an overridden-by-name rule, the unioned rule sets, and the last-wins options, then proves the composed firewall enforces every layer while leaving the inputs unchanged.

## Related pages

- [Portable Config](/advanced/portable-config) — ship each layer as serializable data.
- [Presets](/advanced/presets) — bundled `Config`s designed to be composed under your own rules.
- [Getting Started](/getting-started) — the base `Config` and its options.
