---
outline: deep
---

# Discriminator Normalizer

Phirewall provides two layers of key normalization to ensure consistent counting, prevent bypass attacks, and keep cache keys safe across all storage backends.

## Overview

When a request is evaluated, the key goes through two normalization stages:

1. **Discriminator Normalizer** (optional, user-configured) -- transforms the raw key before it reaches the cache key generator. Use this for domain-specific normalization like case-insensitive matching.
2. **Cache Key Generator** (automatic) -- rule names are sanitized to safe characters; user-extracted keys are SHA-256 hashed for collision-free, fixed-length cache keys.

## The Bypass Problem

Without normalization, attackers can bypass rate limiting by manipulating the key used for counting:

```
phirewall:throttle:api:<hash of "192.168.1.100">   ← Real IP
phirewall:throttle:api:<hash of "192.168.1.100 ">  ← Trailing space
phirewall:throttle:api:<hash of " 192.168.1.100">  ← Leading space
```

Each of these would produce a different SHA-256 hash and create a separate counter, effectively multiplying the attacker's rate limit. The discriminator normalizer prevents this by transforming keys before hashing.

## Setting a Discriminator Normalizer

Use `Config::setDiscriminatorNormalizer()` to apply a transformation to all discriminator keys (throttle, fail2ban, allow2ban, track) before they are used for cache lookups:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;

$config = new Config(new InMemoryCache());

// Case-insensitive key matching
$config->setDiscriminatorNormalizer(fn(string $key): string => strtolower(trim($key)));
```

The normalizer is a `Closure` that receives a string and returns a string. It is applied to every discriminator key extracted from requests before the cache key is generated.

### Parameters

| Method | Signature | Description |
|--------|-----------|-------------|
| `setDiscriminatorNormalizer()` | `Closure(string): string` | Set the normalizer for all keys |
| `getDiscriminatorNormalizer()` | returns `?Closure` | Get the current normalizer (null if none set) |

## How Cache Keys Are Generated

Phirewall's `CacheKeyGenerator` produces cache keys in this format:

```
{prefix}:{type}:{normalized_rule_name}:{hashed_key}
```

### Rule Name Normalization

Rule names are sanitized for safe use in cache keys:

1. **Trimmed** -- leading and trailing whitespace removed
2. **Sanitized** -- only `A-Za-z0-9._:-` characters are kept; all others replaced with `_`
3. **Deduplicated** -- consecutive underscores collapsed to one
4. **Truncated** -- names longer than 120 characters are shortened with a SHA-1 suffix
5. **Empty-safe** -- empty strings are replaced with `empty`

Rule names are memoized internally for performance.

### User Key Hashing

User-extracted keys (IP addresses, usernames, API keys, etc.) are hashed with SHA-256:

```
192.168.1.100 → a17c...e4f2 (64-character hex string)
```

This ensures:
- **Fixed length** -- regardless of input length, the cache key is always the same size
- **No special characters** -- hex output is always safe for any cache backend
- **Collision-free** -- SHA-256 has negligible collision probability
- **No memory leak** -- unlike memoized normalization, hashing is stateless and safe for long-running processes

### Examples

| Rule Name | Normalized |
|-----------|------------|
| `ip-limit` | `ip-limit` |
| `my rule with spaces` | `my_rule_with_spaces` |
| (empty string) | `empty` |
| (very long name) | `first_107_chars...-a1b2c3d4e5f6` |

| User Key | Cache Key Suffix |
|----------|-----------------|
| `192.168.1.100` | `a17c9a...` (SHA-256 hex) |
| `user@example.com` | `b4c3d2...` (SHA-256 hex) |
| (500-char User-Agent) | `f1e2d3...` (SHA-256 hex) |

## Common Normalizer Patterns

### Case-Insensitive Matching

The most common use case: ensure that `Admin` and `admin` hit the same counter.

```php
$config->setDiscriminatorNormalizer(fn(string $key): string => strtolower($key));
```

### Trim and Lowercase

Prevent whitespace and case variations from creating separate counters:

```php
$config->setDiscriminatorNormalizer(
    fn(string $key): string => strtolower(trim($key))
);
```

### Email Normalization

When rate limiting by email address (e.g., for password reset endpoints), normalize emails in the key extractor before they reach the discriminator normalizer:

```php
$config->throttles->add('password-reset',
    limit: 3, period: 3600,
    key: function ($req): ?string {
        if ($req->getUri()->getPath() !== '/api/password-reset') {
            return null;
        }

        $body = (array) $req->getParsedBody();
        $email = $body['email'] ?? null;
        if ($email === null) return null;

        // Normalize email before using as key
        $email = strtolower(trim($email));

        // Remove Gmail dots and plus addressing
        if (str_ends_with($email, '@gmail.com')) {
            [$local, $domain] = explode('@', $email, 2);
            $local = str_replace('.', '', $local);
            $local = explode('+', $local, 2)[0];
            $email = $local . '@' . $domain;
        }

        return 'email:' . $email;
    }
);
```

Without this normalization, an attacker could bypass password reset limits using:
- `user@gmail.com`
- `u.s.e.r@gmail.com`
- `user+tag1@gmail.com`
- `user+tag2@gmail.com`

All of these are the same Gmail inbox but would create different rate limit counters.

## Why It Matters

### Cache Backend Compatibility

Different cache backends have different key constraints:

| Backend | Key Limit | Unsafe Characters |
|---------|-----------|-------------------|
| Redis | 512 MB (practical: keep short) | None technically, but long keys waste memory |
| APCu | Varies by `apc.shm_size` | Control characters |
| PDO | 255 bytes (VARCHAR column) | Depends on collation |
| File-based | OS path limit (~260 chars) | `/`, `\`, `NUL` |
| Memcached | 250 bytes | Spaces, control characters |

SHA-256 hashing ensures user keys are always exactly 64 hex characters, safe across all backends.

### Security

Without normalization, user-supplied values (like User-Agent strings, API keys, or email addresses) could:

- **Enable bypass attacks** -- padding, encoding, or case variations create distinct keys for the same identity
- **Exhaust cache memory** -- long user-agents or query strings create bloated keys
- **Leak sensitive data** -- raw keys may appear in cache monitoring tools; hashed keys are opaque

## Discriminator Normalizer vs. Key Extractor Normalization

The discriminator normalizer and key extractor serve different purposes:

| Concern | Where to Handle | Example |
|---------|----------------|---------|
| Global consistency (case, trim) | `setDiscriminatorNormalizer()` | `strtolower()` |
| Domain-specific logic | Key extractor closure | Email deduplication, username canonicalization |
| Cache safety | Automatic (CacheKeyGenerator) | SHA-256 hashing, rule name sanitization |

Apply the discriminator normalizer for concerns that apply to all rules. Use the key extractor for rule-specific logic.

## Custom Key Prefixes

Use `$config->setKeyPrefix()` to change the prefix and avoid collisions when sharing a cache instance:

```php
$config->setKeyPrefix('myapp');
// Keys become: myapp:throttle:..., myapp:fail2ban:..., etc.
```

The prefix itself is validated -- it cannot be empty.

## Best Practices

1. **Set a discriminator normalizer early.** If you need case-insensitive matching, set the normalizer before adding rules. It applies globally to all rule types.

2. **Normalize application-level keys yourself.** The discriminator normalizer handles global concerns (case, trim). Domain-specific normalization (like email deduplication) should happen in your key closure.

3. **Use consistent key structures.** When writing custom key closures, prefix your keys to avoid collisions between different rule types: `user:123` instead of just `123`.

4. **Avoid sensitive data in keys.** While user keys are SHA-256 hashed in cache, the raw key is still visible in event payloads (`TrackHit`, `ThrottleExceeded`, etc.). Use hashed or anonymized identifiers when possible.
