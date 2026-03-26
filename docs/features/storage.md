---
outline: deep
---

# Storage Backends

Phirewall uses PSR-16 (PHP Standard Recommendation for Simple Caching) compatible backends for storing counters and ban states. The choice of backend determines performance characteristics, persistence, and multi-server support.

All examples on this page assume `use Flowd\Phirewall\Config;` is imported.

## Comparison

| Backend | Persistence | Multi-Server | Atomic Counters | Latency | Best For |
|---------|:-----------:|:------------:|:---------------:|:-------:|----------|
| `InMemoryCache` | None | No | Yes | ~0 | Testing, development |
| `ApcuCache` | Process lifetime | No | Yes (native) | ~1 us | Single-server production |
| `RedisCache` | Full | Yes | Yes (Lua script) | ~100 us | Multi-server production |
| `PdoCache` | Full | Yes | Yes (upsert) | ~1 ms | Existing database, no Redis |
| Any PSR-16 | Varies | Varies | No | Varies | Custom integrations |

## InMemoryCache

A simple in-memory cache. Data is stored in a PHP array and lost when the process ends.

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;

$cache = new InMemoryCache();
$config = new Config($cache);
```

### Characteristics

- Zero external dependencies
- Data resets on every request in PHP-FPM (each request is a new process)
- Data persists for the lifetime of a long-running process (CLI, Swoole, RoadRunner)
- Implements both `CacheInterface` (PSR-16) and `CounterStoreInterface`
- Automatic expired entry purging every 1000 operations

### Testing with a Custom Clock

For deterministic testing, inject a custom clock to control time progression:

```php
use Flowd\Phirewall\Store\ClockInterface;

$clock = new class implements ClockInterface {
    private float $time;
    public function __construct() { $this->time = microtime(true); }
    public function now(): float { return $this->time; }
    public function advance(int $seconds): void { $this->time += $seconds; }
};

$cache = new InMemoryCache($clock);

// In your tests, advance time to simulate window expiry
$clock->advance(60); // Move forward 60 seconds
```

::: tip
`InMemoryCache` is the recommended backend for unit tests and integration tests. It requires no external services and provides deterministic behavior with the clock interface.
:::

### When to Use

- Unit tests and integration tests
- Development and prototyping
- Single-script CLI tools
- Long-running processes where per-process state is acceptable

### When NOT to Use

- PHP-FPM production (counters reset each request)
- Multi-server deployments (no shared state)

::: warning
In coroutine-based servers (Swoole), `InMemoryCache` may experience race conditions under high concurrency because it uses plain PHP arrays with no locking. Use `RedisCache` or `ApcuCache` for production Swoole deployments.
:::

## ApcuCache

High-performance in-process cache backed by the APCu PHP extension. Data is shared across all requests handled by the same PHP-FPM pool.

### Requirements

```bash
pecl install apcu
```

```ini
; php.ini
extension=apcu.so
apc.enable_cli=1  ; Required for CLI testing
```

### Usage

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\ApcuCache;

$cache = new ApcuCache();
$config = new Config($cache);
```

### Characteristics

- Shared memory within a single PHP-FPM pool
- Atomic counter operations via `apcu_inc()` / `apcu_add()`
- No network overhead (in-process memory access)
- Data lost on PHP-FPM restart or `opcache_reset()`
- Implements both `CacheInterface` and `CounterStoreInterface`

### Performance Tuning

```ini
; php.ini
apc.shm_size=128M      ; Shared memory size (default 32M)
apc.ttl=0              ; No automatic expiration (Phirewall handles TTL)
apc.gc_ttl=3600        ; Garbage collection TTL
apc.entries_hint=4096  ; Expected number of cache entries
```

### When to Use

- Single-server production deployments
- High-traffic applications where latency matters
- Environments where Redis is not available

### When NOT to Use

- Multi-server deployments (each server has its own APCu)
- Kubernetes with horizontal pod autoscaling (pods don't share APCu)

## RedisCache

Distributed cache using Redis via the Predis client library. Counters are incremented atomically using Lua scripts to prevent race conditions under high concurrency.

### Installation

```bash
composer require predis/predis
```

### Basic Usage

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\RedisCache;
use Predis\Client as PredisClient;

$redis = new PredisClient(getenv('REDIS_URL') ?: 'redis://localhost:6379');
$cache = new RedisCache($redis);
$config = new Config($cache);
```

### With Custom Namespace

Isolate keys when sharing a Redis instance across applications:

```php
$cache = new RedisCache($redis, 'myapp:firewall:');
```

### Connection Options

::: code-group

```php [TCP]
$redis = new PredisClient([
    'scheme' => 'tcp',
    'host' => 'redis.example.com',
    'port' => 6379,
    'password' => 'secret',
    'database' => 1,
]);
```

```php [Unix Socket]
$redis = new PredisClient([
    'scheme' => 'unix',
    'path' => '/var/run/redis/redis.sock',
]);
```

```php [Cluster]
$redis = new PredisClient([
    ['host' => 'node1.example.com', 'port' => 6379],
    ['host' => 'node2.example.com', 'port' => 6379],
], ['cluster' => 'redis']);
```

```php [Sentinel]
$redis = new PredisClient([
    ['host' => 'sentinel1.example.com', 'port' => 26379],
    ['host' => 'sentinel2.example.com', 'port' => 26379],
], [
    'replication' => 'sentinel',
    'service' => 'mymaster',
]);
```

:::

### Characteristics

- Shared state across all application servers
- Atomic counter increments via Lua scripts (no race conditions)
- Full persistence (survives restarts with Redis persistence enabled)
- Network latency per operation (~100-500 us depending on network)
- Implements both `CacheInterface` and `CounterStoreInterface`

### Fail-Open Behavior

RedisCache is designed to fail open. If Redis is unavailable, `increment()` returns `0`, which means no throttle or Fail2Ban rule will trigger. This prevents Redis outages from blocking all traffic to your application.

::: tip
In a production environment, monitor your Redis connection. A down Redis means your firewall rules are not being enforced.
:::

### When to Use

- Multi-server production deployments
- Kubernetes, Docker Swarm, or container orchestration
- Serverless environments (AWS Lambda, Google Cloud Functions)
- Any deployment where multiple processes need shared state

### When NOT to Use

- Simple single-server setups where APCu would be faster and simpler

## PdoCache

Database-backed cache using PDO for MySQL, PostgreSQL, and SQLite. PdoCache stores entries in a single table (`phirewall_cache` by default) with columns for the key, value, and expiry timestamp. The table is auto-created on first use when the database user has `CREATE TABLE` privileges.

### Supported Databases

| Database | Counter Strategy | Notes |
|----------|-----------------|-------|
| MySQL | Transaction + `ON DUPLICATE KEY UPDATE` | Compatible with MariaDB |
| PostgreSQL | `ON CONFLICT ... RETURNING` | Single atomic upsert |
| SQLite | `ON CONFLICT ... RETURNING` | Requires SQLite 3.35+ (PHP 8.1+ ships 3.36+) |

### Basic Usage

::: code-group

```php [SQLite]
use Flowd\Phirewall\Store\PdoCache;

// In-memory (testing)
$pdo = new PDO('sqlite::memory:');
$cache = new PdoCache($pdo);

// File-based (persistence across restarts)
$pdo = new PDO('sqlite:/var/lib/phirewall/cache.db');
$pdo->exec('PRAGMA journal_mode=WAL');
$cache = new PdoCache($pdo);
```

```php [MySQL]
use Flowd\Phirewall\Store\PdoCache;

$pdo = new PDO(
    'mysql:host=db.example.com;dbname=myapp',
    getenv('DB_USER'),
    getenv('DB_PASSWORD'),
);
$cache = new PdoCache($pdo);
```

```php [PostgreSQL]
use Flowd\Phirewall\Store\PdoCache;

$pdo = new PDO(
    'pgsql:host=db.example.com;dbname=myapp',
    getenv('DB_USER'),
    getenv('DB_PASSWORD'),
);
$cache = new PdoCache($pdo);
```

:::

### Custom Table Name

```php
$cache = new PdoCache($pdo, 'my_firewall_cache');

// Schema-qualified names are also supported
$cache = new PdoCache($pdo, 'myschema.firewall_cache');
```

### Table Schema

PdoCache auto-creates this table on first use:

```sql
CREATE TABLE IF NOT EXISTS phirewall_cache (
    cache_key VARCHAR(255) NOT NULL PRIMARY KEY,
    cache_value TEXT NOT NULL,
    expires_at BIGINT NULL
);
```

On MySQL, the `cache_key` column uses `CHARACTER SET ascii COLLATE ascii_bin` for case-sensitive matching.

If the database user lacks `CREATE TABLE` privileges, create the table manually before initializing PdoCache.

::: tip
For production, add an index on `expires_at` for efficient pruning:
```sql
CREATE INDEX idx_phirewall_expires ON phirewall_cache (expires_at);
```
:::

### Characteristics

- Shared state across all servers using the same database
- Automatic expired entry pruning (~1% of operations, limited to 1000 rows)
- Prepared statement caching for optimal performance
- Full persistence across application and server restarts
- Implements both `CacheInterface` and `CounterStoreInterface`
- No additional dependencies -- uses PHP's built-in PDO extension

### When to Use

- Applications that already have a database but no Redis
- Single-server deployments where APCu is not available
- Environments where you want persistence without adding infrastructure
- SQLite as a lightweight alternative for single-server setups

### When NOT to Use

- High-traffic applications where database latency is a concern (use Redis or APCu)
- Deployments where the database is already under heavy load

::: warning
PdoCache adds load to your database. Under high traffic, counter increments create significant write pressure. For high-throughput applications, prefer RedisCache or ApcuCache.
:::

## Using Any PSR-16 Cache

Phirewall works with any PSR-16 compatible cache implementation:

```php
// Symfony Cache
use Symfony\Component\Cache\Adapter\RedisAdapter;
use Symfony\Component\Cache\Psr16Cache;

$adapter = new RedisAdapter(RedisAdapter::createConnection('redis://localhost'));
$cache = new Psr16Cache($adapter);
$config = new Config($cache);
```

::: warning
Generic PSR-16 caches that do not implement `CounterStoreInterface` use a non-atomic read-modify-write pattern for counter increments. Under high concurrency, this can lead to inaccurate counts. For production use, prefer the bundled `RedisCache`, `ApcuCache`, or `PdoCache`.
:::

## CounterStoreInterface

The bundled storage backends implement `CounterStoreInterface` in addition to PSR-16:

```php
interface CounterStoreInterface
{
    /**
     * Increment a counter within a fixed time window.
     * Returns the new counter value.
     */
    public function increment(string $key, int $period): int;

    /**
     * Return the number of seconds remaining before the key expires.
     */
    public function ttlRemaining(string $key): int;
}
```

This interface enables atomic counter operations and precise TTL (Time To Live) reporting. All four bundled backends implement it: `InMemoryCache`, `ApcuCache`, `RedisCache`, and `PdoCache`.

## Decision Guide

```text
Need multi-server support?
  Yes --> Have Redis?
            Yes --> RedisCache
            No  --> Have a shared database?
                      Yes --> PdoCache
                      No  --> RedisCache (add it)
  No  --> Need persistence between requests?
            Yes --> APCu available?
                      Yes --> ApcuCache
                      No  --> PdoCache (SQLite) or RedisCache
            No  --> InMemoryCache (testing only)
```

| Environment | Recommended Backend |
|-------------|---------------------|
| Unit tests | `InMemoryCache` |
| Integration tests | `InMemoryCache` or `RedisCache` (Docker) |
| Development | `InMemoryCache` or `ApcuCache` |
| Single server | `ApcuCache` |
| Single server (no APCu) | `PdoCache` (SQLite) |
| Multiple servers | `RedisCache` |
| Multiple servers (no Redis) | `PdoCache` (MySQL/PostgreSQL) |
| Kubernetes | `RedisCache` |
| Serverless | `RedisCache` (external) |

## Cache Key Structure

Keys follow the format `{prefix}:{type}:{rule}:{normalized_key}`:

```
phirewall:throttle:ip-limit:192.168.1.100
phirewall:fail2ban:fail:login:192.168.1.100
phirewall:fail2ban:ban:login:192.168.1.100
phirewall:allow2ban:hit:high-volume:192.168.1.100
phirewall:allow2ban:ban:high-volume:192.168.1.100
phirewall:track:api-calls:user-123
```

Use `$config->setKeyPrefix('myapp')` to change the prefix and avoid collisions when sharing a cache instance.

See [Discriminator Normalizer](/advanced/discriminator-normalizer) for details on how keys are sanitized.

## Monitoring

### Redis

Redis keys have two layers of prefixing: the RedisCache namespace (default `Phirewall:`) and the firewall key prefix (default `phirewall`). For example, a throttle counter key looks like `Phirewall:phirewall:throttle:ip-limit:192.168.1.100`. You can change the Redis namespace via `new RedisCache($redis, 'custom:')` and the key prefix via `$config->setKeyPrefix('custom')`.

```bash
# Watch Phirewall keys in real-time
redis-cli monitor | grep Phirewall

# Count Phirewall keys (use SCAN in production -- see warning below)
redis-cli keys "Phirewall:*" | wc -l

# Check memory usage
redis-cli info memory

# Check a specific counter
redis-cli get "Phirewall:phirewall:throttle:ip-limit:192.168.1.100"
redis-cli ttl "Phirewall:phirewall:throttle:ip-limit:192.168.1.100"
```

::: danger
The `KEYS` command scans every key in Redis and blocks the server during execution. **Never use `KEYS` in production.** Use `SCAN` with a cursor instead:
```bash
redis-cli --scan --pattern "Phirewall:*" | wc -l
```
:::

### APCu

```php
$iterator = new APCuIterator('/^phirewall:/');
foreach ($iterator as $item) {
    printf("%s = %s (TTL: %ds)\n",
        $item['key'],
        print_r($item['value'], true),
        $item['ttl']
    );
}
```

### PDO (Database)

```sql
-- Count active entries
SELECT COUNT(*) FROM phirewall_cache WHERE expires_at IS NULL OR expires_at > UNIX_TIMESTAMP();

-- View throttle counters
SELECT cache_key, cache_value, expires_at
FROM phirewall_cache
WHERE cache_key LIKE '%throttle%'
ORDER BY cache_key;

-- Manual cleanup of expired entries
DELETE FROM phirewall_cache WHERE expires_at IS NOT NULL AND expires_at <= UNIX_TIMESTAMP();
```

::: tip
For SQLite, use `strftime('%s', 'now')` instead of `UNIX_TIMESTAMP()`. For PostgreSQL, use `EXTRACT(EPOCH FROM NOW())::bigint`.
:::
