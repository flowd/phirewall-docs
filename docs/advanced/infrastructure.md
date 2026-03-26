---
outline: deep
---

# Infrastructure Adapters

Phirewall can mirror application-level blocks to web server infrastructure, providing defense-in-depth by blocking malicious IPs before they reach your PHP application.

## Why Infrastructure-Level Blocking?

Application-level firewalls run inside PHP, which means every blocked request still consumes PHP-FPM resources. By mirroring bans to the web server layer (Apache, Nginx), subsequent requests from banned IPs are rejected before reaching PHP -- saving CPU, memory, and reducing attack surface.

```text
Request --> Web Server (.htaccess) --> PHP-FPM --> Phirewall Middleware
                 |                                        |
                 v (if banned)                            v (if banned)
              403 (fast, no PHP)                       403 (PHP processed)
```

Phirewall detects and bans at the application level first. The `InfrastructureBanListener` then propagates those bans to the web server for fast rejection on subsequent requests.

## InfrastructureBlockerInterface

All infrastructure adapters implement this interface:

```php
namespace Flowd\Phirewall\Infrastructure;

interface InfrastructureBlockerInterface
{
    public function blockIp(string $ipAddress): void;
    public function unblockIp(string $ipAddress): void;
    public function isBlocked(string $ipAddress): bool;
}
```

| Method | Description |
|--------|-------------|
| `blockIp($ip)` | Add an IP to the infrastructure block list. Idempotent. |
| `unblockIp($ip)` | Remove an IP from the block list. Idempotent. |
| `isBlocked($ip)` | Check whether an IP is currently blocked. |

All methods throw `InvalidArgumentException` for invalid IPs and `RuntimeException` on I/O errors.

## Apache .htaccess Adapter

The built-in `ApacheHtaccessAdapter` maintains a managed section in Apache `.htaccess` files using `Require not ip` directives (mod_authz_core, Apache 2.4+).

### Requirements

- Apache 2.4+ with `mod_authz_core`
- Write permissions to the `.htaccess` file
- `AllowOverride AuthConfig` (or `All`) in the Apache VirtualHost configuration

### Basic Usage

```php
use Flowd\Phirewall\Infrastructure\ApacheHtaccessAdapter;

$adapter = new ApacheHtaccessAdapter('/var/www/app/public/.htaccess');

// Block an IP
$adapter->blockIp('192.168.1.100');
$adapter->blockIp('2001:db8::1');  // IPv6 supported

// Unblock an IP
$adapter->unblockIp('192.168.1.100');

// Check status
if ($adapter->isBlocked('192.168.1.100')) {
    echo "IP is blocked at the server level\n";
}
```

### Batch Operations

The adapter also provides `blockMany()` and `unblockMany()` for atomic batch updates (single file write):

```php
// Block multiple IPs atomically
$adapter->blockMany([
    '192.168.1.100',
    '192.168.1.101',
    '10.0.0.50',
    '2001:db8::5',
]);

// Unblock multiple IPs atomically
$adapter->unblockMany([
    '192.168.1.100',
    '192.168.1.101',
]);
```

### Generated .htaccess Section

The adapter manages only the content between the `# BEGIN Phirewall` and `# END Phirewall` markers. All other content is preserved:

```apache
# Your custom rules (preserved)
RewriteEngine On
RewriteRule ^(.*)$ index.php [L]

# BEGIN Phirewall
Require not ip 192.168.1.101
Require not ip 10.0.0.50
Require not ip 2001:db8::1
# END Phirewall

# More custom rules (preserved)
Options -Indexes
```

### Safety Features

- **Atomic writes** -- writes to a temporary file first, then renames it (POSIX atomic operation), preserving permissions
- **IP validation** -- all IPs are validated with `filter_var()` before writing; IPv6 addresses are normalized to canonical form to prevent duplicates
- **Content preservation** -- only the managed section between markers is modified; all other `.htaccess` content is untouched
- **Idempotent operations** -- blocking an already-blocked IP is a no-op; duplicates in batch operations are deduplicated
- **All-or-nothing semantics** -- in `blockMany()`/`unblockMany()`, all IPs are validated before any file modification; if one IP is invalid, the entire operation is rejected

## Automatic Event Integration

Use `InfrastructureBanListener` to automatically mirror Phirewall bans to the web server via PSR-14 events.

```php
use Flowd\Phirewall\Infrastructure\InfrastructureBanListener;

new InfrastructureBanListener(
    InfrastructureBlockerInterface $infrastructureBlocker,
    NonBlockingRunnerInterface $nonBlockingRunner,
    bool $blockOnFail2Ban = true,
    bool $blockOnBlocklist = false,
    ?callable $keyToIp = null,
    ?callable $requestToIp = null,
)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `$infrastructureBlocker` | `InfrastructureBlockerInterface` | -- | The adapter to push blocks to |
| `$nonBlockingRunner` | `NonBlockingRunnerInterface` | -- | How to execute the adapter call |
| `$blockOnFail2Ban` | `bool` | `true` | Mirror Fail2Ban bans |
| `$blockOnBlocklist` | `bool` | `false` | Mirror blocklist hits (request IP) |
| `$keyToIp` | `?callable` | identity | Map a Fail2Ban key to an IP (default: assumes key is an IP) |
| `$requestToIp` | `?callable` | `KeyExtractors::ip()` | Extract IP from a `ServerRequestInterface` |

### Wiring with PSR-14

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Infrastructure\ApacheHtaccessAdapter;
use Flowd\Phirewall\Infrastructure\InfrastructureBanListener;
use Flowd\Phirewall\Infrastructure\SyncNonBlockingRunner;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Flowd\Phirewall\Events\BlocklistMatched;
use Psr\EventDispatcher\EventDispatcherInterface;

$adapter = new ApacheHtaccessAdapter('/var/www/app/public/.htaccess');
$runner = new SyncNonBlockingRunner();

$listener = new InfrastructureBanListener(
    infrastructureBlocker: $adapter,
    nonBlockingRunner: $runner,
    blockOnFail2Ban: true,     // Mirror Fail2Ban bans
    blockOnBlocklist: false,   // Don't mirror every blocklist hit
);

// Wire to your PSR-14 dispatcher
$dispatcher = new class ($listener) implements EventDispatcherInterface {
    public function __construct(private InfrastructureBanListener $listener) {}

    public function dispatch(object $event): object
    {
        if ($event instanceof Fail2BanBanned) {
            $this->listener->onFail2BanBanned($event);
        }
        if ($event instanceof BlocklistMatched) {
            $this->listener->onBlocklistMatched($event);
        }
        return $event;
    }
};

$config = new Config($cache, $dispatcher);
```

### How It Works

1. Phirewall bans an IP via Fail2Ban (application-level, stored in cache)
2. A `Fail2BanBanned` event is dispatched via PSR-14
3. `InfrastructureBanListener` receives the event
4. The listener calls `$adapter->blockIp()` via the non-blocking runner
5. Subsequent requests from that IP are blocked by Apache before reaching PHP

::: tip
The listener swallows exceptions from the adapter to avoid affecting request processing. Infrastructure blocking is a best-effort optimization, not a hard requirement.
:::

## NonBlockingRunner

Infrastructure operations (file writes) can be delegated to avoid blocking request processing:

```php
interface NonBlockingRunnerInterface
{
    /** @param callable():void $task */
    public function run(callable $task): void;
}
```

### SyncNonBlockingRunner

Executes tasks synchronously. Simplest option, fine for most setups where `.htaccess` writes are fast:

```php
use Flowd\Phirewall\Infrastructure\SyncNonBlockingRunner;

$runner = new SyncNonBlockingRunner();
```

### Custom Async Runners

For high-traffic environments where file I/O during request handling adds noticeable latency:

::: code-group

```php [ReactPHP]
use Flowd\Phirewall\Infrastructure\NonBlockingRunnerInterface;

$runner = new class ($loop) implements NonBlockingRunnerInterface {
    public function __construct(private LoopInterface $loop) {}

    public function run(callable $task): void
    {
        $this->loop->futureTick($task);
    }
};
```

```php [Queue-Based]
use Flowd\Phirewall\Infrastructure\NonBlockingRunnerInterface;

$runner = new class ($queue) implements NonBlockingRunnerInterface {
    public function __construct(private QueueInterface $queue) {}

    public function run(callable $task): void
    {
        $this->queue->push(new ClosureJob($task));
    }
};
```

:::

## Building Custom Adapters

Implement `InfrastructureBlockerInterface` to integrate with any web server or WAF.

### Nginx Example

```php
use Flowd\Phirewall\Infrastructure\InfrastructureBlockerInterface;

class NginxBlocklistAdapter implements InfrastructureBlockerInterface
{
    public function __construct(
        private string $blocklistPath,
        private string $reloadCommand = 'nginx -s reload',
    ) {}

    public function blockIp(string $ipAddress): void
    {
        $current = $this->readBlocklist();
        if (!in_array($ipAddress, $current, true)) {
            $current[] = $ipAddress;
            $this->writeBlocklist($current);
            $this->reload();
        }
    }

    public function unblockIp(string $ipAddress): void
    {
        $current = $this->readBlocklist();
        $filtered = array_values(array_filter(
            $current,
            fn(string $ip) => $ip !== $ipAddress
        ));
        if (count($filtered) !== count($current)) {
            $this->writeBlocklist($filtered);
            $this->reload();
        }
    }

    public function isBlocked(string $ipAddress): bool
    {
        return in_array($ipAddress, $this->readBlocklist(), true);
    }

    /** @return list<string> */
    private function readBlocklist(): array
    {
        if (!file_exists($this->blocklistPath)) {
            return [];
        }
        preg_match_all('/deny\s+([^;]+);/',
            file_get_contents($this->blocklistPath) ?: '', $matches);
        return array_map('trim', $matches[1] ?? []);
    }

    /** @param list<string> $ips */
    private function writeBlocklist(array $ips): void
    {
        $content = "# Phirewall blocklist - auto-generated\n";
        foreach ($ips as $ip) {
            $content .= "deny {$ip};\n";
        }
        file_put_contents($this->blocklistPath, $content);
    }

    private function reload(): void
    {
        exec($this->reloadCommand);
    }
}
```

The generated Nginx blocklist file can be included in your server block:

```nginx
# /etc/nginx/conf.d/phirewall-blocklist.conf
# (auto-generated by NginxBlocklistAdapter)
deny 192.168.1.100;
deny 203.0.113.50;
```

```nginx
server {
    listen 80;
    include /etc/nginx/conf.d/phirewall-blocklist.conf;
    # ...
}
```

### Redis Shared Blocklist

For blocking across multiple web servers in a cluster:

```php
use Flowd\Phirewall\Infrastructure\InfrastructureBlockerInterface;

class RedisBlocklistAdapter implements InfrastructureBlockerInterface
{
    public function __construct(
        private \Predis\Client $redis,
        private string $setKey = 'phirewall:blocked_ips',
    ) {}

    public function blockIp(string $ipAddress): void
    {
        $this->redis->sadd($this->setKey, [$ipAddress]);
    }

    public function unblockIp(string $ipAddress): void
    {
        $this->redis->srem($this->setKey, $ipAddress);
    }

    public function isBlocked(string $ipAddress): bool
    {
        return (bool) $this->redis->sismember($this->setKey, $ipAddress);
    }
}
```

## Complete Integration Example

A full setup combining Fail2Ban, infrastructure mirroring, and rate limiting:

```php
<?php

declare(strict_types=1);

use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\RedisCache;
use Flowd\Phirewall\Infrastructure\ApacheHtaccessAdapter;
use Flowd\Phirewall\Infrastructure\InfrastructureBanListener;
use Flowd\Phirewall\Infrastructure\SyncNonBlockingRunner;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Psr\EventDispatcher\EventDispatcherInterface;
use Predis\Client as PredisClient;

// Setup
$redis = new PredisClient(getenv('REDIS_URL') ?: 'redis://localhost:6379');
$cache = new RedisCache($redis);
$htaccess = new ApacheHtaccessAdapter('/var/www/app/public/.htaccess');

$infraListener = new InfrastructureBanListener(
    infrastructureBlocker: $htaccess,
    nonBlockingRunner: new SyncNonBlockingRunner(),
    blockOnFail2Ban: true,
    blockOnBlocklist: false,
);

$dispatcher = new class ($infraListener) implements EventDispatcherInterface {
    public function __construct(private InfrastructureBanListener $listener) {}

    public function dispatch(object $event): object
    {
        if ($event instanceof Fail2BanBanned) {
            $this->listener->onFail2BanBanned($event);
        }
        return $event;
    }
};

$config = new Config($cache, $dispatcher);

// Login brute force protection with infrastructure mirroring
$config->fail2ban->add('login-abuse',
    threshold: 5, period: 300, ban: 3600,
    filter: fn($req) => $req->getMethod() === 'POST'
        && $req->getUri()->getPath() === '/login',
    key: KeyExtractors::ip()
);

// Standard rate limiting
$config->throttles->add('global',
    limit: 100, period: 60,
    key: KeyExtractors::ip()
);

$middleware = new Middleware($config);
```

## Troubleshooting

### Apache: 403 Forbidden for All Requests

Check `.htaccess` syntax:

```bash
apachectl configtest
```

Verify the managed section has valid directives. If the file is corrupted, delete the section between `# BEGIN Phirewall` and `# END Phirewall` markers.

### Apache: Require Directive Not Recognized

Enable `mod_authz_core`:

```bash
a2enmod authz_core
systemctl restart apache2
```

### Permission Denied Writing .htaccess

Ensure the file is writable by the web server user:

```bash
chown www-data:www-data /var/www/app/public/.htaccess
chmod 644 /var/www/app/public/.htaccess
```

### IPv6 Addresses Not Blocking

Ensure Apache is listening on IPv6:

```apache
Listen 80
Listen [::]:80
```

## Best Practices

1. **Only mirror Fail2Ban bans, not every blocklist hit.** Blocklist rules evaluate patterns that may change frequently. Fail2Ban bans are deliberate and worth persisting at the infrastructure level.

2. **Test in staging first.** Infrastructure changes affect all traffic. Verify your `.htaccess` integration works before deploying to production.

3. **Monitor the block list size.** Accumulated bans can grow the `.htaccess` file over time. Implement a periodic cleanup process or use Fail2Ban's `ban` duration to naturally expire bans.

4. **Use async runners in high-traffic environments.** File writes during request processing add latency. Use a queue-based runner for asynchronous updates.

5. **Validate your IP resolver.** If Fail2Ban keys are not raw IPs (e.g., using a composite key), provide a `keyToIp` callable to extract the IP correctly.
