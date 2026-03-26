---
outline: deep
---

# Installation & Quick Start

Get Phirewall running in your PHP application in five minutes.

## Prerequisites

- PHP 8.2 or higher
- Composer
- A PSR-7 (PHP Standard Recommendation for HTTP Messages) / PSR-15 (PHP Standard Recommendation for HTTP Server Middleware) compatible application. Most modern PHP frameworks support these standards, including Slim, Mezzio, Laravel, and Symfony. If you are using plain PHP, you will need a PSR-7 implementation such as `nyholm/psr7`.

## Installation

```bash
composer require flowd/phirewall
```

### Optional Dependencies

```bash
# PSR-7 implementation (needed for the examples below)
composer require nyholm/psr7

# For Redis-backed distributed counters (multi-server)
composer require predis/predis

# For Monolog logging integration
composer require monolog/monolog
```

::: tip
**APCu**: Enable the PHP extension and set `apc.enable_cli=1` for CLI testing.
:::

## Step 1: Choose a Storage Backend

Phirewall needs a PSR-16 (PHP Standard Recommendation for Simple Caching) cache for storing counters and ban states. Pick the backend that fits your deployment.

::: code-group

```php [InMemoryCache (Dev/Test)]
use Flowd\Phirewall\Store\InMemoryCache;

$cache = new InMemoryCache();
```

```php [Redis (Multi-Server)]
use Flowd\Phirewall\Store\RedisCache;
use Predis\Client as PredisClient;

$redis = new PredisClient(getenv('REDIS_URL') ?: 'redis://localhost:6379');
$cache = new RedisCache($redis, 'myapp:firewall:');
```

```php [APCu (Single Server)]
use Flowd\Phirewall\Store\ApcuCache;

// Requires ext-apcu and apc.enable_cli=1 for CLI
$cache = new ApcuCache();
```

```php [PDO (MySQL/PostgreSQL/SQLite)]
use Flowd\Phirewall\Store\PdoCache;

// SQLite (file-based persistence)
$pdo = new PDO('sqlite:/var/lib/phirewall/cache.db');
$pdo->exec('PRAGMA journal_mode=WAL');
$cache = new PdoCache($pdo);

// MySQL or PostgreSQL (shared across servers)
// $pdo = new PDO('mysql:host=db.example.com;dbname=myapp', $dbUser, $dbPassword);
// $cache = new PdoCache($pdo);
```

:::

See [Storage Backends](/features/storage) for a detailed comparison.

## Step 2: Create Configuration

```php
use Flowd\Phirewall\Config;

$config = new Config($cache);

// Optional: Set a key prefix to avoid collisions
$config->setKeyPrefix('myapp');
```

The `Config` constructor accepts:

| Parameter | Type | Description |
|-----------|------|-------------|
| `$cache` | `CacheInterface` | Any PSR-16 cache for counters and ban states |
| `$eventDispatcher` | `?EventDispatcherInterface` | Optional [PSR-14](https://www.php-fig.org/psr/psr-14/) (Event Dispatching) dispatcher for [observability](/advanced/observability) |
| `$clock` | `?ClockInterface` | Optional clock for deterministic testing |

## Step 3: Define Rules

All imports needed for the examples below:

```php
use Flowd\Phirewall\KeyExtractors;
```

### Safelists (Allow Trusted Traffic)

Safelisted requests bypass all other rules. Use them for health checks, internal monitoring, and other trusted traffic.

```php
$config->safelists->add('health', fn($req) => $req->getUri()->getPath() === '/health');
$config->safelists->add('metrics', fn($req) => $req->getUri()->getPath() === '/metrics');

// Safelist specific IPs or CIDR ranges
$config->safelists->ip('office', ['10.0.0.0/8', '192.168.1.0/24']);

// Safelist verified search engine bots (Googlebot, Bingbot, etc.)
$config->safelists->trustedBots();
```

### Blocklists (Deny Malicious Traffic)

Blocklisted requests are immediately rejected with `403 Forbidden`.

```php
// Block WordPress admin probes
$config->blocklists->add('scanner-probe', fn($req) => str_starts_with($req->getUri()->getPath(), '/admin-panel'));

// Block phpMyAdmin probes
$config->blocklists->add('pma-probe', fn($req) => str_contains($req->getUri()->getPath(), 'phpmyadmin'));

// Block specific IPs or CIDR ranges
$config->blocklists->ip('bad-actors', ['198.51.100.0/24']);

// Block known vulnerability scanners by User-Agent
$config->blocklists->knownScanners();

// Block requests missing standard browser headers
$config->blocklists->suspiciousHeaders();
```

### Throttling (Rate Limiting)

Throttled requests receive `429 Too Many Requests` with a `Retry-After` header.

```php
// 100 requests per minute per IP
$config->throttles->add('ip-minute', limit: 100, period: 60, key: KeyExtractors::ip());

// Sliding window (prevents double-burst at window boundaries)
$config->throttles->sliding('api-sliding', limit: 100, period: 60, key: KeyExtractors::ip());

// Multi-window (burst + sustained limits in a single call)
$config->throttles->multi('api', [
    1  => 5,    // 5 req/s burst limit
    60 => 100,  // 100 req/min sustained limit
], KeyExtractors::ip());

// Dynamic limits based on request properties
$config->throttles->add('role-based',
    limit: fn($req) => $req->getHeaderLine('X-Role') === 'admin' ? 1000 : 100,
    period: 60,
    key: KeyExtractors::ip()
);

// Enable standard rate limit headers
$config->enableRateLimitHeaders();
```

See [Rate Limiting](/features/rate-limiting) and [Dynamic Throttle](/advanced/dynamic-throttle) for advanced usage.

### Fail2Ban (Brute Force Protection)

Automatically ban clients after repeated failures. The filter evaluates each incoming request; matching requests increment a failure counter, and the client is banned when the threshold is reached.

```php
// Ban IPs that POST to /login more than 5 times in 5 minutes
$config->fail2ban->add('login-abuse',
    threshold: 5,
    period: 300,
    ban: 3600,
    filter: fn($req) => $req->getMethod() === 'POST'
        && $req->getUri()->getPath() === '/login',
    key: KeyExtractors::ip()
);
```

For post-handler failure signaling (e.g., recording failures after verifying credentials), see [Request Context](/advanced/request-context).

### Allow2Ban (Request Volume Banning)

Allow2Ban is the inverse of Fail2Ban: it counts every request for a key and bans after a threshold, without needing a filter predicate.

```php
// Ban any IP that sends more than 1000 requests in 60 seconds
$config->allow2ban->add('high-volume',
    threshold: 1000,
    period: 60,
    banSeconds: 3600,
    key: KeyExtractors::ip()
);
```

See [Fail2Ban & Allow2Ban](/features/fail2ban) for details.

### Track (Passive Monitoring)

Track rules count requests passively without blocking. Use them for dashboards, alerting, and analytics.

```php
$config->tracks->add('login-attempts',
    period: 3600,
    filter: fn($req) => $req->getUri()->getPath() === '/login' && $req->getMethod() === 'POST',
    key: KeyExtractors::ip()
);

// Track with a threshold for alerting
$config->tracks->add('suspicious-burst',
    period: 60,
    filter: fn($req) => $req->getUri()->getPath() === '/login',
    key: KeyExtractors::ip(),
    limit: 10, // TrackHit event includes thresholdReached flag at 10+ hits
);
```

::: tip
Track rules never block requests. They fire `TrackHit` events via the PSR-14 event dispatcher for observability. See [Track & Notifications](/advanced/track-notifications) for details.
:::

## Step 4: Create Middleware

```php
use Flowd\Phirewall\Middleware;

$middleware = new Middleware($config);
```

The `Middleware` constructor auto-detects your PSR-17 (PHP Standard Recommendation for HTTP Factories) response factory. If auto-detection fails, pass one explicitly:

```php
use Nyholm\Psr7\Factory\Psr17Factory;

$middleware = new Middleware($config, new Psr17Factory());
```

You can also configure response bodies with PSR-17 factories:

```php
$psr17Factory = new Psr17Factory();
$config->usePsr17Responses($psr17Factory, $psr17Factory);
```

See [PSR-17 Factories](/advanced/psr17) for custom response configuration.

## Step 5: Add to Your Application

::: code-group

```php [PSR-15]
// Any PSR-15 compatible stack (Mezzio, custom dispatchers, etc.)
// The middleware from Step 4 plugs directly into your pipeline.
$app->pipe($middleware);
```

```php [Symfony]
// 1. Install the PSR-15 bridge:
//    composer require symfony/psr-http-message-bridge nyholm/psr7
//
// 2. Create src/Factory/PhirewallFactory.php:

namespace App\Factory;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\ApcuCache;
use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Message\ServerRequestInterface;

class PhirewallFactory
{
    public function create(): Middleware
    {
        // ApcuCache requires ext-apcu (zero config, single-server)
        // For multi-server: use RedisCache with predis/predis
        $cache  = new ApcuCache();
        $config = new Config($cache);
        $config->enableRateLimitHeaders();

        // Safelists
        $config->safelists->add('health',
            fn(ServerRequestInterface $req): bool =>
                $req->getUri()->getPath() === '/health'
        );
        $config->safelists->add('profiler',
            fn(ServerRequestInterface $req): bool =>
                str_starts_with($req->getUri()->getPath(), '/_profiler')
        );
        $config->safelists->trustedBots(cache: $cache);

        // Blocklists
        $config->blocklists->knownScanners();
        $config->blocklists->suspiciousHeaders();

        // Fail2Ban
        $config->fail2ban->add('login-abuse',
            threshold: 5, period: 300, ban: 3600,
            filter: fn(ServerRequestInterface $req): bool =>
                $req->getMethod() === 'POST'
                && $req->getUri()->getPath() === '/login',
            key: KeyExtractors::ip()
        );

        // Rate limiting
        $config->throttles->add('burst',
            limit: 30, period: 5,
            key: KeyExtractors::ip()
        );
        $config->throttles->add('global',
            limit: 1000, period: 60,
            key: KeyExtractors::ip()
        );

        $psr17 = new Psr17Factory();
        $config->usePsr17Responses($psr17, $psr17);

        return new Middleware($config, $psr17);
    }
}

// 3. Register in config/services.yaml:
//    services:
//        Flowd\Phirewall\Middleware:
//            factory: ['@App\Factory\PhirewallFactory', 'create']
//
// 4. Create src/EventSubscriber/PhirewallSubscriber.php:

namespace App\EventSubscriber;

use Flowd\Phirewall\Middleware as PhirewallMiddleware;
use Nyholm\Psr7\Factory\Psr17Factory;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

class PhirewallSubscriber implements EventSubscriberInterface
{
    public function __construct(
        private readonly PhirewallMiddleware $middleware,
    ) {}

    public static function getSubscribedEvents(): array
    {
        return [KernelEvents::REQUEST => ['onKernelRequest', 256]];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $psr17 = new Psr17Factory();
        $psrFactory = new PsrHttpFactory($psr17, $psr17, $psr17, $psr17);
        $httpFoundationFactory = new HttpFoundationFactory();

        $psrRequest  = $psrFactory->createRequest($event->getRequest());
        $psrResponse = $this->middleware->process(
            $psrRequest,
            new class ($psr17) implements \Psr\Http\Server\RequestHandlerInterface {
                public function __construct(private readonly Psr17Factory $responseFactory) {}
                public function handle(
                    \Psr\Http\Message\ServerRequestInterface $request,
                ): \Psr\Http\Message\ResponseInterface {
                    return $this->responseFactory->createResponse(200);
                }
            }
        );

        if ($psrResponse->getStatusCode() !== 200) {
            $event->setResponse(
                $httpFoundationFactory->createResponse($psrResponse)
            );
        }
    }
}
```

```php [Laravel]
// 1. Create app/Providers/PhirewallServiceProvider.php:

namespace App\Providers;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware as PhirewallMiddleware;
use Flowd\Phirewall\Store\ApcuCache;
use Illuminate\Support\ServiceProvider;
use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Message\ServerRequestInterface;

class PhirewallServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(PhirewallMiddleware::class, function () {
            // ApcuCache requires ext-apcu (zero config, single-server)
            // For multi-server: use RedisCache with predis/predis
            $cache = new ApcuCache();

            $config = new Config($cache);
            $config->setKeyPrefix(config('app.name', 'laravel'));
            $config->enableRateLimitHeaders();

            // Safelists
            $config->safelists->add('health',
                fn(ServerRequestInterface $req): bool =>
                    $req->getUri()->getPath() === '/health'
            );
            $config->safelists->trustedBots(cache: $cache);

            // Blocklists
            $config->blocklists->knownScanners();
            $config->blocklists->suspiciousHeaders();

            // Fail2Ban
            $config->fail2ban->add('login-abuse',
                threshold: 5, period: 300, ban: 3600,
                filter: fn(ServerRequestInterface $req): bool =>
                    $req->getMethod() === 'POST'
                    && $req->getUri()->getPath() === '/login',
                key: KeyExtractors::ip()
            );

            // Rate limiting
            $config->throttles->add('burst',
                limit: 30, period: 5,
                key: KeyExtractors::ip()
            );
            $config->throttles->add('global',
                limit: 1000, period: 60,
                key: KeyExtractors::ip()
            );

            $psr17 = new Psr17Factory();
            $config->usePsr17Responses($psr17, $psr17);

            return new PhirewallMiddleware($config, $psr17);
        });
    }
}

// 2. Register in bootstrap/app.php (Laravel 11+):
//    ->withMiddleware(function (Middleware $middleware) {
//        $middleware->prepend(\Flowd\Phirewall\Middleware::class);
//    })
//
// Or in app/Http/Kernel.php (Laravel 10):
//    protected $middleware = [
//        \Flowd\Phirewall\Middleware::class,
//        // ...
//    ];
```

```php [Slim]
// Slim uses LIFO middleware ordering.
// Add Phirewall LAST so it executes FIRST (outermost).

use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware as PhirewallMiddleware;
use Flowd\Phirewall\Store\ApcuCache;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Factory\AppFactory;

$app = AppFactory::create();

// ApcuCache requires ext-apcu (zero config, single-server)
// For multi-server: use RedisCache with predis/predis
$cache  = new ApcuCache();
$config = new Config($cache);
$config->enableRateLimitHeaders();

// Safelists
$config->safelists->add('health',
    fn(ServerRequestInterface $req): bool =>
        $req->getUri()->getPath() === '/health'
);
$config->safelists->trustedBots(cache: $cache);

// Blocklists
$config->blocklists->knownScanners();
$config->blocklists->suspiciousHeaders();

// Fail2Ban
$config->fail2ban->add('login-abuse',
    threshold: 5, period: 300, ban: 3600,
    filter: fn(ServerRequestInterface $req): bool =>
        $req->getMethod() === 'POST'
        && $req->getUri()->getPath() === '/login',
    key: KeyExtractors::ip()
);

// Rate limiting
$config->throttles->add('burst',
    limit: 30, period: 5,
    key: KeyExtractors::ip()
);
$config->throttles->add('global',
    limit: 1000, period: 60,
    key: KeyExtractors::ip()
);

// Add Phirewall LAST (Slim LIFO = executes first)
$app->add(new PhirewallMiddleware($config));

// ... define routes ...
$app->run();
```

```php [Mezzio]
// Mezzio uses PSR-15 natively -- pipe Phirewall first.

// In config/autoload/phirewall.global.php:
// return [
//     'dependencies' => [
//         'factories' => [
//             \Flowd\Phirewall\Middleware::class =>
//                 \App\Factory\PhirewallMiddlewareFactory::class,
//         ],
//     ],
// ];

// src/App/Factory/PhirewallMiddlewareFactory.php:

namespace App\Factory;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware as PhirewallMiddleware;
use Flowd\Phirewall\Store\ApcuCache;
use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ServerRequestInterface;

class PhirewallMiddlewareFactory
{
    public function __invoke(ContainerInterface $container): PhirewallMiddleware
    {
        // ApcuCache requires ext-apcu (zero config, single-server)
        // For multi-server: use RedisCache with predis/predis
        $cache = new ApcuCache();

        $config = new Config($cache);
        $config->enableRateLimitHeaders();

        // Safelists
        $config->safelists->add('health',
            fn(ServerRequestInterface $req): bool =>
                $req->getUri()->getPath() === '/health'
        );
        $config->safelists->trustedBots(cache: $cache);

        // Blocklists
        $config->blocklists->knownScanners();
        $config->blocklists->suspiciousHeaders();

        // Fail2Ban
        $config->fail2ban->add('login-abuse',
            threshold: 5, period: 300, ban: 3600,
            filter: fn(ServerRequestInterface $req): bool =>
                $req->getMethod() === 'POST'
                && $req->getUri()->getPath() === '/login',
            key: KeyExtractors::ip()
        );

        // Rate limiting
        $config->throttles->add('burst',
            limit: 30, period: 5,
            key: KeyExtractors::ip()
        );
        $config->throttles->add('global',
            limit: 1000, period: 60,
            key: KeyExtractors::ip()
        );

        $psr17 = new Psr17Factory();
        $config->usePsr17Responses($psr17, $psr17);

        return new PhirewallMiddleware($config, $psr17);
    }
}

// In config/pipeline.php:
// $app->pipe(\Flowd\Phirewall\Middleware::class); // outermost
// $app->pipe(\Mezzio\Router\Middleware\RouteMiddleware::class);
// $app->pipe(\Mezzio\Router\Middleware\DispatchMiddleware::class);
```

:::

> **Middleware ordering:** Ensure Phirewall runs as the outermost middleware so it executes before your application handles the request. See the [Examples](/examples#framework-integration) page for more detailed, production-ready integrations.

## Complete Example

Here is a full, runnable example you can copy into a file and execute immediately. Requires `nyholm/psr7` (`composer require nyholm/psr7`):

```php
<?php

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

// 1. Setup cache
$cache = new InMemoryCache();

// 2. Configure firewall
$config = new Config($cache);
$config->setKeyPrefix('demo');
$config->enableRateLimitHeaders();

// Safelist health endpoint
$config->safelists->add('health', fn($req) => $req->getUri()->getPath() === '/health');

// Block suspicious paths
$config->blocklists->add('scanner-probe', fn($req) => str_starts_with($req->getUri()->getPath(), '/admin-panel'));

// Block known vulnerability scanners
$config->blocklists->knownScanners();

// Rate limit: 10 requests per minute per IP
$config->throttles->add('ip-limit', limit: 10, period: 60, key: KeyExtractors::ip());

// Fail2Ban: Ban IPs that POST to /login more than 3 times in 2 minutes
$config->fail2ban->add('login',
    threshold: 3,
    period: 120,
    ban: 300,
    filter: fn($req) => $req->getMethod() === 'POST'
        && $req->getUri()->getPath() === '/login',
    key: KeyExtractors::ip()
);

// 3. Create middleware
$middleware = new Middleware($config, new Psr17Factory());

// 4. Your application handler
$handler = new class implements RequestHandlerInterface {
    public function handle(ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface
    {
        return new Response(200, ['Content-Type' => 'text/plain'], "Hello, World!\n");
    }
};

// 5. Process a request
$request = new ServerRequest('GET', '/api/users', [], null, '1.1', ['REMOTE_ADDR' => '192.168.1.100']);
$response = $middleware->process($request, $handler);

echo "Status: " . $response->getStatusCode() . "\n";
// Output: Status: 200
```

## Evaluation Order

Phirewall evaluates rules in a strict, deterministic order. The first match wins.

```text
Request --> Track (passive) --> Safelist --> Blocklist --> Fail2Ban --> Throttle --> Allow2Ban --> Pass
                                   |            |             |            |            |
                                   v            v             v            v            v
                                 Allow        403           403          429          403
```

The evaluation order is:

1. **Track** rules are always evaluated first (passive counting, never blocks)
2. **Safelist** -- if matched, the request bypasses all remaining checks
3. **Blocklist** -- if matched, the request is rejected with `403`
4. **Fail2Ban** -- if the client is already banned, `403`; if the filter matches, increment failure counter
5. **Throttle** -- if the counter exceeds the limit, `429` with `Retry-After`
6. **Allow2Ban** -- if the client has exceeded the request threshold, `403` with `Retry-After`
7. **Pass** -- the request reaches your application

## Fail-Open / Fail-Closed

By default, Phirewall fails open: if the cache backend is unavailable or throws an exception, the request is allowed through and the error is dispatched as a `FirewallError` event for logging.

```php
// Fail-open (default): requests pass through on errors
$config->setFailOpen(true);

// Fail-closed: exceptions propagate, resulting in 500 errors
// Use only when blocking is more important than availability
$config->setFailOpen(false);
```

## Response Headers

Blocked responses always include `Retry-After` where applicable. Diagnostic `X-Phirewall` headers are opt-in:

```php
$config->enableResponseHeaders();
```

| Header | Opt-in | Description |
|--------|--------|-------------|
| `X-Phirewall` | Yes | Block type: `blocklist`, `throttle`, `fail2ban`, or `allow2ban` |
| `X-Phirewall-Matched` | Yes | Name of the rule that triggered |
| `X-Phirewall-Safelist` | Yes | Name of the safelist rule that matched |
| `Retry-After` | No | Seconds until the rate limit window resets (429 and allow2ban only) |

::: warning
Diagnostic headers reveal internal rule names and firewall topology. Only enable them in development or staging environments.
:::

Enable `$config->enableRateLimitHeaders()` for standard rate limit headers on every response:

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Configured request limit |
| `X-RateLimit-Remaining` | Remaining requests in window |
| `X-RateLimit-Reset` | Seconds until window resets |

## Client IP Behind Proxies

When your application sits behind a load balancer or CDN (Content Delivery Network), `REMOTE_ADDR` contains the proxy IP, not the client IP. Use `TrustedProxyResolver` to extract the real client IP safely:

```php
use Flowd\Phirewall\Http\TrustedProxyResolver;
use Flowd\Phirewall\KeyExtractors;

$resolver = new TrustedProxyResolver([
    '10.0.0.0/8',      // Internal network
    '172.16.0.0/12',   // Docker
    '192.168.0.0/16',  // Private ranges
]);

// Use as a key extractor for any rule
$config->throttles->add('api', limit: 100, period: 60,
    key: KeyExtractors::clientIp($resolver)
);

// Or set globally so all IP-aware matchers use it
$config->setIpResolver(KeyExtractors::clientIp($resolver));
```

::: warning
Never trust `X-Forwarded-For` without configuring trusted proxies. An attacker can spoof this header to bypass rate limiting.
:::

## First Test

Verify your setup works by sending requests:

```bash
# Should pass (200)
curl -i http://localhost:8080/api/users

# Should be blocked (403) if you have a scanner-probe blocklist
curl -i http://localhost:8080/admin-panel

# Should be safelisted (200, no rate limit counted)
curl -i http://localhost:8080/health
```

## Next Steps

- Learn about [Safelists & Blocklists](/features/safelists-blocklists)
- Configure [Rate Limiting](/features/rate-limiting)
- Set up [Fail2Ban & Allow2Ban](/features/fail2ban) for brute force protection
- Explore [Storage Backends](/features/storage) for production
- Add [Observability](/advanced/observability) for monitoring
- Use [Request Context](/advanced/request-context) for post-handler failure signaling
- Browse [Examples](/examples) for complete, copy-pasteable configurations
