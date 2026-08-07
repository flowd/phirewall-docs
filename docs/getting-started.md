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

Phirewall needs a PSR-16 (PHP Standard Recommendation for Simple Caching) cache for storing counters and ban states. Pick the backend that fits your deployment. If you are trying Phirewall locally, start with `InMemoryCache`; choose a shared backend (Redis or PDO) before production.

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

Every safelist, blocklist, throttle, fail2ban, and track callback receives the incoming PSR-7 `ServerRequestInterface`, so you can branch on the path, method, headers, and so on. The snippets below use the `$config` from Step 2; the `$req` parameter is that request.

### Safelists (Allow Trusted Traffic)

Safelisted requests bypass all other rules. Use them for health checks, internal monitoring, and other trusted traffic.

```php
use Flowd\Phirewall\Config\Rule\SafelistRule;
use Flowd\Phirewall\Matchers\TrustedBotMatcher;

$config->safelists->add('health', fn($req) => $req->getUri()->getPath() === '/health');
$config->safelists->add('metrics', fn($req) => $req->getUri()->getPath() === '/metrics');

// Safelist specific IPs or CIDR ranges
$config->safelists->ip('office', ['10.0.0.0/8', '192.168.1.0/24']);

// Safelist verified search engine bots (Googlebot, Bingbot, etc.). The matcher uses the
// Config's IP resolver automatically; in production also pass a PSR-16 cache to skip
// repeat reverse-DNS lookups (see Bot Detection).
$config->safelists->addRule(new SafelistRule('trusted-bots', new TrustedBotMatcher()));
```

### Blocklists (Deny Malicious Traffic)

Blocklisted requests are immediately rejected with `403 Forbidden`.

```php
// Block admin-panel probes
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

Throttled requests receive `429 Too Many Requests` with a `Retry-After` header. Counting rules (throttle, fail2ban, allow2ban, track) count requests against a *key*, an identity that defaults to the resolved client IP (the Config's IP resolver, falling back to `REMOTE_ADDR` when no resolver is set). Pass a `key:` with a `KeyExtractors::*` callable to count against something else; behind a proxy, configure proxy trust once on the Config with `setIpResolver` (see [Client IP Behind Proxies](#client-ip-behind-proxies)).

```php
// 100 requests per minute per IP
$config->throttles->add('ip-minute', limit: 100, period: 60);

// Sliding window (prevents double-burst at window boundaries)
$config->throttles->sliding('api-sliding', limit: 100, period: 60);

// Multi-window (burst + sustained limits in a single call)
$config->throttles->multi('api', [
    1  => 5,    // 5 req/s burst limit
    60 => 100,  // 100 req/min sustained limit
]);

// Dynamic limit from a request attribute your auth middleware sets server-side
// ($req->withAttribute('role', ...)), never a forgeable header
$config->throttles->add('role-based',
    limit: fn($req) => $req->getAttribute('role') === 'admin' ? 1000 : 100,
    period: 60,
);

// Enable standard rate limit headers
$config->enableRateLimitHeaders();
```

See [Rate Limiting](/features/rate-limiting) and [Dynamic Throttle](/advanced/dynamic-throttle) for advanced usage.

### Fail2Ban (Malicious-Match Blocking)

A Fail2Ban filter marks a request as malicious, so **every match is blocked with `403`** and counted; the Nth match additionally bans the key. Use it for unambiguously malicious requests (scanner paths, invalid signatures), not for counting legitimate traffic.

```php
// Block and ban IPs probing scanner paths (each probe is blocked on the spot)
$config->fail2ban->add('scanner-probe',
    threshold: 5,
    period: 60,
    ban: 86400,
    filter: fn($req) => (bool) preg_match(
        '#^/(\.env|\.git(?:/|$)|\.aws/credentials)#i',
        $req->getUri()->getPath(),
    ),
);
```

::: warning
Do **not** use a Fail2Ban filter to count legitimate requests such as login POSTs: from 0.8 the first match is blocked. For login brute-force, use [Allow2Ban with a filter](/features/fail2ban#allow2ban) or post-handler signaling via [Request Context](/advanced/request-context).
:::

### Allow2Ban (Request Volume Banning)

Allow2Ban counts requests for a key and bans as soon as the count reaches the threshold (`threshold: 1000` bans on the 1000th request), letting counted requests pass until then. Without a filter it counts every request (a hard volume cap); with an optional filter it counts only the matching requests.

```php
// Ban any IP that sends more than 1000 requests in 60 seconds
$config->allow2ban->add('high-volume',
    threshold: 1000,
    period: 60,
    banSeconds: 3600,
);

// Or count login attempts (POST /login) and ban after 30 in 5 minutes.
// Successful attempts count too; for exact failure counting use RequestContext.
$config->allow2ban->add('login-brute-force',
    threshold: 30, period: 300, banSeconds: 3600,
    filter: fn($req) => $req->getMethod() === 'POST'
        && $req->getUri()->getPath() === '/login',
);
```

See [Fail2Ban & Allow2Ban](/features/fail2ban) for details.

### Track (Passive Monitoring)

Track rules count requests passively without blocking. Use them for dashboards, alerting, and analytics.

```php
$config->tracks->add('login-attempts',
    period: 3600,
    filter: fn($req) => $req->getUri()->getPath() === '/login' && $req->getMethod() === 'POST',
);

// Track with a threshold for alerting
$config->tracks->add('suspicious-burst',
    period: 60,
    filter: fn($req) => $req->getUri()->getPath() === '/login',
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

::: warning
The framework tabs below use `ApcuCache`, which needs the `ext-apcu` extension and throws without it. On a machine without APCu, swap in `new InMemoryCache()` to try it out, or `RedisCache` / `PdoCache` for shared production storage (see [Step 1](#step-1-choose-a-storage-backend)).
:::

::: code-group

```php [PSR-15 / Plain PHP]
// In a PSR-15 pipeline (Mezzio, custom dispatchers): $app->pipe($middleware);
//
// With no framework, a minimal public/index.php front controller. Serve with:
//   php -S localhost:8080 public/index.php
// Requires: composer require nyholm/psr7 nyholm/psr7-server
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7Server\ServerRequestCreator;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

// $middleware is the Phirewall middleware from Step 4.
$psr17 = new Psr17Factory();
$request = (new ServerRequestCreator($psr17, $psr17, $psr17, $psr17))->fromGlobals();

// Your application handler; it runs only if Phirewall lets the request through.
$appHandler = new class ($psr17) implements RequestHandlerInterface {
    public function __construct(private Psr17Factory $psr17) {}
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        return $this->psr17->createResponse(200);
    }
};

$response = $middleware->process($request, $appHandler);

// Emit the PSR-7 response.
http_response_code($response->getStatusCode());
foreach ($response->getHeaders() as $name => $values) {
    foreach ($values as $value) {
        header("$name: $value", false);
    }
}
echo $response->getBody();
```

```php [Symfony]
// 1. Install the PSR-15 bridge:
//    composer require symfony/psr-http-message-bridge nyholm/psr7
//
// 2. Create src/Factory/PhirewallFactory.php:

namespace App\Factory;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\Rule\SafelistRule;
use Flowd\Phirewall\Matchers\TrustedBotMatcher;
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
        $config->safelists->addRule(new SafelistRule('trusted-bots', new TrustedBotMatcher(cache: $cache)));

        // Blocklists
        $config->blocklists->knownScanners();
        $config->blocklists->suspiciousHeaders();

        // Allow2Ban brute-force counting: count login POSTs and ban the IP
        // after 5 in 5 min. Real login attempts pass until the threshold; a
        // pre-handler Fail2Ban filter would block the first attempt from 0.8.
        $config->allow2ban->add('login-abuse',
            threshold: 5, period: 300, banSeconds: 3600,
            filter: fn(ServerRequestInterface $req): bool =>
                $req->getMethod() === 'POST'
                && $req->getUri()->getPath() === '/login',
        );

        // Rate limiting
        $config->throttles->add('burst',
            limit: 30, period: 5,
        );
        $config->throttles->add('global',
            limit: 1000, period: 60,
        );

        $psr17 = new Psr17Factory();
        $config->usePsr17Responses($psr17, $psr17);

        return new Middleware($config, $psr17);
    }
}

// 3. Register the middleware factory in config/services.yaml:
//    services:
//        Flowd\Phirewall\Middleware:
//            factory: ['@App\Factory\PhirewallFactory', 'create']
//    The listener below auto-registers via #[AsEventListener] +
//    autoconfigure; the bridge factory interfaces autowire from the
//    symfony/psr-http-message-bridge + nyholm/psr7 packages.
//
// 4. Create src/EventListener/PhirewallListener.php
//    A two-phase listener: it blocks on kernel.request, and re-attaches
//    the X-RateLimit-* headers on kernel.response (a status-only
//    subscriber would silently drop them on the allowed 200 path).
//    NOTE: the bridge runs Phirewall with a pass-through handler, so the
//    RequestContext attribute for app-recorded fail2ban/allow2ban signals
//    is NOT visible to your controllers. Use pre-handler rule filters.

namespace App\EventListener;

use Flowd\Phirewall\Middleware as PhirewallMiddleware;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Symfony\Bridge\PsrHttpMessage\HttpFoundationFactoryInterface;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

final class PhirewallListener
{
    private const HEADERS_ATTRIBUTE = '_phirewall_headers';

    public function __construct(
        private readonly PhirewallMiddleware $middleware,
        private readonly HttpMessageFactoryInterface $psrHttpFactory,
        private readonly HttpFoundationFactoryInterface $httpFoundationFactory,
        private readonly ResponseFactoryInterface $responseFactory,
    ) {}

    #[AsEventListener(event: KernelEvents::REQUEST, priority: 256)]
    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }
        $psrRequest = $this->psrHttpFactory->createRequest($event->getRequest());
        $probe = new class ($this->responseFactory) implements RequestHandlerInterface {
            private bool $invoked = false;
            public function __construct(private readonly ResponseFactoryInterface $responseFactory) {}
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->invoked = true;
                return $this->responseFactory->createResponse(200);
            }
            public function wasInvoked(): bool { return $this->invoked; }
        };
        $psrResponse = $this->middleware->process($psrRequest, $probe);
        if (!$probe->wasInvoked()) {
            // The handler never ran: Phirewall produced a block/throttle response.
            $event->setResponse($this->httpFoundationFactory->createResponse($psrResponse));
            return;
        }
        // Allowed: carry Phirewall's rate-limit headers onto the real response.
        if ($psrResponse->getHeaders() !== []) {
            $event->getRequest()->attributes->set(self::HEADERS_ATTRIBUTE, $psrResponse->getHeaders());
        }
    }

    #[AsEventListener(event: KernelEvents::RESPONSE)]
    public function onKernelResponse(ResponseEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }
        /** @var array<string, list<string>> $headers */
        $headers = $event->getRequest()->attributes->get(self::HEADERS_ATTRIBUTE, []);
        foreach ($headers as $name => $values) {
            $event->getResponse()->headers->set($name, $values);
        }
    }

}
```

```php [Laravel]
// Flowd\Phirewall\Middleware is a PSR-15 middleware (process(...)), NOT a
// Laravel middleware (handle($request, $next)); registering the class
// directly throws. A thin bridge middleware (step 3) adapts it.
// Install the bridge: composer require symfony/psr-http-message-bridge nyholm/psr7
//
// 1. Create app/Providers/PhirewallServiceProvider.php:

namespace App\Providers;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\Rule\SafelistRule;
use Flowd\Phirewall\Matchers\TrustedBotMatcher;
use Flowd\Phirewall\Middleware as PhirewallMiddleware;
use Flowd\Phirewall\Store\ApcuCache;
use Illuminate\Support\ServiceProvider;
use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;

class PhirewallServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        // PSR-7/PSR-17 bridge factories used by the bridge middleware.
        // HttpFoundationFactory autowires (no-arg constructor).
        $this->app->singleton(Psr17Factory::class);
        $this->app->singleton(PsrHttpFactory::class, fn ($app) => new PsrHttpFactory(
            $app->make(Psr17Factory::class), $app->make(Psr17Factory::class),
            $app->make(Psr17Factory::class), $app->make(Psr17Factory::class),
        ));

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
            $config->safelists->addRule(new SafelistRule('trusted-bots', new TrustedBotMatcher(cache: $cache)));

            // Blocklists
            $config->blocklists->knownScanners();
            $config->blocklists->suspiciousHeaders();

            // Allow2Ban brute-force counting: count login POSTs and ban the IP
            // after 5 in 5 min. Real login attempts pass until the threshold; a
            // pre-handler Fail2Ban filter would block the first attempt from 0.8.
            $config->allow2ban->add('login-abuse',
                threshold: 5, period: 300, banSeconds: 3600,
                filter: fn(ServerRequestInterface $req): bool =>
                    $req->getMethod() === 'POST'
                    && $req->getUri()->getPath() === '/login',
            );

            // Rate limiting
            $config->throttles->add('burst',
                limit: 30, period: 5,
            );
            $config->throttles->add('global',
                limit: 1000, period: 60,
            );

            $psr17 = new Psr17Factory();
            $config->usePsr17Responses($psr17, $psr17);

            return new PhirewallMiddleware($config, $psr17);
        });
    }
}

// 2. Register the provider in bootstrap/providers.php (Laravel 11+)
//    or the providers array in config/app.php (Laravel 10).
//
// 3. Create app/Http/Middleware/Phirewall.php, the bridge.
//    Uses a probe handler so the real Laravel response is never
//    round-tripped through PSR-7 (preserves StreamedResponse /
//    BinaryFileResponse) and copies Phirewall's X-RateLimit-* headers
//    onto the allowed response.
//    NOTE: the bridge runs Phirewall with a probe handler, so the
//    RequestContext attribute for app-recorded fail2ban/allow2ban signals
//    is NOT visible to your controllers. Use pre-handler rule filters.

namespace App\Http\Middleware;

use Closure;
use Flowd\Phirewall\Middleware as PhirewallEngine;
use Illuminate\Http\Request;
use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\Response;

final readonly class Phirewall
{
    public function __construct(
        private PhirewallEngine $firewall,
        private PsrHttpFactory $psrHttpFactory,
        private HttpFoundationFactory $httpFoundationFactory,
        private Psr17Factory $psr17,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $psrRequest = $this->psrHttpFactory->createRequest($request);
        $probe = new class($this->psr17) implements RequestHandlerInterface {
            private bool $invoked = false;
            public function __construct(private readonly Psr17Factory $responseFactory) {}
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->invoked = true;
                return $this->responseFactory->createResponse();
            }
            public function wasInvoked(): bool { return $this->invoked; }
        };
        $psrResponse = $this->firewall->process($psrRequest, $probe);
        if (! $probe->wasInvoked()) {
            return $this->httpFoundationFactory->createResponse($psrResponse);
        }
        $response = $next($request);
        foreach ($psrResponse->getHeaders() as $name => $values) {
            $response->headers->set($name, $values);
        }
        return $response;
    }
}

// 4. Register the bridge middleware (outermost):
//    bootstrap/app.php (Laravel 11/12):
//    ->withMiddleware(function (Middleware $middleware): void {
//        $middleware->prepend(\App\Http\Middleware\Phirewall::class);
//    })
//
//    Or app/Http/Kernel.php (Laravel 10 and earlier):
//    protected $middleware = [
//        \App\Http\Middleware\Phirewall::class,
//        // ...
//    ];
```

```php [Slim]
// Slim uses LIFO middleware ordering.
// Add Phirewall LAST so it executes FIRST (outermost).

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\Rule\SafelistRule;
use Flowd\Phirewall\Matchers\TrustedBotMatcher;
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
$config->safelists->addRule(new SafelistRule('trusted-bots', new TrustedBotMatcher(cache: $cache)));

// Blocklists
$config->blocklists->knownScanners();
$config->blocklists->suspiciousHeaders();

// Allow2Ban brute-force counting: count login POSTs and ban the IP after
// 5 in 5 min. Real login attempts pass until the threshold; a pre-handler
// Fail2Ban filter would block the first attempt from 0.8.
$config->allow2ban->add('login-abuse',
    threshold: 5, period: 300, banSeconds: 3600,
    filter: fn(ServerRequestInterface $req): bool =>
        $req->getMethod() === 'POST'
        && $req->getUri()->getPath() === '/login',
);

// Rate limiting
$config->throttles->add('burst',
    limit: 30, period: 5,
);
$config->throttles->add('global',
    limit: 1000, period: 60,
);

// Add Phirewall LAST (Slim LIFO = executes first)
$app->add(new PhirewallMiddleware($config));

// ... define routes ...
$app->run();
```

```php [Mezzio]
// Mezzio uses PSR-15 natively. Pipe Phirewall right after the ErrorHandler.

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
use Flowd\Phirewall\Config\Rule\SafelistRule;
use Flowd\Phirewall\Matchers\TrustedBotMatcher;
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
        $config->safelists->addRule(new SafelistRule('trusted-bots', new TrustedBotMatcher(cache: $cache)));

        // Blocklists
        $config->blocklists->knownScanners();
        $config->blocklists->suspiciousHeaders();

        // Allow2Ban brute-force counting: count login POSTs and ban the IP
        // after 5 in 5 min. Real login attempts pass until the threshold; a
        // pre-handler Fail2Ban filter would block the first attempt from 0.8.
        $config->allow2ban->add('login-abuse',
            threshold: 5, period: 300, banSeconds: 3600,
            filter: fn(ServerRequestInterface $req): bool =>
                $req->getMethod() === 'POST'
                && $req->getUri()->getPath() === '/login',
        );

        // Rate limiting
        $config->throttles->add('burst',
            limit: 30, period: 5,
        );
        $config->throttles->add('global',
            limit: 1000, period: 60,
        );

        $psr17 = new Psr17Factory();
        $config->usePsr17Responses($psr17, $psr17);

        return new PhirewallMiddleware($config, $psr17);
    }
}

// In config/pipeline.php (pipe the ErrorHandler first, then Phirewall):
// $app->pipe(\Laminas\Stratigility\Middleware\ErrorHandler::class);
// $app->pipe(\Flowd\Phirewall\Middleware::class);
// $app->pipe(\Mezzio\Router\Middleware\RouteMiddleware::class);
// $app->pipe(\Mezzio\Router\Middleware\DispatchMiddleware::class);
```

:::

> **Middleware ordering:** Pipe Phirewall as early as possible, but after your error-handling middleware. Phirewall does not wrap the downstream handler, so a handler exception must be able to reach the error handler. See the [Examples](/examples#framework-integration) page for more detailed integrations.

## Complete Example

Here is a full, runnable example you can copy into a file and execute immediately. Requires `nyholm/psr7` (`composer require nyholm/psr7`):

```php
<?php

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use Flowd\Phirewall\Config;
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
$config->throttles->add('ip-limit', limit: 10, period: 60);

// Allow2Ban: Ban IPs that POST to /login more than 3 times in 2 minutes.
// Login POSTs are legitimate requests, so count them with Allow2Ban (they
// pass until the threshold) rather than a Fail2Ban filter (which blocks
// every match from 0.8).
$config->allow2ban->add('login',
    threshold: 3,
    period: 120,
    banSeconds: 300,
    filter: fn($req) => $req->getMethod() === 'POST'
        && $req->getUri()->getPath() === '/login',
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

Phirewall evaluates rules in a strict, deterministic order using an [evaluator pipeline](/advanced/architecture). The first match wins.

```text
Request --> Track (passive) --> Safelist --> Blocklist --> Fail2Ban --> Throttle --> Allow2Ban --> Pass
                                   |            |             |            |            |
                                   v            v             v            v            v
                                 Allow        403           403          429          403
```

The evaluation order is:

1. **Track** rules are always evaluated first (passive counting, never blocks)
2. **Safelist**: if matched, the request bypasses all remaining checks
3. **Blocklist**: if matched, the request is rejected with `403`
4. **Fail2Ban**: if the client is already banned, `403`; if the filter matches, block with `403` and count (the Nth match also bans)
5. **Throttle**: if the counter exceeds the limit, `429` with `Retry-After`
6. **Allow2Ban**: counts the request (every request, or only filtered ones), and `403` with `Retry-After` once the threshold is reached
7. **Pass**: the request reaches your application

## Fail-Open / Fail-Closed

By default, Phirewall fails open: if the cache backend is unavailable or throws an exception, the request is allowed through and the error is dispatched as a `FirewallError` event for logging.

```php
// Fail-open (default): requests pass through on errors
$config->setFailOpen(true);

// Fail-closed: exceptions propagate, resulting in 500 errors
// Use only when blocking is more important than availability
$config->setFailOpen(false);
```

The policy also governs pattern-blocklist regex matching: a compile-valid pattern that errors at match time (e.g. the backtrack limit exceeded) counts as no match under fail-open, while a fail-closed firewall treats the error as a match, so a forced engine error cannot slip past a block rule. The OWASP CRS engine is separate: its `@rx` operator always treats an engine error as a match, regardless of this policy (see [OWASP CRS](/features/owasp-crs#operator-evaluators)).

## Response Headers

Diagnostic `X-Phirewall` headers are opt-in and can be added to blocked or safelisted responses:

```php
$config->enableResponseHeaders();
```

| Header | Opt-in | Description |
|--------|--------|-------------|
| `X-Phirewall` | Yes | Block type: `blocklist`, `throttle`, `fail2ban`, or `allow2ban` |
| `X-Phirewall-Matched` | Yes | Name of the rule that triggered |
| `X-Phirewall-Safelist` | Yes | Name of the safelist rule that matched |
| `Retry-After` | No | Seconds until the client may retry (throttles and allow2ban bans) |

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

$resolver = new TrustedProxyResolver([
    '10.0.0.0/8',      // Internal network
    '172.16.0.0/12',   // Docker
    '192.168.0.0/16',  // Private ranges
]);

// Configure proxy trust once on the Config; all rules then key on
// the resolved client IP by default (no key: argument needed).
$config->setIpResolver($resolver->resolve(...));

$config->throttles->add('api', limit: 100, period: 60);
```

::: danger Set a resolver behind a proxy, or every client shares one key
The raw `REMOTE_ADDR` peer address is used verbatim when no resolver is configured. Behind a CDN or load balancer that value is the *proxy's* address, so every client collapses onto a single throttle/ban key and your rate limits and bans become useless (or ban everyone at once). The same default applies to file-backed IP blocklists and infrastructure ban listeners. Whenever Phirewall runs behind a proxy, install a client-IP resolver, `$config->setIpResolver((new TrustedProxyResolver([...]))->resolve(...))`, so rules key on the originating client. And never trust `X-Forwarded-For` *without* configuring the trusted proxies: an attacker can otherwise spoof the header to forge any client IP.
:::

### Resolver behavior

`TrustedProxyResolver` walks the forwarded chain from right to left, skipping hops whose address is in your trusted-proxy list, and returns the first untrusted address as the client IP (falling back to `REMOTE_ADDR` when the chain yields nothing valid). A few details are worth knowing:

```php
// Constructor: trusted proxies first, then the header(s) to consult, then a chain cap.
new TrustedProxyResolver(
    trustedProxies: ['10.0.0.0/8', '172.16.0.0/12'],
    allowedHeaders: ['X-Forwarded-For'], // default
    maxChainEntries: 50,                 // default
);
```

- **The default header is a single header.** `allowedHeaders` defaults to `['X-Forwarded-For']` only. If your stack emits the RFC 7239 `Forwarded` header instead, pass it explicitly: `new TrustedProxyResolver([...], ['Forwarded'])`, or `['Forwarded', 'X-Forwarded-For']` for both, so the header the resolver trusts is visible at the call site rather than inferred.
- **Proxy headers are read only when the direct peer is trusted.** The resolver consults `X-Forwarded-For` (or `Forwarded`) only when `REMOTE_ADDR`, the address that connected, is itself in your trusted-proxy list. A request arriving directly from an untrusted client has its forwarded headers ignored and is keyed on `REMOTE_ADDR`.
- **All header instances are folded into one chain.** Whether intermediaries keep `X-Forwarded-For` as separate lines or fold them into one comma-separated value (the nginx default), the resolver flattens them and walks the chain right to left, returning the first hop that is not in your trusted-proxy list. The protection is this trusted-hop walk, not the number or order of header instances: a client-prepended value sits to the left of the addresses your proxies append, so it is returned only if every hop to its right is trusted. Correct trusted ranges are therefore essential, and stripping or overwriting the inbound header at the edge prevents spoofing outright.
- **An unparsable hop stops the walk.** If a chain entry cannot be parsed as an IP address - the literal `for=unknown`, an RFC 7239 obfuscated identifier (`for=_hidden`), or a malformed value - the walk treats it as terminal and falls back to `REMOTE_ADDR` rather than stepping past it. An unidentifiable hop breaks the verifiable chain, so entries further left cannot be trusted either.
- **IPv6 is canonicalized.** An IPv4-mapped IPv6 peer (`::ffff:203.0.113.7`) collapses to its embedded IPv4 form, so a plain IPv4 rule or CIDR matches it and an attacker cannot bypass an IPv4 rule by presenting the mapped form. Alternate *genuine*-IPv6 spellings (expanded `2001:0db8::1` vs compressed `2001:db8::1`, mixed case) are also treated as one identity by `ip()` / CIDR **list** matching, which compares the raw binary address. When a `TrustedProxyResolver` is set via `setIpResolver`, the resolver canonicalizes the address it returns, so per-client keys stay stable regardless of the spelling the client presents; the consistent-spelling caveat applies only to the raw `REMOTE_ADDR` peer address (read via `$request->getServerParams()['REMOTE_ADDR']`) or a custom resolver that does not canonicalize.

## First Test

With your application served (for the plain-PHP front controller in Step 5, run `php -S localhost:8080 public/index.php`; otherwise use your framework's own server), verify the firewall by sending requests:

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
- Add ready-made presets from the companion packages: [OWASP CRS](/features/owasp-crs), [Bot Presets](/features/bot-presets), and the [Bad-IP Preset](/features/bad-ip-preset)
- Explore [Storage Backends](/features/storage) for production
- Add [Observability](/advanced/observability) for monitoring
- Use [Request Context](/advanced/request-context) for post-handler failure signaling
- Browse [Examples](/examples) for complete, copy-pasteable configurations
