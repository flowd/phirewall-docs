---
outline: deep
---

# Examples

Complete, copy-pasteable configurations for common scenarios. Each example is self-contained and uses the section API.

## Running the Built-in Examples

The Phirewall repository includes 31 runnable examples:

```bash
git clone https://github.com/flowd/phirewall
cd phirewall
composer install
php examples/01-basic-setup.php
```

| # | Example | Description |
|---|---------|-------------|
| 01 | [basic-setup](https://github.com/flowd/phirewall/blob/main/examples/01-basic-setup.php) | Minimal configuration to get started |
| 02 | [brute-force-protection](https://github.com/flowd/phirewall/blob/main/examples/02-brute-force-protection.php) | Fail2Ban-style login protection |
| 03 | [api-rate-limiting](https://github.com/flowd/phirewall/blob/main/examples/03-api-rate-limiting.php) | Tiered rate limits for APIs |
| 04 | [sql-injection-blocking](https://github.com/flowd/phirewall/blob/main/examples/04-sql-injection-blocking.php) | OWASP-style SQLi detection |
| 05 | [xss-prevention](https://github.com/flowd/phirewall/blob/main/examples/05-xss-prevention.php) | Cross-Site Scripting protection |
| 06 | [bot-detection](https://github.com/flowd/phirewall/blob/main/examples/06-bot-detection.php) | Scanner and malicious bot blocking |
| 07 | [ip-blocklist](https://github.com/flowd/phirewall/blob/main/examples/07-ip-blocklist.php) | File-backed IP/CIDR blocklists |
| 08 | [comprehensive-protection](https://github.com/flowd/phirewall/blob/main/examples/08-comprehensive-protection.php) | Production-ready multi-layer setup |
| 09 | [observability-monolog](https://github.com/flowd/phirewall/blob/main/examples/09-observability-monolog.php) | Event logging with Monolog |
| 10 | [observability-opentelemetry](https://github.com/flowd/phirewall/blob/main/examples/10-observability-opentelemetry.php) | Distributed tracing with OpenTelemetry |
| 11 | [redis-storage](https://github.com/flowd/phirewall/blob/main/examples/11-redis-storage.php) | Redis backend for multi-server deployments |
| 12 | [apache-htaccess](https://github.com/flowd/phirewall/blob/main/examples/12-apache-htaccess.php) | Apache .htaccess IP blocking |
| 13 | [benchmarks](https://github.com/flowd/phirewall/blob/main/examples/13-benchmarks.php) | Storage backend performance comparison |
| 14 | [owasp-crs-files](https://github.com/flowd/phirewall/blob/main/examples/14-owasp-crs-files.php) | Loading OWASP CRS rules from files |
| 15 | [in-memory-pattern-backend](https://github.com/flowd/phirewall/blob/main/examples/15-in-memory-pattern-backend.php) | Configuration-based CIDR/IP blocklists |
| 16 | [allow2ban](https://github.com/flowd/phirewall/blob/main/examples/16-allow2ban.php) | Volume-based banning (inverse of fail2ban) |
| 17 | [known-scanners](https://github.com/flowd/phirewall/blob/main/examples/17-known-scanners.php) | Block known attack tools by User-Agent |
| 18 | [trusted-bots](https://github.com/flowd/phirewall/blob/main/examples/18-trusted-bots.php) | Safelist verified search engine bots via RDNS |
| 19 | [header-analysis](https://github.com/flowd/phirewall/blob/main/examples/19-header-analysis.php) | Block requests missing standard browser headers |
| 20 | [rule-benchmarks](https://github.com/flowd/phirewall/blob/main/examples/20-rule-benchmarks.php) | Firewall rule evaluation performance benchmarks |
| 21 | [sliding-window](https://github.com/flowd/phirewall/blob/main/examples/21-sliding-window.php) | Sliding window rate limiting |
| 22 | [multi-throttle](https://github.com/flowd/phirewall/blob/main/examples/22-multi-throttle.php) | Multi-window throttling (burst + sustained) |
| 23 | [dynamic-limits](https://github.com/flowd/phirewall/blob/main/examples/23-dynamic-limits.php) | Dynamic rate limits based on request properties |
| 24 | [pdo-storage](https://github.com/flowd/phirewall/blob/main/examples/24-pdo-storage.php) | PdoCache backend (MySQL/PostgreSQL/SQLite) |
| 25 | [track-threshold](https://github.com/flowd/phirewall/blob/main/examples/25-track-threshold.php) | Track with threshold for alerting |
| 26 | [psr17-factories](https://github.com/flowd/phirewall/blob/main/examples/26-psr17-factories.php) | PSR-17 response factory integration |
| 27 | [request-context](https://github.com/flowd/phirewall/blob/main/examples/27-request-context.php) | Post-handler fail2ban signaling |
| 28 | [portable-config-signing](https://github.com/flowd/phirewall/blob/main/examples/28-portable-config-signing.php) | Signed PortableConfig transport (HMAC-SHA256) |
| 29 | [portable-config](https://github.com/flowd/phirewall/blob/main/examples/29-portable-config.php) | PortableConfig as a first-class transport with DB hot-reload |
| 30 | [config-composition](https://github.com/flowd/phirewall/blob/main/examples/30-config-composition.php) | Layering configs (vendor → environment → tenant → deployment) |
| 31 | [presets](https://github.com/flowd/phirewall/blob/main/examples/31-presets.php) | Ready-to-use rule presets and version comparison (compare `Presets::VERSION` against your own release feed) |

---

## Framework Integration

Production-ready integration examples for popular PHP frameworks. Each example includes storage, safelists, blocklists, rate limiting, brute-force protection, OWASP rules, and observability. Copy, paste, adapt.

### PSR-15 (Generic / Plain PHP)

Works with any PSR-15 compatible stack (custom dispatchers, runtimes, etc.; Mezzio has its own section below). Requires `nyholm/psr7`.

```php
<?php

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\TrustedProxyResolver;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Owasp\SecRuleLoader;
use Flowd\Phirewall\Store\ApcuCache;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

// ── Storage ──────────────────────────────────────────────────────────
// ApcuCache requires ext-apcu (zero config, single-server)
// For multi-server deployments: use RedisCache with predis/predis
$cache = new ApcuCache();

// ── Configuration ────────────────────────────────────────────────────
$config = new Config($cache);
$config->setKeyPrefix('prod');
$config->enableRateLimitHeaders();
$config->setFailOpen(true);

// ── Trusted Proxies ──────────────────────────────────────────────────
$proxyResolver = new TrustedProxyResolver([
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
]);
$config->setIpResolver(KeyExtractors::clientIp($proxyResolver));

// ── Safelists ────────────────────────────────────────────────────────
$config->safelists->add('health',
    fn(ServerRequestInterface $req): bool =>
        $req->getUri()->getPath() === '/health'
);
$config->safelists->add('metrics',
    fn(ServerRequestInterface $req): bool =>
        $req->getUri()->getPath() === '/metrics'
);
$config->safelists->ip('office', ['10.0.0.0/8', '192.168.1.0/24']);
$config->safelists->trustedBots(cache: $cache);

// ── Blocklists ───────────────────────────────────────────────────────
$config->blocklists->knownScanners();
$config->blocklists->suspiciousHeaders();
$config->blocklists->add('scanner-probe',
    fn(ServerRequestInterface $req): bool =>
        str_starts_with($req->getUri()->getPath(), '/admin-panel')
);

// ── OWASP Rules ──────────────────────────────────────────────────────
$owaspRules = SecRuleLoader::fromString(<<<'CRS'
SecRule ARGS "@rx (?i)\bunion\b.*\bselect\b" "id:942100,phase:2,deny,msg:'SQLi'"
SecRule ARGS "@rx (?i)<script[^>]*>" "id:941100,phase:2,deny,msg:'XSS'"
SecRule ARGS "@rx (?i)(eval|exec|system|shell_exec|passthru)\s*\(" "id:933100,phase:2,deny,msg:'RCE'"
CRS);
$config->blocklists->owasp('owasp', $owaspRules);

// ── Fail2Ban ─────────────────────────────────────────────────────────
$config->fail2ban->add('login-abuse',
    threshold: 5,
    period: 300,
    ban: 3600,
    filter: fn(ServerRequestInterface $req): bool =>
        $req->getMethod() === 'POST'
        && $req->getUri()->getPath() === '/login',
    key: KeyExtractors::clientIp($proxyResolver)
);

// ── Rate Limiting ────────────────────────────────────────────────────
$config->throttles->add('burst',
    limit: 30, period: 5,
    key: KeyExtractors::clientIp($proxyResolver)
);
$config->throttles->add('global',
    limit: 1000, period: 60,
    key: KeyExtractors::clientIp($proxyResolver)
);

// ── Allow2Ban ────────────────────────────────────────────────────────
$config->allow2ban->add('flood-protection',
    threshold: 500, period: 60, banSeconds: 3600,
    key: KeyExtractors::clientIp($proxyResolver)
);

// ── PSR-17 Response Bodies ───────────────────────────────────────────
$psr17 = new Psr17Factory();
$config->usePsr17Responses($psr17, $psr17);

// ── Middleware ────────────────────────────────────────────────────────
$middleware = new Middleware($config, $psr17);

// ── Application Handler ──────────────────────────────────────────────
$handler = new class implements RequestHandlerInterface {
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        return new Response(200, ['Content-Type' => 'application/json'], '{"ok":true}');
    }
};

// ── Process Request ──────────────────────────────────────────────────
$request  = new ServerRequest('GET', '/api/users', [], null, '1.1', [
    'REMOTE_ADDR' => '192.168.1.100',
]);
$response = $middleware->process($request, $handler);

echo 'Status: ' . $response->getStatusCode() . "\n";
```

---

### Symfony

Requires `symfony/psr-http-message-bridge` and `nyholm/psr7`. Phirewall runs as a PSR-15 middleware wrapped by Symfony's PSR bridge; the bridge factories (`HttpMessageFactoryInterface`, `HttpFoundationFactoryInterface`) and the `nyholm/psr7` PSR-17 factory then autowire into the listener below.

```bash
composer require symfony/psr-http-message-bridge nyholm/psr7
```

::: warning
This bridge runs Phirewall with a pass-through handler, so the `RequestContext` attribute it attaches for app-recorded fail2ban/allow2ban signals lives on the throwaway PSR request and is not visible to your Symfony controllers. Use the pre-handler rule filters for blocking; post-handler `recordFailure()`/`recordHit()` from a controller is not propagated by this basic bridge.
:::

**`src/Factory/PhirewallFactory.php`**

```php
<?php

declare(strict_types=1);

namespace App\Factory;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\TrustedProxyResolver;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware as PhirewallMiddleware;
use Flowd\Phirewall\Owasp\SecRuleLoader;
use Flowd\Phirewall\Store\ApcuCache;
use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Message\ServerRequestInterface;

class PhirewallFactory
{
    /** @param list<string> $trustedProxies */
    public function __construct(
        private readonly array $trustedProxies = [],
    ) {}

    public function create(): PhirewallMiddleware
    {
        // ── Storage ──────────────────────────────────────────────
        // ApcuCache requires ext-apcu (zero config, single-server)
        // For multi-server: use RedisCache with predis/predis
        $cache = new ApcuCache();

        // ── Configuration ────────────────────────────────────────
        $config = new Config($cache);
        $config->setKeyPrefix('symfony');
        $config->enableRateLimitHeaders();
        $config->setFailOpen(true);

        // ── Trusted Proxies ──────────────────────────────────────
        // Drop empty entries so an unset/blank env var disables the
        // resolver instead of registering an empty proxy list.
        $trustedProxies = array_values(array_filter($this->trustedProxies));
        if ($trustedProxies !== []) {
            $proxyResolver = new TrustedProxyResolver($trustedProxies);
            $config->setIpResolver(
                KeyExtractors::clientIp($proxyResolver)
            );
        }

        // ── Safelists ────────────────────────────────────────────
        $config->safelists->add('health',
            fn(ServerRequestInterface $req): bool =>
                $req->getUri()->getPath() === '/health'
        );
        $config->safelists->add('profiler',
            fn(ServerRequestInterface $req): bool =>
                str_starts_with($req->getUri()->getPath(), '/_profiler')
        );
        $config->safelists->trustedBots(cache: $cache);

        // ── Blocklists ───────────────────────────────────────────
        $config->blocklists->knownScanners();
        $config->blocklists->suspiciousHeaders();

        // ── OWASP Rules ──────────────────────────────────────────
        $owaspRules = SecRuleLoader::fromString(<<<'CRS'
        SecRule ARGS "@rx (?i)\bunion\b.*\bselect\b" "id:942100,phase:2,deny,msg:'SQLi'"
        SecRule ARGS "@rx (?i)<script[^>]*>" "id:941100,phase:2,deny,msg:'XSS'"
        SecRule ARGS "@rx (?i)(eval|exec|system|shell_exec|passthru)\s*\(" "id:933100,phase:2,deny,msg:'RCE'"
        CRS);
        $config->blocklists->owasp('owasp', $owaspRules);

        // ── Fail2Ban ─────────────────────────────────────────────
        // No key: these rules default to the client IP from the
        // global resolver set above.
        $config->fail2ban->add('login-abuse',
            threshold: 5,
            period: 300,
            ban: 3600,
            filter: fn(ServerRequestInterface $req): bool =>
                $req->getMethod() === 'POST'
                && $req->getUri()->getPath() === '/login',
        );

        // ── Rate Limiting ────────────────────────────────────────
        $config->throttles->add('burst',
            limit: 30, period: 5,
        );
        $config->throttles->add('global',
            limit: 1000, period: 60,
        );

        // ── Allow2Ban ────────────────────────────────────────────
        $config->allow2ban->add('flood-protection',
            threshold: 500, period: 60, banSeconds: 3600,
        );

        // ── PSR-17 Response Bodies ───────────────────────────────
        $psr17 = new Psr17Factory();
        $config->usePsr17Responses($psr17, $psr17);

        return new PhirewallMiddleware($config, $psr17);
    }
}
```

**`config/services.yaml`**

```yaml
# Add these under the `services:` key in Symfony's default config/services.yaml.
# Keep the stock `_defaults: { autowire: true, autoconfigure: true }` and `App\:`
# resource block: `autoconfigure` is what turns the #[AsEventListener] below into a
# registered listener, and the `App\` loader registers the factory and listener as
# services. Drop them and the listener never runs, so Phirewall silently does nothing.
services:
    App\Factory\PhirewallFactory:
        arguments:
            $trustedProxies: '%env(csv:PHIREWALL_TRUSTED_PROXIES)%'

    Flowd\Phirewall\Middleware:
        factory: ['@App\Factory\PhirewallFactory', 'create']
```

Define `PHIREWALL_TRUSTED_PROXIES` in your environment even if empty: an undefined `%env()%` reference fails container compilation, whereas an empty value cleanly disables proxy resolution (the factory's `array_filter` drops it).

```dotenv
# .env  (empty disables Phirewall's proxy resolution)
PHIREWALL_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12
```

The listener below auto-registers via `#[AsEventListener]` + autoconfigure; no manual `tags:` entry needed.

**`src/EventListener/PhirewallListener.php`**

A two-phase listener: it runs Phirewall on `kernel.request` (blocking early when a rule fires) and re-attaches the `X-RateLimit-*` headers Phirewall adds on the allowed path during `kernel.response`. A single-phase subscriber that only acts when the status is non-200 would silently drop those headers.

```php
<?php

declare(strict_types=1);

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

---

### Laravel

`Flowd\Phirewall\Middleware` is a PSR-15 middleware (`process(...)`), **not** a Laravel middleware (`handle($request, $next)`); registering the class directly throws. A thin bridge middleware adapts it. Install the bridge:

```bash
composer require symfony/psr-http-message-bridge nyholm/psr7
```

::: warning
This bridge runs Phirewall with a probe handler, so the `RequestContext` attribute it attaches for app-recorded fail2ban/allow2ban signals lives on the throwaway PSR request and is not visible to your Laravel controllers. Use the pre-handler rule filters for blocking; post-handler `recordFailure()`/`recordHit()` from a controller is not propagated by this basic bridge.
:::

**`app/Providers/PhirewallServiceProvider.php`**

```php
<?php

declare(strict_types=1);

namespace App\Providers;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\TrustedProxyResolver;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware as PhirewallMiddleware;
use Flowd\Phirewall\Owasp\SecRuleLoader;
use Flowd\Phirewall\Store\ApcuCache;
use Illuminate\Support\ServiceProvider;
use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;

class PhirewallServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        // PSR-7/PSR-17 bridge factories used by the Phirewall middleware.
        // HttpFoundationFactory has a no-arg constructor, so Laravel
        // autowires it without an explicit binding.
        $this->app->singleton(Psr17Factory::class);
        $this->app->singleton(PsrHttpFactory::class, fn ($app) => new PsrHttpFactory(
            $app->make(Psr17Factory::class), $app->make(Psr17Factory::class),
            $app->make(Psr17Factory::class), $app->make(Psr17Factory::class),
        ));

        $this->app->singleton(PhirewallMiddleware::class, function () {
            // ── Storage ──────────────────────────────────────────
            // ApcuCache requires ext-apcu (zero config, single-server)
            // For multi-server: use RedisCache with predis/predis
            $cache = new ApcuCache();

            // ── Configuration ────────────────────────────────────
            $config = new Config($cache);
            $config->setKeyPrefix(config('app.name', 'laravel'));
            $config->enableRateLimitHeaders();
            $config->setFailOpen(true);

            // ── Trusted Proxies ──────────────────────────────────
            // Phirewall resolves the client IP from its OWN trusted-proxy list,
            // independent of Laravel's TrustProxies middleware. List your load
            // balancer / CDN ranges here (e.g. via a TRUSTED_PROXIES env var).
            // Leave empty only for a direct-to-PHP deployment.
            $trustedProxies = array_filter(explode(',', (string) env('TRUSTED_PROXIES', '')));
            if ($trustedProxies !== []) {
                $proxyResolver = new TrustedProxyResolver($trustedProxies);
                $config->setIpResolver(
                    KeyExtractors::clientIp($proxyResolver)
                );
            }

            // ── Safelists ────────────────────────────────────────
            $config->safelists->add('health',
                fn(ServerRequestInterface $req): bool =>
                    $req->getUri()->getPath() === '/health'
            );
            $config->safelists->add('horizon',
                fn(ServerRequestInterface $req): bool =>
                    str_starts_with($req->getUri()->getPath(), '/horizon')
            );
            $config->safelists->trustedBots(cache: $cache);

            // ── Blocklists ───────────────────────────────────────
            $config->blocklists->knownScanners();
            $config->blocklists->suspiciousHeaders();
            $config->blocklists->add('scanner-probe',
                fn(ServerRequestInterface $req): bool =>
                    str_starts_with($req->getUri()->getPath(), '/admin-panel')
            );

            // ── OWASP Rules ──────────────────────────────────────
            $owaspRules = SecRuleLoader::fromString(<<<'CRS'
            SecRule ARGS "@rx (?i)\bunion\b.*\bselect\b" "id:942100,phase:2,deny,msg:'SQLi'"
            SecRule ARGS "@rx (?i)<script[^>]*>" "id:941100,phase:2,deny,msg:'XSS'"
            SecRule ARGS "@rx (?i)(eval|exec|system|shell_exec|passthru)\s*\(" "id:933100,phase:2,deny,msg:'RCE'"
            CRS);
            $config->blocklists->owasp('owasp', $owaspRules);

            // ── Fail2Ban ─────────────────────────────────────────
            // No key: these rules default to the client IP from the
            // global resolver set above.
            $config->fail2ban->add('login-abuse',
                threshold: 5,
                period: 300,
                ban: 3600,
                filter: fn(ServerRequestInterface $req): bool =>
                    $req->getMethod() === 'POST'
                    && $req->getUri()->getPath() === '/login',
            );

            // ── Rate Limiting ────────────────────────────────────
            $config->throttles->add('burst',
                limit: 30, period: 5,
            );
            $config->throttles->add('global',
                limit: 1000, period: 60,
            );
            $config->throttles->add('api',
                limit: fn(ServerRequestInterface $req): int =>
                    $req->getHeaderLine('X-Role') === 'admin' ? 5000 : 200,
                period: 60,
            );

            // ── Allow2Ban ────────────────────────────────────────
            $config->allow2ban->add('flood-protection',
                threshold: 500, period: 60, banSeconds: 3600,
            );

            // ── PSR-17 Response Bodies ───────────────────────────
            // usePsr17Responses() sets the block/throttle response bodies; the
            // constructor argument is only the fallback ResponseFactory.
            $psr17 = new Psr17Factory();
            $config->usePsr17Responses($psr17, $psr17);

            return new PhirewallMiddleware($config, $psr17);
        });
    }
}
```

**`app/Http/Middleware/Phirewall.php`**

The bridge adapts the PSR-15 engine to Laravel's middleware contract. It uses a probe handler so the real Laravel response is never round-tripped through PSR-7; `StreamedResponse`/`BinaryFileResponse` and other special responses are preserved. On the allowed path it copies Phirewall's `X-RateLimit-*` headers onto the real response.

```php
<?php

declare(strict_types=1);

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
```

Register the service provider in `bootstrap/providers.php` (Laravel 11+) or the `providers` array in `config/app.php` (Laravel 10 and earlier):

```php
// bootstrap/providers.php (Laravel 11+)
return [
    App\Providers\AppServiceProvider::class,
    App\Providers\PhirewallServiceProvider::class,
];
```

**`bootstrap/app.php`** (Laravel 11/12)

```php
<?php

use App\Http\Middleware\Phirewall;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->prepend(Phirewall::class);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        //
    })->create();
```

**`app/Http/Kernel.php`** (Laravel 10 and earlier)

```php
protected $middleware = [
    \App\Http\Middleware\Phirewall::class, // outermost: runs before everything
    // ... other global middleware
];
```

---

### Slim

Native PSR-15 support. The middleware auto-detects a PSR-17 `ResponseFactory` from installed packages (`slim/psr7`, which ships with the Slim skeleton, or `nyholm/psr7`) and throws if none is found, so install one (plus `ext-apcu` for `ApcuCache`).

```php
<?php

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\TrustedProxyResolver;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware as PhirewallMiddleware;
use Flowd\Phirewall\Owasp\SecRuleLoader;
use Flowd\Phirewall\Store\ApcuCache;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Factory\AppFactory;

// ── Storage ──────────────────────────────────────────────────────────
// ApcuCache requires ext-apcu (zero config, single-server)
// For multi-server: use RedisCache with predis/predis
$cache = new ApcuCache();

// ── Configuration ────────────────────────────────────────────────────
$config = new Config($cache);
$config->setKeyPrefix('slim');
$config->enableRateLimitHeaders();
$config->setFailOpen(true);

// ── Trusted Proxies ──────────────────────────────────────────────────
$proxyResolver = new TrustedProxyResolver(['10.0.0.0/8', '172.16.0.0/12']);
$config->setIpResolver(KeyExtractors::clientIp($proxyResolver));

// ── Safelists ────────────────────────────────────────────────────────
$config->safelists->add('health',
    fn(ServerRequestInterface $req): bool =>
        $req->getUri()->getPath() === '/health'
);
$config->safelists->trustedBots(cache: $cache);

// ── Blocklists ───────────────────────────────────────────────────────
$config->blocklists->knownScanners();
$config->blocklists->suspiciousHeaders();

// ── OWASP Rules ──────────────────────────────────────────────────────
$owaspRules = SecRuleLoader::fromString(<<<'CRS'
SecRule ARGS "@rx (?i)\bunion\b.*\bselect\b" "id:942100,phase:2,deny,msg:'SQLi'"
SecRule ARGS "@rx (?i)<script[^>]*>" "id:941100,phase:2,deny,msg:'XSS'"
SecRule ARGS "@rx (?i)(eval|exec|system|shell_exec|passthru)\s*\(" "id:933100,phase:2,deny,msg:'RCE'"
CRS);
$config->blocklists->owasp('owasp', $owaspRules);

// ── Fail2Ban ─────────────────────────────────────────────────────────
$config->fail2ban->add('login-abuse',
    threshold: 5,
    period: 300,
    ban: 3600,
    filter: fn(ServerRequestInterface $req): bool =>
        $req->getMethod() === 'POST'
        && $req->getUri()->getPath() === '/login',
    key: KeyExtractors::clientIp($proxyResolver)
);

// ── Rate Limiting ────────────────────────────────────────────────────
$config->throttles->multi('api', [
    5  => 30,    // 30 req / 5 sec burst limit
    60 => 1000,  // 1000 req / min sustained limit
], KeyExtractors::clientIp($proxyResolver));

// ── Allow2Ban ────────────────────────────────────────────────────────
$config->allow2ban->add('flood-protection',
    threshold: 500, period: 60, banSeconds: 3600,
    key: KeyExtractors::clientIp($proxyResolver)
);

// ── Application ──────────────────────────────────────────────────────
$app = AppFactory::create();

// Phirewall must be added LAST (Slim processes middleware LIFO)
$app->add(new PhirewallMiddleware($config));

$app->get('/health', function ($request, ResponseInterface $response) {
    $response->getBody()->write('OK');
    return $response;
});

$app->get('/api/users', function ($request, ResponseInterface $response) {
    $response->getBody()->write(json_encode(['users' => []]));
    return $response->withHeader('Content-Type', 'application/json');
});

$app->run();
```

> **Note:** Slim uses LIFO middleware ordering. Add Phirewall **last** with `$app->add()` so it executes **first** (outermost).

---

### Mezzio (Laminas)

Native PSR-15 support. Requires `nyholm/psr7`.

**`src/App/Factory/PhirewallMiddlewareFactory.php`**

```php
<?php

declare(strict_types=1);

namespace App\Factory;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\TrustedProxyResolver;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware as PhirewallMiddleware;
use Flowd\Phirewall\Owasp\SecRuleLoader;
use Flowd\Phirewall\Store\ApcuCache;
use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ServerRequestInterface;

class PhirewallMiddlewareFactory
{
    public function __invoke(ContainerInterface $container): PhirewallMiddleware
    {
        // ── Storage ──────────────────────────────────────────────
        // ApcuCache requires ext-apcu (zero config, single-server)
        // For multi-server: use RedisCache with predis/predis
        $cache = new ApcuCache();

        // ── Configuration ────────────────────────────────────────
        $config = new Config($cache);
        $config->setKeyPrefix('mezzio');
        $config->enableRateLimitHeaders();
        // failOpen defaults to true; call setFailOpen(false) to fail closed.

        // ── Trusted Proxies ──────────────────────────────────────
        $proxyResolver = new TrustedProxyResolver([
            '10.0.0.0/8',
            '172.16.0.0/12',
        ]);
        $config->setIpResolver(
            KeyExtractors::clientIp($proxyResolver)
        );

        // ── Safelists ────────────────────────────────────────────
        $config->safelists->add('health',
            fn(ServerRequestInterface $req): bool =>
                $req->getUri()->getPath() === '/health'
        );
        $config->safelists->trustedBots(cache: $cache);

        // ── Blocklists ───────────────────────────────────────────
        $config->blocklists->knownScanners();
        $config->blocklists->suspiciousHeaders();

        // ── OWASP Rules ──────────────────────────────────────────
        $owaspRules = SecRuleLoader::fromString(<<<'CRS'
        SecRule ARGS "@rx (?i)\bunion\b.*\bselect\b" "id:942100,phase:2,deny,msg:'SQLi'"
        SecRule ARGS "@rx (?i)<script[^>]*>" "id:941100,phase:2,deny,msg:'XSS'"
        SecRule ARGS "@rx (?i)(eval|exec|system|shell_exec|passthru)\s*\(" "id:933100,phase:2,deny,msg:'RCE'"
        CRS);
        $config->blocklists->owasp('owasp', $owaspRules);

        // ── Fail2Ban ─────────────────────────────────────────────
        // No key: these rules default to the client IP from the
        // global resolver set above.
        $config->fail2ban->add('login-abuse',
            threshold: 5,
            period: 300,
            ban: 3600,
            filter: fn(ServerRequestInterface $req): bool =>
                $req->getMethod() === 'POST'
                && $req->getUri()->getPath() === '/login',
        );

        // ── Rate Limiting ────────────────────────────────────────
        $config->throttles->add('burst',
            limit: 30, period: 5,
        );
        $config->throttles->add('global',
            limit: 1000, period: 60,
        );

        // ── Allow2Ban ────────────────────────────────────────────
        $config->allow2ban->add('flood-protection',
            threshold: 500, period: 60, banSeconds: 3600,
        );

        // ── PSR-17 Response Bodies ───────────────────────────────
        $psr17 = new Psr17Factory();
        $config->usePsr17Responses($psr17, $psr17);

        return new PhirewallMiddleware($config, $psr17);
    }
}
```

**`config/autoload/phirewall.global.php`**

```php
<?php

declare(strict_types=1);

return [
    'dependencies' => [
        'factories' => [
            \Flowd\Phirewall\Middleware::class =>
                \App\Factory\PhirewallMiddlewareFactory::class,
        ],
    ],
];
```

**`config/pipeline.php`**

```php
// ErrorHandler must be piped FIRST so it can catch exceptions thrown by
// downstream middleware and route handlers. Phirewall does not wrap the
// downstream handler in a try/catch, so a handler exception propagates
// through it; if Phirewall were piped above ErrorHandler, that exception
// would escape the error boundary and reach the emitter unhandled.
$app->pipe(\Laminas\Stratigility\Middleware\ErrorHandler::class);

// Phirewall runs as early as possible AFTER the error boundary, so it
// blocks before routing/dispatch while still being covered by ErrorHandler.
$app->pipe(\Flowd\Phirewall\Middleware::class);

// ... other middleware
$app->pipe(\Mezzio\Router\Middleware\RouteMiddleware::class);
$app->pipe(\Mezzio\Router\Middleware\DispatchMiddleware::class);
```

---

### TYPO3

**Use the official extension.** For TYPO3, install [`flowd/typo3-firewall`](https://extensions.typo3.org/extension/firewall) rather than wiring Phirewall by hand. It integrates Phirewall into TYPO3, registers the PSR-15 middleware in the frontend stack for you, and adds a backend module for managing block patterns.

```bash
composer require flowd/typo3-firewall
```

Phirewall is then configured in TYPO3's core configuration file `config/system/phirewall.php`. That file must **return a closure** that receives the PSR-14 `EventDispatcherInterface` and returns a built `Config` (the cache is the first constructor argument, the dispatcher the second). The full [Phirewall configuration](/getting-started) applies inside the closure; use one of Phirewall's bundled PSR-16 stores (`RedisCache`, `ApcuCache`, `PdoCache`), since TYPO3's own caches are not PSR-16.

```php
<?php
// config/system/phirewall.php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\ApcuCache;
use Psr\EventDispatcher\EventDispatcherInterface;

return function (EventDispatcherInterface $eventDispatcher): Config {
    $config = new Config(new ApcuCache(), $eventDispatcher);

    $config->blocklists->knownScanners();
    $config->throttles->add('burst', limit: 30, period: 5);

    return $config;
};
```

Block patterns created in the backend module are stored in `config/system/phirewall.patterns.json` and take effect immediately. See the [extension documentation](https://docs.typo3.org/p/flowd/typo3-firewall/main/en-us/) for details.

---

## Basic: Minimal Setup

The smallest useful configuration. Protects against common scanners and rate-limits all traffic.

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;

$config = new Config(new InMemoryCache());

// Allow health checks
$config->safelists->add('health',
    fn($req) => $req->getUri()->getPath() === '/health'
);

// Block scanner paths
$config->blocklists->add('scanners',
    fn($req) => str_starts_with($req->getUri()->getPath(), '/admin-panel')
);

// Block known vulnerability scanners by User-Agent
$config->blocklists->knownScanners();

// Rate limit: 100 requests per minute per IP
$config->throttles->add('api',
    limit: 100, period: 60,
);

$middleware = new Middleware($config);
```

---

## Basic: API Rate Limiting

Tiered per-client-IP rate limits for an API, with a tighter cap on an expensive endpoint.

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Http\TrustedProxyResolver;
use Flowd\Phirewall\Store\RedisCache;
use Predis\Client as PredisClient;

$redis = new PredisClient(getenv('REDIS_URL') ?: 'redis://localhost:6379');
$config = new Config(new RedisCache($redis, 'api:'));
$config->enableRateLimitHeaders();

$proxyResolver = new TrustedProxyResolver(['10.0.0.0/8', '172.16.0.0/12']);

// Global burst detection
$config->throttles->add('burst',
    limit: 30, period: 5,
    key: KeyExtractors::clientIp($proxyResolver)
);

// Global per-IP limit
$config->throttles->add('global',
    limit: 1000, period: 60,
    key: KeyExtractors::clientIp($proxyResolver)
);

// Expensive endpoint limit
$config->throttles->add('search',
    limit: 20, period: 60,
    key: function ($req) use ($proxyResolver): ?string {
        if ($req->getUri()->getPath() === '/api/search') {
            return $proxyResolver->resolve($req);
        }
        return null;
    }
);
```

---

## Advanced Rate Limiting: Sliding Window

The sliding window algorithm prevents the "double burst" problem at fixed window boundaries. With fixed windows, a client can send `limit` requests at the end of one window and another `limit` at the start of the next, effectively doubling throughput. The sliding window uses a weighted average of the current and previous window counters.

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\InMemoryCache;

$config = new Config(new InMemoryCache());

// Sliding window: 100 requests per 60 seconds per IP
$config->throttles->sliding('api-sliding',
    limit: 100,
    period: 60,
);
```

See [Rate Limiting](/features/rate-limiting) for a detailed comparison of fixed vs. sliding windows.

---

## Advanced Rate Limiting: Multi-Window

Apply multiple time windows to a single logical throttle for burst protection alongside sustained limits.

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\InMemoryCache;

$config = new Config(new InMemoryCache());

// Burst + sustained rate limiting in a single call.
// Creates "api:1s" (3 req/s burst) and "api:60s" (60 req/min sustained).
$config->throttles->multi('api', [
    1  => 3,   // 3 req/s burst limit
    60 => 60,  // 60 req/min sustained limit
]);
```

---

## Advanced Rate Limiting: Dynamic Limits

Use closures for the `limit` and/or `period` parameters to vary rate limits based on request properties (e.g., user role, subscription tier).

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\InMemoryCache;
use Psr\Http\Message\ServerRequestInterface;

$config = new Config(new InMemoryCache());
$config->enableRateLimitHeaders();

// Dynamic limit: admins get 1000 req/min, regular users get 100 req/min
$config->throttles->add('role-based',
    limit: fn(ServerRequestInterface $req): int =>
        $req->getHeaderLine('X-Role') === 'admin' ? 1000 : 100,
    period: 60,
);
```

See [Dynamic Throttle](/advanced/dynamic-throttle) for details.

---

## Login Protection: Brute Force & Credential Stuffing

Complete login protection with throttling, Fail2Ban, and tracking.

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\RedisCache;
use Predis\Client as PredisClient;

$redis = new PredisClient(getenv('REDIS_URL') ?: 'redis://localhost:6379');
$config = new Config(new RedisCache($redis));

// Track all login attempts for dashboards
$config->tracks->add('login-attempts',
    period: 3600,
    filter: fn($req) => $req->getUri()->getPath() === '/login'
        && $req->getMethod() === 'POST',
);

// Track login attempts by username for alerting
$config->tracks->add('login-by-user',
    period: 3600,
    filter: fn($req) => $req->getMethod() === 'POST'
        && $req->getUri()->getPath() === '/login',
    key: function ($req): ?string {
        $body = (array) $req->getParsedBody();
        return $body['username'] ?? $body['email'] ?? null;
    }
);

// Safelist internal health checks
$config->safelists->add('health',
    fn($req) => $req->getUri()->getPath() === '/health'
);

// Throttle login attempts: 10 per minute per IP
$config->throttles->add('login-rate',
    limit: 10, period: 60,
    key: function ($req): ?string {
        if ($req->getUri()->getPath() === '/login' && $req->getMethod() === 'POST') {
            return $req->getServerParams()['REMOTE_ADDR'] ?? null;
        }
        return null;
    }
);

// Burst detection: 3 login attempts in 10 seconds
$config->throttles->add('login-burst',
    limit: 3, period: 10,
    key: function ($req): ?string {
        if ($req->getUri()->getPath() === '/login' && $req->getMethod() === 'POST') {
            return $req->getServerParams()['REMOTE_ADDR'] ?? null;
        }
        return null;
    }
);

// Fail2Ban: ban after 5 login attempts in 5 minutes
$config->fail2ban->add('login-brute-force',
    threshold: 5,
    period: 300,
    ban: 3600,
    filter: fn($req) => $req->getMethod() === 'POST'
        && $req->getUri()->getPath() === '/login',
);

// Per-username throttle: 5 attempts per 5 minutes per username
$config->throttles->add('per-username',
    limit: 5, period: 300,
    key: function ($req): ?string {
        if ($req->getUri()->getPath() !== '/login') return null;
        $body = (array) $req->getParsedBody();
        $username = $body['username'] ?? $body['email'] ?? null;
        return $username ? 'user:' . strtolower(trim($username)) : null;
    }
);
```

---

## Login Protection: Post-Handler Fail2Ban with RequestContext

Use `RequestContext` to signal fail2ban failures after verifying credentials in your handler, rather than counting every login POST:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Context\RequestContext;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\InMemoryCache;
use Psr\Http\Message\ServerRequestInterface;

$config = new Config(new InMemoryCache());

// The filter returns false; failures are signaled programmatically
$config->fail2ban->add('login-failures',
    threshold: 3,
    period: 300,
    ban: 3600,
    filter: fn(ServerRequestInterface $req): bool => false,
);

// In your login handler:
// $context = $request->getAttribute(RequestContext::ATTRIBUTE_NAME);
// if ($loginFailed) {
//     // The firewall derives the key from the rule's own keyExtractor
//     // No need to repeat the IP/header/etc. extraction here.
//     $context?->recordFailure('login-failures');
// }
```

The middleware automatically processes recorded signals after the handler returns. Use `$context->recordHit('rule-name')` for allow2ban rules. See [Request Context](/advanced/request-context) for the full API.

---

## Allow2Ban: Volume-Based Banning

Allow2Ban is the inverse of Fail2Ban: it counts every request for a key and bans after a threshold, without needing a filter predicate.

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;

$config = new Config(new InMemoryCache());

// Ban any IP that sends more than 100 requests in 60 seconds for 1 hour
$config->allow2ban->add('high-volume-ban',
    threshold: 100,
    period: 60,
    banSeconds: 3600,
);
```

See [Fail2Ban & Allow2Ban](/features/fail2ban) for details.

---

## Bot Detection: Known Scanners

Block known vulnerability scanners and attack tools by User-Agent:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Matchers\KnownScannerMatcher;
use Flowd\Phirewall\Store\InMemoryCache;

$config = new Config(new InMemoryCache());

// Block all known scanners with default patterns
// Matches: sqlmap, nikto, nmap, masscan, nuclei, gobuster, wfuzz, hydra, etc.
$config->blocklists->knownScanners();

// Extend defaults with custom patterns
$config->blocklists->knownScanners('extended-scanners', [
    ...KnownScannerMatcher::DEFAULT_PATTERNS,
    'my-internal-tool',
]);

// Or use only your own list
// $config->blocklists->knownScanners('custom', ['my-tool', 'other-tool']);
```

---

## Bot Detection: Trusted Bot Verification

Safelist verified search engine bots using reverse DNS (RDNS) verification. Only bots whose IPs resolve to known hostnames (e.g., `*.googlebot.com`) are safelisted:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;

$cache = new InMemoryCache();
$config = new Config($cache);

// Safelist known bots (Googlebot, Bingbot, Baidu, etc.) via RDNS
// Pass a PSR-16 cache to avoid repeated DNS lookups
$config->safelists->trustedBots(cache: $cache);

// Safelist a custom internal bot
$config->safelists->trustedBots('custom-bots', [
    ['ua' => 'mycompany-crawler', 'hostname' => '.crawler.mycompany.com'],
], cache: $cache);
```

See [Bot Detection](/features/bot-detection) for details.

---

## Bot Detection: Suspicious Headers

Block requests that are missing standard HTTP headers which real browsers always send:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;

$config = new Config(new InMemoryCache());

// Block requests missing Accept, Accept-Language, Accept-Encoding
$config->blocklists->suspiciousHeaders();

// Or specify custom required headers for API endpoints
$config->blocklists->suspiciousHeaders('api-headers', ['Authorization', 'X-API-Key']);
```

---

## IP-Based Rules

Safelist and blocklist by IP address or CIDR range:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;

$config = new Config(new InMemoryCache());

// Safelist office and internal networks
$config->safelists->ip('office', ['10.0.0.0/8', '192.168.1.0/24']);
$config->safelists->ip('monitoring', '172.16.0.100');

// Blocklist known bad actors
$config->blocklists->ip('bad-actors', ['198.51.100.0/24', '203.0.113.50']);

// File-backed dynamic blocklist (updated by external tools)
$config->blocklists->fileIp('banned-ips', '/var/lib/phirewall/banned.txt');
```

---

## Track: Passive Monitoring with Thresholds

Track rules count requests passively without blocking. Use the optional `limit` parameter to get a `thresholdReached` flag in the `TrackHit` event for alerting:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\InMemoryCache;

$config = new Config(new InMemoryCache());

// Track every login attempt (thresholdReached always false)
$config->tracks->add('every-login-attempt',
    period: 60,
    filter: fn($req) => $req->getUri()->getPath() === '/login',
);

// Track with threshold: thresholdReached=true at 5+ hits
$config->tracks->add('suspicious-login-burst',
    period: 60,
    filter: fn($req) => $req->getUri()->getPath() === '/login',
    limit: 5,
);
```

See [Track & Notifications](/advanced/track-notifications) for details.

---

## PdoCache: Database Storage Backend

Use PdoCache with MySQL, PostgreSQL, or SQLite when Redis is not available:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\PdoCache;

// SQLite with file persistence and WAL mode
$pdo = new PDO('sqlite:/var/lib/phirewall/cache.db');
$pdo->exec('PRAGMA journal_mode=WAL');
$cache = new PdoCache($pdo);

$config = new Config($cache);
$config->throttles->add('api', limit: 100, period: 60);

// MySQL (shared across multiple app servers)
// $pdo = new PDO('mysql:host=db.example.com;dbname=myapp', getenv('DB_USER'), getenv('DB_PASSWORD'));
// $cache = new PdoCache($pdo);

// PostgreSQL
// $pdo = new PDO('pgsql:host=db.example.com;dbname=myapp', getenv('DB_USER'), getenv('DB_PASSWORD'));
// $cache = new PdoCache($pdo);

// Custom table name
// $cache = new PdoCache($pdo, 'my_firewall_cache');
```

See [Storage Backends](/features/storage) for a detailed comparison.

---

## PSR-17: Custom Response Bodies

Use PSR-17 factories for custom blocked/throttled response bodies:

::: code-group

```php [Quick Setup]
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Factory\Psr17Factory;

$config = new Config(new InMemoryCache());
$psr17Factory = new Psr17Factory();

// Configure both response factories in one call
$config->usePsr17Responses($psr17Factory, $psr17Factory);
```

```php [Custom Body Text]
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\Response\Psr17BlocklistedResponseFactory;
use Flowd\Phirewall\Config\Response\Psr17ThrottledResponseFactory;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Factory\Psr17Factory;

$config = new Config(new InMemoryCache());
$psr17Factory = new Psr17Factory();

$config->blocklistedResponseFactory = new Psr17BlocklistedResponseFactory(
    $psr17Factory,
    $psr17Factory,
    'Access Denied. Your request has been blocked.',
);

$config->throttledResponseFactory = new Psr17ThrottledResponseFactory(
    $psr17Factory,
    $psr17Factory,
    'Rate limit exceeded. Please slow down.',
);
```

:::

See [PSR-17 Factories](/advanced/psr17) for details.

---

## Production: Comprehensive Multi-Layer Protection

A production-ready configuration combining safelists, blocklists, OWASP rules, bot detection, Fail2Ban, rate limiting, and observability.

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\TrustedProxyResolver;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Owasp\SecRuleLoader;
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Phirewall\Store\RedisCache;
use Flowd\Phirewall\Config\Response\ClosureBlocklistedResponseFactory;
use Flowd\Phirewall\Config\Response\ClosureThrottledResponseFactory;
use Nyholm\Psr7\Response;
use Predis\Client as PredisClient;

// --- Storage ---
$redis = new PredisClient(getenv('REDIS_URL') ?: 'redis://localhost:6379');
$cache = new RedisCache($redis, 'myapp:fw:');

// --- Config ---
$config = new Config($cache);
$config->setKeyPrefix('prod');
$config->enableRateLimitHeaders();
$config->setFailOpen(true); // Fail open on cache errors (default)

// --- Trusted Proxies ---
$proxyResolver = new TrustedProxyResolver([
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
]);

// Set global IP resolver so all IP-aware matchers use it
$config->setIpResolver(KeyExtractors::clientIp($proxyResolver));

// === SAFELISTS ===
$config->safelists->add('health',
    fn($req) => $req->getUri()->getPath() === '/health'
);
$config->safelists->add('metrics',
    fn($req) => $req->getUri()->getPath() === '/metrics'
);
$config->safelists->trustedBots(cache: $cache);

// === BLOCKLISTS ===

// Known vulnerability scanners
$config->blocklists->knownScanners();

// Suspicious headers (missing standard browser headers)
$config->blocklists->suspiciousHeaders();

// Scanner paths
$config->blocklists->patternBlocklist('scanner-paths', [
    new PatternEntry(PatternKind::PATH_PREFIX, '/admin-panel'),
    new PatternEntry(PatternKind::PATH_PREFIX, '/admin-login'),
    new PatternEntry(PatternKind::PATH_PREFIX, '/phpmyadmin'),
    new PatternEntry(PatternKind::PATH_EXACT, '/.env'),
    new PatternEntry(PatternKind::PATH_PREFIX, '/.git/'),
    new PatternEntry(PatternKind::PATH_EXACT, '/phpinfo.php'),
    new PatternEntry(PatternKind::PATH_REGEX, '/\.(sql|bak|old)$/i'),
]);

// Path traversal
$config->blocklists->add('path-traversal', function ($req): bool {
    $input = urldecode($req->getUri()->getPath() . '?' . $req->getUri()->getQuery());
    return preg_match('~\.\.[\\\\/]~', $input) === 1;
});

// === OWASP RULES ===
$owaspRules = SecRuleLoader::fromString(<<<'CRS'
SecRule ARGS "@rx (?i)\bunion\b.*\bselect\b" "id:942100,phase:2,deny,msg:'SQLi'"
SecRule ARGS "@rx (?i)<script[^>]*>" "id:941100,phase:2,deny,msg:'XSS'"
SecRule ARGS "@rx (?i)(eval|exec|system|shell_exec|passthru)\s*\(" "id:933100,phase:2,deny,msg:'RCE'"
SecRule REQUEST_URI "@rx \.\.\/" "id:930100,phase:2,deny,msg:'Path Traversal'"
CRS);
$config->blocklists->owasp('owasp', $owaspRules);

// === FAIL2BAN ===
$config->fail2ban->add('login-abuse',
    threshold: 5, period: 300, ban: 3600,
    filter: fn($req) => $req->getMethod() === 'POST'
        && $req->getUri()->getPath() === '/login',
    key: KeyExtractors::clientIp($proxyResolver)
);

$config->fail2ban->add('persistent-scanner',
    threshold: 10, period: 60, ban: 86400,
    filter: fn($req) => true,
    key: KeyExtractors::clientIp($proxyResolver)
);

// === ALLOW2BAN ===
$config->allow2ban->add('flood-protection',
    threshold: 500, period: 60, banSeconds: 3600,
    key: KeyExtractors::clientIp($proxyResolver)
);

// === THROTTLES ===
$config->throttles->add('global',
    limit: 1000, period: 60,
    key: KeyExtractors::clientIp($proxyResolver)
);

$config->throttles->add('burst',
    limit: 50, period: 5,
    key: KeyExtractors::clientIp($proxyResolver)
);

$config->throttles->add('write-ops',
    limit: 100, period: 60,
    key: function ($req) use ($proxyResolver): ?string {
        if (in_array($req->getMethod(), ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            return $proxyResolver->resolve($req);
        }
        return null;
    }
);

$config->throttles->add('login',
    limit: 10, period: 60,
    key: function ($req) use ($proxyResolver): ?string {
        if ($req->getUri()->getPath() === '/login') {
            return $proxyResolver->resolve($req);
        }
        return null;
    }
);

// === CUSTOM RESPONSES ===
$config->blocklistedResponseFactory = new ClosureBlocklistedResponseFactory(
    function (string $rule, string $type, $req) {
        return new Response(
            403,
            ['Content-Type' => 'application/json'],
            json_encode(['error' => 'Access denied', 'code' => 'BLOCKED'])
        );
    }
);

$config->throttledResponseFactory = new ClosureThrottledResponseFactory(
    function (string $rule, int $retryAfter, $req) {
        return new Response(
            429,
            ['Content-Type' => 'application/json'],
            json_encode([
                'error' => 'Rate limit exceeded',
                'code' => 'RATE_LIMITED',
                'retry_after' => $retryAfter,
            ])
        );
    }
);

// === MIDDLEWARE ===
$middleware = new Middleware($config);
```

---

## Production: OWASP Protection Suite

SQL injection (SQLi), XSS (Cross-Site Scripting), PHP injection, and path traversal detection:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Owasp\SecRuleLoader;
use Flowd\Phirewall\Store\RedisCache;
use Predis\Client as PredisClient;

$redis = new PredisClient(getenv('REDIS_URL') ?: 'redis://localhost:6379');
$config = new Config(new RedisCache($redis));

$rules = SecRuleLoader::fromString(<<<'CRS'
# SQL Injection
SecRule ARGS "@rx (?i)(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b)" \
    "id:942100,phase:2,deny,msg:'SQL Injection'"
SecRule ARGS "@rx ('\s*(or|and)\s*'|'\s*=\s*')" \
    "id:942120,phase:2,deny,msg:'SQL Quote Injection'"

# XSS
SecRule ARGS "@rx (?i)<script[^>]*>" \
    "id:941100,phase:2,deny,msg:'XSS Script Tag'"
SecRule ARGS "@rx (?i)\bon\w+\s*=" \
    "id:941110,phase:2,deny,msg:'XSS Event Handler'"
SecRule ARGS "@rx (?i)javascript\s*:" \
    "id:941120,phase:2,deny,msg:'XSS JavaScript Protocol'"

# PHP Injection
SecRule ARGS "@rx (?i)(eval|exec|system|shell_exec|passthru)\s*\(" \
    "id:933100,phase:2,deny,msg:'PHP Code Injection'"
SecRule ARGS "@rx (?i)(base64_decode|gzinflate|str_rot13)\s*\(" \
    "id:933110,phase:2,deny,msg:'PHP Obfuscation'"

# Path Traversal
SecRule REQUEST_URI "@rx \.\.\/" \
    "id:930100,phase:2,deny,msg:'Path Traversal'"
SecRule REQUEST_URI "@rx (?i)(%2e%2e%2f|%2e%2e/)" \
    "id:930110,phase:2,deny,msg:'Encoded Path Traversal'"
CRS);

$config->blocklists->owasp('owasp-suite', $rules);

// Optionally disable specific rules that cause false positives
// $rules->disable(941110); // XSS Event Handler might be too aggressive
```

See [OWASP CRS](/features/owasp-crs) for details.

---

## Production: Observability with Monolog

Full logging setup with different severity levels:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\RedisCache;
use Flowd\Phirewall\Events\BlocklistMatched;
use Flowd\Phirewall\Events\ThrottleExceeded;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Flowd\Phirewall\Events\Allow2BanBanned;
use Flowd\Phirewall\Events\SafelistMatched;
use Flowd\Phirewall\Events\FirewallError;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Predis\Client as PredisClient;
use Psr\EventDispatcher\EventDispatcherInterface;

$redis = new PredisClient(getenv('REDIS_URL') ?: 'redis://localhost:6379');

$logger = new Logger('phirewall');
$logger->pushHandler(new StreamHandler('/var/log/phirewall.log', Logger::INFO));
$logger->pushHandler(new StreamHandler('/var/log/phirewall-attacks.log', Logger::WARNING));

$dispatcher = new class ($logger) implements EventDispatcherInterface {
    public function __construct(private Logger $logger) {}

    public function dispatch(object $event): object
    {
        $context = [];
        if (property_exists($event, 'rule')) $context['rule'] = $event->rule;
        if (property_exists($event, 'key')) $context['key'] = $event->key;
        if (property_exists($event, 'serverRequest')) {
            $req = $event->serverRequest;
            $context['ip'] = $req->getServerParams()['REMOTE_ADDR'] ?? 'unknown';
            $context['path'] = $req->getUri()->getPath();
        }

        match (true) {
            $event instanceof Fail2BanBanned => $this->logger->warning('IP banned by fail2ban', $context),
            $event instanceof Allow2BanBanned => $this->logger->warning('IP banned by allow2ban', $context),
            $event instanceof BlocklistMatched => $this->logger->warning('Request blocklisted', $context),
            $event instanceof ThrottleExceeded => $this->logger->notice('Rate limited', $context),
            $event instanceof SafelistMatched => $this->logger->debug('Safelisted', $context),
            $event instanceof FirewallError => $this->logger->error('Firewall error', ['error' => $event->exception->getMessage()]),
            default => null,
        };

        return $event;
    }
};

$config = new Config(new RedisCache($redis), $dispatcher);
$config->throttles->add('api', limit: 100, period: 60);
$config->fail2ban->add('login', threshold: 5, period: 300, ban: 3600,
    filter: fn($req) => $req->getMethod() === 'POST'
        && $req->getUri()->getPath() === '/login',
);
```

See [Observability](/advanced/observability) for details.

---

## Production: Bot Detection & IP Blocking

Complete bot defense with threat feeds and file-backed blocklists:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\RedisCache;
use Predis\Client as PredisClient;

$redis = new PredisClient(getenv('REDIS_URL') ?: 'redis://localhost:6379');
$config = new Config(new RedisCache($redis));

// Known scanner User-Agents (built-in list)
$config->blocklists->knownScanners();

// Suspicious headers (missing standard browser headers)
$config->blocklists->suspiciousHeaders();

// File-backed dynamic blocklist (updated by external tools)
$config->blocklists->filePatternBlocklist('dynamic',
    '/var/lib/phirewall/dynamic-blocks.txt'
);

// IP blocklist from file
$config->blocklists->fileIp('banned-ips', '/var/lib/phirewall/banned.txt');

// IP blocklist from CIDR ranges
$config->blocklists->ip('known-bad', ['198.51.100.0/24', '203.0.113.0/24']);

// Auto-ban persistent scanners
$config->fail2ban->add('persistent-scanner',
    threshold: 10, period: 60, ban: 86400,
    filter: fn($req) => true,
);

// Global rate limit as backstop
$config->throttles->add('global',
    limit: 100, period: 60,
);
```
