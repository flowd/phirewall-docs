---
outline: deep
---

# PSR-17 Response Factories

Phirewall generates HTTP responses (`403 Forbidden`, `429 Too Many Requests`) when blocking or throttling requests. It uses PSR-17 response factories to create these responses, ensuring compatibility with any PSR-7 implementation.

There are two layers of response customization:

1. **Base response factory** -- the `ResponseFactoryInterface` used by the `Middleware` to create bare responses (status code + headers). Auto-detected or injected explicitly.
2. **Custom response factories** -- optional `BlocklistedResponseFactoryInterface` and `ThrottledResponseFactoryInterface` on `Config` that produce complete responses with body text, content negotiation, etc.

## Auto-Detection

The `Middleware` constructor automatically detects your PSR-17 response factory from common PSR-7/17 libraries. If any of the following packages are installed, Phirewall finds the factory automatically:

| Package | Factory Class |
|---------|---------------|
| `nyholm/psr7` (recommended) | `Nyholm\Psr7\Factory\Psr17Factory` |
| `guzzlehttp/psr7` | `GuzzleHttp\Psr7\HttpFactory` |
| `http-interop/http-factory-guzzle` | `Http\Factory\Guzzle\ResponseFactory` |
| `laminas/laminas-diactoros` | `Laminas\Diactoros\ResponseFactory` |
| `slim/psr7` | `Slim\Psr7\Factory\ResponseFactory` |

```php
use Flowd\Phirewall\Middleware;

// Auto-detects PSR-17 factory from installed packages
$middleware = new Middleware($config);
```

If no supported package is found, a `RuntimeException` is thrown. We recommend:

```bash
composer require nyholm/psr7
```

## Explicit Factory

Pass your own factory to the `Middleware` constructor:

```php
use Flowd\Phirewall\Middleware;
use Nyholm\Psr7\Factory\Psr17Factory;

$middleware = new Middleware($config, new Psr17Factory());
```

This is useful when your DI container provides a custom `ResponseFactoryInterface` implementation.

## Response Body with `usePsr17Responses()`

By default, blocked and throttled responses have the correct status code and headers but an empty body. The `usePsr17Responses()` convenience method on `Config` configures both `BlocklistedResponseFactoryInterface` and `ThrottledResponseFactoryInterface` using PSR-17 factories, adding proper body text to responses.

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Factory\Psr17Factory;

$psr17 = new Psr17Factory();
$config = new Config(new InMemoryCache());

// Adds "Forbidden" body to 403 responses and "Too Many Requests" body to 429 responses
$config->usePsr17Responses($psr17, $psr17);
```

### Method Signature

```php
$config->usePsr17Responses(
    ResponseFactoryInterface $responseFactory,
    ?StreamFactoryInterface $streamFactory = null,
): Config
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$responseFactory` | `ResponseFactoryInterface` | Creates the HTTP response objects |
| `$streamFactory` | `?StreamFactoryInterface` | Creates response body streams. Without it, responses have an empty body. |

::: tip
Many PSR-17 implementations (like `nyholm/psr7`) implement both `ResponseFactoryInterface` and `StreamFactoryInterface` in a single class. Pass the same instance for both parameters.
:::

Internally, `usePsr17Responses()` creates a `Psr17BlocklistedResponseFactory` (body: `"Forbidden"`) and a `Psr17ThrottledResponseFactory` (body: `"Too Many Requests"`).

## Built-In PSR-17 Response Factories

For more control over the default body text, instantiate the factories directly.

### Psr17BlocklistedResponseFactory

Creates `403 Forbidden` responses with a configurable body:

```php
use Flowd\Phirewall\Config\Response\Psr17BlocklistedResponseFactory;
use Nyholm\Psr7\Factory\Psr17Factory;

$psr17 = new Psr17Factory();

$config->blocklistedResponseFactory = new Psr17BlocklistedResponseFactory(
    $psr17,           // ResponseFactoryInterface
    $psr17,           // StreamFactoryInterface (optional)
    'Access Denied',  // Custom body text (default: "Forbidden")
);
```

### Psr17ThrottledResponseFactory

Creates `429 Too Many Requests` responses with a configurable body and `Retry-After` header:

```php
use Flowd\Phirewall\Config\Response\Psr17ThrottledResponseFactory;
use Nyholm\Psr7\Factory\Psr17Factory;

$psr17 = new Psr17Factory();

$config->throttledResponseFactory = new Psr17ThrottledResponseFactory(
    $psr17,                     // ResponseFactoryInterface
    $psr17,                     // StreamFactoryInterface (optional)
    'Rate limit exceeded.',     // Custom body text (default: "Too Many Requests")
);
```

## Custom Response Factories (Closure)

For full control over the response (status code, headers, body, content negotiation), use the closure-based factories.

### Custom Blocked Response (403)

```php
use Flowd\Phirewall\Config\Response\ClosureBlocklistedResponseFactory;
use Nyholm\Psr7\Response;

$config->blocklistedResponseFactory = new ClosureBlocklistedResponseFactory(
    function (string $rule, string $type, $request) {
        return new Response(
            403,
            ['Content-Type' => 'application/json'],
            json_encode([
                'error' => 'Access denied',
                'code' => 'BLOCKED',
                'rule' => $rule,
                'type' => $type,  // 'blocklist', 'fail2ban', or 'allow2ban'
            ])
        );
    }
);
```

The closure receives:

| Parameter | Type | Description |
|-----------|------|-------------|
| `$rule` | `string` | Name of the rule that triggered the block |
| `$type` | `string` | Block type: `blocklist`, `fail2ban`, or `allow2ban` |
| `$request` | `ServerRequestInterface` | The original request |

### Custom Throttled Response (429)

```php
use Flowd\Phirewall\Config\Response\ClosureThrottledResponseFactory;
use Nyholm\Psr7\Response;

$config->throttledResponseFactory = new ClosureThrottledResponseFactory(
    function (string $rule, int $retryAfter, $request) {
        return new Response(
            429,
            ['Content-Type' => 'application/json'],
            json_encode([
                'error' => 'Rate limit exceeded',
                'code' => 'RATE_LIMITED',
                'rule' => $rule,
                'retry_after' => $retryAfter,
            ])
        );
    }
);
```

The closure receives:

| Parameter | Type | Description |
|-----------|------|-------------|
| `$rule` | `string` | Name of the throttle rule that triggered |
| `$retryAfter` | `int` | Seconds until the client can retry |
| `$request` | `ServerRequestInterface` | The original request |

::: tip
Phirewall automatically adds `Retry-After` and any `X-RateLimit-*` headers to your custom response. When `enableResponseHeaders()` is active, `X-Phirewall` and `X-Phirewall-Matched` headers are also included. You do not need to set these headers yourself.
:::

## Implementing Your Own Factory

Both `BlocklistedResponseFactoryInterface` and `ThrottledResponseFactoryInterface` are simple single-method interfaces. Implement them for full control:

### BlocklistedResponseFactoryInterface

```php
use Flowd\Phirewall\Config\Response\BlocklistedResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class MyBlockedResponseFactory implements BlocklistedResponseFactoryInterface
{
    public function create(
        string $rule,
        string $type,
        ServerRequestInterface $serverRequest,
    ): ResponseInterface {
        // Return your custom 403 response
    }
}

$config->blocklistedResponseFactory = new MyBlockedResponseFactory();
```

### ThrottledResponseFactoryInterface

```php
use Flowd\Phirewall\Config\Response\ThrottledResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class MyThrottledResponseFactory implements ThrottledResponseFactoryInterface
{
    public function create(
        string $rule,
        int $retryAfter,
        ServerRequestInterface $serverRequest,
    ): ResponseInterface {
        // Return your custom 429 response
    }
}

$config->throttledResponseFactory = new MyThrottledResponseFactory();
```

## HTML Error Pages

Serve user-friendly HTML error pages:

```php
use Flowd\Phirewall\Config\Response\ClosureBlocklistedResponseFactory;
use Nyholm\Psr7\Response;

$config->blocklistedResponseFactory = new ClosureBlocklistedResponseFactory(
    function (string $rule, string $type, $request) {
        $html = <<<'HTML'
<!DOCTYPE html>
<html>
<head><title>Access Denied</title></head>
<body>
    <h1>403 Forbidden</h1>
    <p>Your request has been blocked by our security system.</p>
    <p>If you believe this is an error, please contact support.</p>
</body>
</html>
HTML;

        return new Response(
            403,
            ['Content-Type' => 'text/html; charset=utf-8'],
            $html
        );
    }
);
```

## Content Negotiation

Serve different response formats based on the `Accept` header:

```php
use Flowd\Phirewall\Config\Response\ClosureBlocklistedResponseFactory;
use Nyholm\Psr7\Response;

$config->blocklistedResponseFactory = new ClosureBlocklistedResponseFactory(
    function (string $rule, string $type, $request) {
        $accept = $request->getHeaderLine('Accept');

        if (str_contains($accept, 'application/json')) {
            return new Response(
                403,
                ['Content-Type' => 'application/json'],
                json_encode(['error' => 'Blocked', 'rule' => $rule])
            );
        }

        if (str_contains($accept, 'text/html')) {
            return new Response(
                403,
                ['Content-Type' => 'text/html'],
                '<h1>403 Forbidden</h1><p>Access denied.</p>'
            );
        }

        return new Response(
            403,
            ['Content-Type' => 'text/plain'],
            '403 Forbidden'
        );
    }
);
```

## Complete Example

A full example combining both approaches:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\Response\Psr17BlocklistedResponseFactory;
use Flowd\Phirewall\Config\Response\Psr17ThrottledResponseFactory;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Factory\Psr17Factory;

$psr17 = new Psr17Factory();
$config = new Config(new InMemoryCache());

// Approach 1: Quick setup with default body text
$config->usePsr17Responses($psr17, $psr17);

// Approach 2: Custom body text per factory
$config->blocklistedResponseFactory = new Psr17BlocklistedResponseFactory(
    $psr17,
    $psr17,
    'Access Denied -- your request has been blocked.',
);
$config->throttledResponseFactory = new Psr17ThrottledResponseFactory(
    $psr17,
    $psr17,
    'Rate limit exceeded. Please slow down.',
);

// Configure rules
$config->blocklists->add('admin',
    fn($req) => str_starts_with($req->getUri()->getPath(), '/admin')
);
$config->throttles->add('ip', 100, 60, KeyExtractors::ip());

// Create middleware (also pass PSR-17 factory for base responses)
$middleware = new Middleware($config, $psr17);
```

## How Responses Are Built

The `Middleware` follows this logic when building blocked responses:

```text
Request blocked?
  ├── Throttled (429)
  │     ├── throttledResponseFactory set? → Use it
  │     └── Not set? → responseFactory->createResponse(429)
  │     └── Always: ensure Retry-After header
  │
  └── Blocklisted / Fail2Ban / Allow2Ban (403)
        ├── blocklistedResponseFactory set? → Use it
        └── Not set? → responseFactory->createResponse(403)

Finally: append firewall headers (Retry-After, X-RateLimit-*, and opt-in X-Phirewall headers)
```

## Framework Integration

::: code-group

```php [PSR-15]
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\ApcuCache;
use Nyholm\Psr7\Factory\Psr17Factory;

$cache  = new ApcuCache();
$config = new Config($cache);

$psr17 = new Psr17Factory();
$config->usePsr17Responses($psr17, $psr17);
// ... configure rules ...

$middleware = new Middleware($config, $psr17);
$app->pipe($middleware);
```

```php [Symfony]
// 1. Install: composer require symfony/psr-http-message-bridge nyholm/psr7
//
// 2. Register in config/services.yaml:
//    services:
//        Flowd\Phirewall\Middleware:
//            factory: ['@App\Factory\PhirewallFactory', 'create']
//
// 3. Create the factory:
namespace App\Factory;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\ApcuCache;
use Nyholm\Psr7\Factory\Psr17Factory;

class PhirewallFactory
{
    public function create(): Middleware
    {
        $cache  = new ApcuCache();
        $config = new Config($cache);

        $psr17 = new Psr17Factory();
        $config->usePsr17Responses($psr17, $psr17);

        // ... configure rules ...

        return new Middleware($config, $psr17);
    }
}
```

```php [Laravel]
// In a service provider
use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\ApcuCache;
use Nyholm\Psr7\Factory\Psr17Factory;

$this->app->singleton(Middleware::class, function ($app) {
    $cache  = new ApcuCache();
    $config = new Config($cache);

    $psr17 = new Psr17Factory();
    $config->usePsr17Responses($psr17, $psr17);

    $config->safelists->add('health',
        fn($req) => $req->getUri()->getPath() === '/health'
    );
    $config->throttles->add('global',
        limit: 100, period: 60,
        key: KeyExtractors::ip()
    );

    return new Middleware($config, $psr17);
});
```

```php [Slim]
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\ApcuCache;
use Slim\Factory\AppFactory;

$app = AppFactory::create();

$cache  = new ApcuCache();
$config = new Config($cache);
// ... configure rules ...

// Slim's PSR-17 factory is auto-detected
$middleware = new Middleware($config);
$app->add($middleware); // LIFO: add last to run first
```

```php [Mezzio]
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\ApcuCache;
use Nyholm\Psr7\Factory\Psr17Factory;

$cache  = new ApcuCache();
$config = new Config($cache);

$psr17 = new Psr17Factory();
$config->usePsr17Responses($psr17, $psr17);
// ... configure rules ...

// Mezzio uses PSR-15 natively -- pipe first
$app->pipe(new Middleware($config, $psr17));
```

:::

## API Reference

### Config Properties

| Property | Type | Description |
|----------|------|-------------|
| `$blocklistedResponseFactory` | `?BlocklistedResponseFactoryInterface` | Custom factory for 403 responses |
| `$throttledResponseFactory` | `?ThrottledResponseFactoryInterface` | Custom factory for 429 responses |

### Built-In Factory Classes

| Class | Interface | Default Body |
|-------|-----------|-------------|
| `Psr17BlocklistedResponseFactory` | `BlocklistedResponseFactoryInterface` | `"Forbidden"` |
| `Psr17ThrottledResponseFactory` | `ThrottledResponseFactoryInterface` | `"Too Many Requests"` |
| `ClosureBlocklistedResponseFactory` | `BlocklistedResponseFactoryInterface` | (closure-defined) |
| `ClosureThrottledResponseFactory` | `ThrottledResponseFactoryInterface` | (closure-defined) |

### Supported Auto-Detection Libraries

Detection order (first match wins):

1. `nyholm/psr7`
2. `guzzlehttp/psr7`
3. `http-interop/http-factory-guzzle`
4. `laminas/laminas-diactoros`
5. `slim/psr7`

## Best Practices

1. **Install `nyholm/psr7`.** It is the fastest and most lightweight PSR-7/17 implementation for PHP 8.2+.

2. **Use `usePsr17Responses()` for quick setup.** It configures both response factories in one call with sensible defaults.

3. **Return consistent error formats.** If your API uses JSON, make sure the firewall responses are also JSON. Clients should not need to handle mixed formats.

4. **Do not leak rule details in production.** While including the rule name in JSON responses helps during development, omit it in production to avoid revealing your security configuration.

5. **Set the `Content-Type` header.** Always include an appropriate `Content-Type` header in custom responses. Phirewall does not override headers you set.
