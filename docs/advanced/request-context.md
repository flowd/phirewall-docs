---
outline: deep
---

# Request Context

The `RequestContext` API lets your application signal fail2ban failures **from inside the request handler** -- after the firewall has already passed the request through. This solves a fundamental limitation: standard fail2ban filters run _before_ your handler, so they cannot see whether credentials were valid, whether a payment failed, or whether an API key was revoked.

## The Problem

Standard fail2ban rules use a filter predicate that evaluates the incoming request. This works for simple patterns (like "every POST to /login counts as a failure attempt"), but it cannot distinguish between successful and failed logins:

```php
// Problem: this counts EVERY POST to /login, including successful logins
$config->fail2ban->add('login',
    threshold: 5, period: 300, ban: 3600,
    filter: fn($request) => $request->getMethod() === 'POST'
        && $request->getUri()->getPath() === '/login',
    key: KeyExtractors::ip(),
);
```

With `RequestContext`, your handler verifies the credentials first, then signals a failure **only when authentication actually fails**. This gives you precise control over what counts as a failure.

## How It Works

The flow has three stages:

```text
1. Middleware evaluates request
   └── Attaches a mutable RequestContext to the PSR-7 request attribute

2. Handler runs your application logic
   └── Retrieves the context and calls recordFailure() if needed

3. Middleware runs post-handler processing
   └── Processes all recorded failures through the fail2ban engine
```

Here is what happens step by step:

1. The middleware calls the firewall's `decide()` method on the incoming request
2. If the request passes (is not blocked), the middleware creates a `RequestContext` and attaches it to the request as a PSR-7 attribute named `phirewall.context`
3. Your handler receives the request with the attached context
4. If your handler determines that the request represents a failure (wrong password, invalid API key, etc.), it calls `$context->recordFailure('rule-name', 'key')`
5. After your handler returns a response, the middleware checks for recorded failures and processes them through the fail2ban counter engine
6. If the failure count crosses the threshold, the key is banned for future requests

## Setup

Configure a fail2ban rule with a filter that **always returns `false`**. This means the firewall never counts failures automatically -- your handler does it instead:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Psr\Http\Message\ServerRequestInterface;

$config = new Config(new InMemoryCache());

// The filter returns false -- no request is counted automatically.
// Failures are recorded programmatically via RequestContext in your handler.
$config->fail2ban->add('login-failures',
    threshold: 3,
    period: 300,
    ban: 3600,
    filter: fn(ServerRequestInterface $request): bool => false,
    key: KeyExtractors::ip(),
);

$middleware = new Middleware($config);
```

::: tip Why `filter: fn() => false`?
The filter still exists because the fail2ban rule requires one. Setting it to always return `false` means the pre-handler phase never counts any request as a failure -- all failure counting is deferred to your handler via `RequestContext`.
:::

## Recording Failures in Your Handler

Retrieve the `RequestContext` from the request attribute and call `recordFailure()`:

```php
use Flowd\Phirewall\Context\RequestContext;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class LoginHandler implements RequestHandlerInterface
{
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $username = $request->getParsedBody()['username'] ?? '';
        $password = $request->getParsedBody()['password'] ?? '';

        if (!$this->authenticate($username, $password)) {
            // Retrieve the RequestContext attached by the middleware
            /** @var RequestContext|null $context */
            $context = $request->getAttribute(RequestContext::ATTRIBUTE_NAME);

            // Signal the failure -- use the null-safe operator for safety
            $ip = $request->getServerParams()['REMOTE_ADDR'] ?? 'unknown';
            $context?->recordFailure('login-failures', $ip);

            return new JsonResponse(['error' => 'Invalid credentials'], 401);
        }

        return new JsonResponse(['success' => true, 'user' => $username], 200);
    }
}
```

::: warning Rule name must match
The first parameter to `recordFailure()` must **exactly** match the `name` you used in `$config->fail2ban->add()`. If no matching rule is found, the failure signal is silently ignored.
:::

## API Reference

### RequestContext

The `RequestContext` class is a mutable recorder that the middleware attaches to the PSR-7 request.

| Method | Signature | Description |
|--------|-----------|-------------|
| `recordFailure()` | `(string $ruleName, string $key): void` | Record a fail2ban failure signal |
| `getResult()` | `(): FirewallResult` | Access the pre-handler firewall decision |
| `getRecordedFailures()` | `(): list<RecordedFailure>` | Get all recorded failure signals |
| `hasRecordedSignals()` | `(): bool` | Whether any failures have been recorded |

**Constants:**

| Constant | Value | Description |
|----------|-------|-------------|
| `RequestContext::ATTRIBUTE_NAME` | `'phirewall.context'` | PSR-7 request attribute key |

### recordFailure() Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `$ruleName` | `string` | Must match the `name` of a configured `fail2ban->add()` rule |
| `$key` | `string` | The discriminator key to count failures against (e.g., IP address, username) |

### RecordedFailure

An immutable value object representing a single failure signal.

| Property | Type | Description |
|----------|------|-------------|
| `$ruleName` | `string` | The fail2ban rule this failure is recorded against |
| `$key` | `string` | The discriminator key |

## Accessing the Firewall Decision

The `RequestContext` also gives your handler access to the pre-handler firewall decision via `getResult()`. This returns a `FirewallResult` object:

```php
use Flowd\Phirewall\Context\RequestContext;

/** @var RequestContext|null $context */
$context = $request->getAttribute(RequestContext::ATTRIBUTE_NAME);

if ($context !== null) {
    $result = $context->getResult();

    $result->outcome->value;  // 'passed', 'safelisted', etc.
    $result->isPass();        // true if the request was allowed through
    $result->rule;            // Name of the matching rule (null if simply passed)
}
```

This is useful for:
- **Logging**: record which safelist rule matched a request
- **Conditional behavior**: adjust handler logic based on whether the request was safelisted
- **Admin dashboards**: display the firewall decision alongside other request metadata

## Null-Safe Access Pattern

When your handler might run without the Phirewall middleware in the stack (for example, in unit tests or a different environment), always use PHP's null-safe operator (`?->`):

```php
$context = $request->getAttribute(RequestContext::ATTRIBUTE_NAME);
$context?->recordFailure('login-failures', $ip);
```

If the middleware is not present, `$context` is `null` and the `recordFailure()` call is silently skipped -- no errors, no side effects. This makes your handler safe to use with or without Phirewall.

## Complete Example

A full, runnable example showing login protection with post-handler failure signaling:

```php
<?php

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Context\RequestContext;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

// 1. Configure fail2ban with a filter that never matches
$config = new Config(new InMemoryCache());
$config->fail2ban->add('login-failures',
    threshold: 3,
    period: 300,
    ban: 3600,
    filter: fn(ServerRequestInterface $request): bool => false,
    key: KeyExtractors::ip(),
);

$middleware = new Middleware($config, new Psr17Factory());

// 2. Handler that checks credentials and signals failures
$handler = new class implements RequestHandlerInterface {
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $username = $request->getHeaderLine('X-Username');
        $password = $request->getHeaderLine('X-Password');

        if ($username !== 'admin' || $password !== 'secret') {
            /** @var RequestContext|null $context */
            $context = $request->getAttribute(RequestContext::ATTRIBUTE_NAME);
            $ip = $request->getServerParams()['REMOTE_ADDR'] ?? 'unknown';
            $context?->recordFailure('login-failures', $ip);

            return new Response(401, ['Content-Type' => 'application/json'],
                json_encode(['error' => 'Invalid credentials'])
            );
        }

        return new Response(200, ['Content-Type' => 'application/json'],
            json_encode(['success' => true])
        );
    }
};

// 3. Simulate failed login attempts
$attackerIp = '10.0.0.50';

for ($i = 1; $i <= 3; ++$i) {
    $request = new ServerRequest('POST', '/login',
        ['X-Username' => 'admin', 'X-Password' => 'wrong'],
        null, '1.1', ['REMOTE_ADDR' => $attackerIp]
    );
    $response = $middleware->process($request, $handler);
    echo "Attempt {$i}: {$response->getStatusCode()}\n";
    // Output: 401, 401, 401
}

// 4. Next request is banned (even with correct credentials)
$request = new ServerRequest('POST', '/login',
    ['X-Username' => 'admin', 'X-Password' => 'secret'],
    null, '1.1', ['REMOTE_ADDR' => $attackerIp]
);
$response = $middleware->process($request, $handler);
echo "Attempt 4: {$response->getStatusCode()}\n";
// Output: 403 (banned)

// 5. Other IPs are not affected
$request = new ServerRequest('POST', '/login',
    ['X-Username' => 'admin', 'X-Password' => 'secret'],
    null, '1.1', ['REMOTE_ADDR' => '10.0.0.200']
);
$response = $middleware->process($request, $handler);
echo "Other IP: {$response->getStatusCode()}\n";
// Output: 200 (allowed)
```

## Fail-Open Behavior

If an error occurs while processing recorded failure signals (for example, a cache connection failure), the middleware follows the configured fail-open/fail-closed behavior:

- **Fail-open** (default): errors are caught, a `FirewallError` event is dispatched for logging, and the handler's response is returned normally
- **Fail-closed** (`$config->setFailOpen(false)`): exceptions propagate to the caller

This means that even if the cache backend goes down after your handler runs, the user still receives the handler's response. The failure signal is lost, but the application remains available.

See [Getting Started: Fail-Open / Fail-Closed](/getting-started#fail-open-fail-closed) for configuration.

## When to Use RequestContext vs. Filter

| Approach | When to Use | Example |
|----------|-------------|---------|
| **Filter predicate** | Failures determined by request properties alone | Block every POST to `/admin` |
| **RequestContext** | Failures require application logic | Ban after 3 failed password attempts |

### Use the filter when:
- The request URI, method, or headers are enough to determine failure
- You do not need to inspect the response or run business logic

### Use RequestContext when:
- You need to verify credentials before deciding if the request is a failure
- The failure depends on a database lookup, API call, or response status
- You want to count only **actual** failures, not all requests to an endpoint

## Testing

Verify that failures recorded via `RequestContext` trigger bans:

```php
use PHPUnit\Framework\TestCase;
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Context\RequestContext;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class RequestContextTest extends TestCase
{
    public function testFailuresRecordedViaContextTriggerBan(): void
    {
        $config = new Config(new InMemoryCache());
        $config->fail2ban->add('test-rule',
            threshold: 2, period: 300, ban: 3600,
            filter: fn($request): bool => false,
            key: KeyExtractors::ip(),
        );

        $middleware = new Middleware($config, new Psr17Factory());
        $firewall = new Firewall($config);

        // Handler that always records a failure
        $handler = new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface
            {
                $context = $request->getAttribute(RequestContext::ATTRIBUTE_NAME);
                $ip = $request->getServerParams()['REMOTE_ADDR'] ?? '0.0.0.0';
                $context?->recordFailure('test-rule', $ip);
                return new Response(401);
            }
        };

        $ip = '10.0.0.1';

        // 2 failures should trigger the ban
        for ($i = 0; $i < 2; ++$i) {
            $request = new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => $ip]);
            $middleware->process($request, $handler);
        }

        // Verify the IP is now banned
        $this->assertTrue($firewall->isBanned('test-rule', $ip));
    }
}
```

## Related Pages

- [Fail2Ban & Allow2Ban](/features/fail2ban) -- fail2ban rule configuration and filter predicates
- [Track & Notifications](/advanced/track-notifications) -- passive counting without blocking
- [Observability](/advanced/observability) -- events and diagnostics
- [Getting Started](/getting-started) -- full setup walkthrough
