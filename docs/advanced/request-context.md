---
outline: deep
---

# Request Context

The `RequestContext` API lets your application signal post-handler events (fail2ban **failures** via `recordFailure()` and allow2ban **hits** via `recordHit()`) **from inside the request handler**, after the firewall has already passed the request through. This solves a fundamental limitation: standard fail2ban and allow2ban filters run _before_ your handler, so they cannot see whether credentials were valid, whether a payment failed, or whether an API key was revoked.

## The Problem

Standard fail2ban rules use a filter predicate that evaluates the incoming request. It cannot distinguish between successful and failed logins, and from 0.8 a fail2ban filter blocks **every** match, so this rule would reject the first legitimate login attempt with `403`:

```php
// Problem: from 0.8 this blocks EVERY POST to /login (including the first
// legitimate one), because a fail2ban match is always blocked.
$config->fail2ban->add('login',
    threshold: 5, period: 300, ban: 3600,
    filter: fn($request) => $request->getMethod() === 'POST'
        && $request->getUri()->getPath() === '/login',
);
```

With `RequestContext`, the fail2ban filter stays closed (`fn() => false`) so nothing is blocked pre-handler; your handler verifies the credentials first, then signals a failure **only when authentication fails**. This gives you precise control over what counts as a failure. (If an upstream marks failed logins with a header instead, use [Allow2Ban with a filter](/features/fail2ban#allow2ban).)

## How It Works

The flow has three stages:

```text
1. Middleware evaluates request
   └── Attaches a mutable RequestContext to the PSR-7 request attribute

2. Handler runs your application logic
   └── Retrieves the context and calls recordFailure() / recordHit() if needed

3. Middleware runs post-handler processing
   └── Routes each recorded signal to its fail2ban or allow2ban evaluator
```

Here is what happens step by step:

1. The middleware calls the firewall's `decide()` method on the incoming request
2. If the request passes (is not blocked), the middleware creates a `RequestContext` and attaches it to the request as a PSR-7 attribute named `phirewall.context`
3. Your handler receives the request with the attached context
4. If your handler determines that the request represents a failure (wrong password, invalid API key, etc.), it calls `$context->recordFailure('rule-name')`. For an allow2ban hit, it calls `$context->recordHit('rule-name')` instead. The key is derived from the matching rule's `keyExtractor`; pass an explicit second argument (`$key`) only when the handler knows a value the firewall cannot derive (e.g. a user id from a session).
5. After your handler returns a response, the middleware processes each recorded signal through the matching counter engine (fail2ban or allow2ban)
6. If the count crosses the threshold, the key is banned for future requests

By default the banning signal never changes the current response: the handler's response is delivered as-is and the ban takes effect from the next request. Opt in to a 403 for the banning request itself with `$config->enableBlockOnSignalBan()` (portable option `blockOnSignalBan`) - the middleware then replaces the handler response with the regular blocked response, including `Retry-After` for allow2ban bans.

::: warning The 403 does not stop the handler
Signals are processed after the handler returns, so the 403 only changes what the client sees. The application has already fully processed the possibly malicious request: database writes, e-mails, and other side effects have happened by the time the response is replaced. When processing must stop as soon as the failure is known, that decision belongs in the handler itself - record the signal and abort your own processing there (for example, return your error response right after `recordFailure()` instead of continuing).
:::

## Setup

Configure a fail2ban rule with a filter that **always returns `false`**. This means the firewall never counts failures automatically; your handler does it instead:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Psr\Http\Message\ServerRequestInterface;

$config = new Config(new InMemoryCache());

// The filter returns false; no request is counted automatically.
// Failures are recorded programmatically via RequestContext in your handler.
$config->fail2ban->add('login-failures',
    threshold: 3,
    period: 300,
    ban: 3600,
    filter: fn(ServerRequestInterface $request): bool => false,
);

$middleware = new Middleware($config);
```

::: tip Why `filter: fn() => false`?
The filter still exists because the fail2ban rule requires one. Setting it to always return `false` means the pre-handler phase never counts any request as a failure; all failure counting is deferred to your handler via `RequestContext`.
:::

## Recording Failures in Your Handler

Retrieve the `RequestContext` from the request attribute and call `recordFailure()`. The second argument is optional: when omitted, the firewall reuses the rule's own `keyExtractor` against this request, so the handler doesn't need to know whether the rule keys on IP, header, or anything else:

```php
use Flowd\Phirewall\Context\RequestContext;
use Nyholm\Psr7\Response;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class LoginHandler implements RequestHandlerInterface
{
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $body = (array) $request->getParsedBody();
        $username = $body['username'] ?? '';
        $password = $body['password'] ?? '';

        if (!$this->authenticate($username, $password)) {
            // Retrieve the RequestContext attached by the middleware
            /** @var RequestContext|null $context */
            $context = $request->getAttribute(RequestContext::ATTRIBUTE_NAME);

            // Signal the failure; the firewall derives the key from the
            // rule's own keyExtractor. Use the null-safe operator for safety.
            $context?->recordFailure('login-failures');

            return new Response(401, ['Content-Type' => 'application/json'], json_encode(['error' => 'Invalid credentials'], JSON_THROW_ON_ERROR));
        }

        return new Response(200, ['Content-Type' => 'application/json'], json_encode(['success' => true, 'user' => $username], JSON_THROW_ON_ERROR));
    }
}
```

If the handler knows a discriminator that the firewall cannot derive from the request alone (for example, a user id looked up in a session store), pass it as the second argument:

```php
$context?->recordFailure('login-failures', $userIdFromSession);
```

::: warning Rule name must match
The first parameter to `recordFailure()` must **exactly** match the `name` you used in `$config->fail2ban->add()` (and likewise `recordHit()` must match a `$config->allow2ban->add()` rule). If no matching rule is found, the signal is silently ignored.
:::

## Recording allow2ban Hits

`recordHit()` is the allow2ban counterpart of `recordFailure()`. The same context records **allow2ban** hits: use it to count handler-observable events the pre-handler path cannot see (an expensive operation completed, a webhook delivered a duplicate payload, a third-party API quota was charged) so the count can drive an allow2ban threshold ban. It mirrors `recordFailure()`, and `$key` is likewise optional: omit it to reuse the matching rule's key extractor on the current request.

First, configure an allow2ban rule. To make the rule count *only* the events recorded by the handler (not every request), give it a filter that never matches (`static fn() => false`); the pre-handler path then never counts, and `recordHit()` bypasses the filter so only handler-signalled hits are counted:

```php

$config->allow2ban->add(
    'expensive-endpoint',
    threshold: 5,
    period: 300,
    banSeconds: 3600,
    filter: static fn($request): bool => false,
);
```

An older idiom achieves the same by having the rule's `keyExtractor` return `null` pre-handler (`key: fn($request): ?string => null`); the firewall then skips counting until the handler signals an explicit key. The `filter: fn() => false` form above is clearer and is the recommended signal-only pattern.

In the handler, record the hit. Omit the key so the rule reuses its own key extractor (the resolved client IP by default) for this request, exactly as `recordFailure()` does:

```php
$context = $request->getAttribute(RequestContext::ATTRIBUTE_NAME);

if ($context !== null && $this->operationWasExpensive($request)) {
    $context->recordHit('expensive-endpoint');
}
```

Pass an explicit second argument only to bucket the count on something other than the rule's default key.

When the rule already counts pre-handler (it has no filter, or a filter that matches this request) and its `keyExtractor` returns a value, **both** the pre-handler counter and the handler's `recordHit()` increment the counter, so the threshold should account for the doubled count. With the signal-only `filter` shown above the pre-handler path never counts, so no doubling occurs.

Recorded failures and hits are processed together after your handler returns; retrieve them all with `getRecordedSignals()`.

## API Reference

### RequestContext

The `RequestContext` class is a mutable recorder that the middleware attaches to the PSR-7 request.

| Method | Signature | Description |
|--------|-----------|-------------|
| `recordFailure()` | `(string $ruleName, ?string $key = null): void` | Record a fail2ban **failure** signal |
| `recordHit()` | `(string $ruleName, ?string $key = null): void` | Record an allow2ban **hit** signal |
| `getResult()` | `(): FirewallResult` | Access the pre-handler firewall decision |
| `getRecordedSignals()` | `(): list<RecordedSignal>` | Get all recorded signals (failures and hits) |
| `hasRecordedSignals()` | `(): bool` | Whether any signals have been recorded |

**Constants:**

| Constant | Value | Description |
|----------|-------|-------------|
| `RequestContext::ATTRIBUTE_NAME` | `'phirewall.context'` | PSR-7 request attribute key |

### recordFailure() / recordHit() Parameters

Both methods take the same parameters:

| Parameter | Type | Description |
|-----------|------|-------------|
| `$ruleName` | `string` | Must match the `name` of a configured `fail2ban->add()` rule (for `recordFailure()`) or `allow2ban->add()` rule (for `recordHit()`) |
| `$key` | `?string` | The discriminator key to count against (e.g., IP address, username). **Optional**: when omitted (`null`), the firewall applies the matching rule's own key extractor to the current request, so your handler does not need to repeat the rule's keying logic. |

### RecordedSignal

An immutable value object representing a single recorded signal (the elements returned by `getRecordedSignals()`).

| Property | Type | Description |
|----------|------|-------------|
| `$ruleName` | `string` | The fail2ban or allow2ban rule this signal is recorded against |
| `$banType` | `BanType` | `BanType::Fail2Ban` (from `recordFailure()`) or `BanType::Allow2Ban` (from `recordHit()`) |
| `$key` | `?string` | The discriminator key override, or `null` to defer to the matching rule's key extractor |

## Accessing the Firewall Decision

The `RequestContext` also gives your handler access to the pre-handler firewall decision via `getResult()`. This returns a `FirewallResult` object:

```php
use Flowd\Phirewall\Context\RequestContext;

/** @var RequestContext|null $context */
$context = $request->getAttribute(RequestContext::ATTRIBUTE_NAME);

if ($context !== null) {
    $result = $context->getResult();

    $result->outcome->value;  // 'pass', 'safelisted', etc.
    $result->isPass();        // true if the request was allowed through
    $result->rule;            // Name of the matching rule (null if the request passed)
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
$context?->recordFailure('login-failures');
$context?->recordHit('expensive-endpoint');
```

If the middleware is not present, `$context` is `null` and the calls are silently skipped: no errors, no side effects. This makes your handler safe to use with or without Phirewall.

## Complete Example

A full, runnable example showing login protection with post-handler failure signaling:

```php
<?php

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Context\RequestContext;
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
            $context?->recordFailure('login-failures');

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
| **Fail2Ban filter predicate** | The request is unambiguously malicious from its properties alone (it should be blocked on the spot) | Block and ban probes to `/.env` |
| **RequestContext** | Failures require application logic, and legitimate requests must not be blocked | Ban after 3 failed password attempts |

### Use a Fail2Ban filter when:
- The request URI, method, or headers alone identify malicious traffic that you want blocked immediately (every match is blocked from 0.8)
- You do not need to inspect the response or run business logic

### Use RequestContext when:
- You need to verify credentials before deciding if the request is a failure
- The failure depends on a database lookup, API call, or response status
- You want to count only **actual** failures without blocking legitimate attempts to an endpoint

## Testing

Verify that failures recorded via `RequestContext` trigger bans:

```php
use PHPUnit\Framework\TestCase;
use Flowd\Phirewall\BanType;
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Context\RequestContext;
use Flowd\Phirewall\Http\Firewall;
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
        );

        $middleware = new Middleware($config, new Psr17Factory());
        $firewall = new Firewall($config);

        // Handler that always records a failure
        $handler = new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface
            {
                $context = $request->getAttribute(RequestContext::ATTRIBUTE_NAME);
                $context?->recordFailure('test-rule');
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
        $this->assertTrue($firewall->isBanned('test-rule', $ip, BanType::Fail2Ban));
    }
}
```

## Related Pages

- [Fail2Ban & Allow2Ban](/features/fail2ban) - fail2ban rule configuration and filter predicates
- [Track & Notifications](/advanced/track-notifications) - passive counting without blocking
- [Observability](/advanced/observability) - events and diagnostics
- [Getting Started](/getting-started) - full setup walkthrough
