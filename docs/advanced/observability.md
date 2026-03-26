---
outline: deep
---

# Observability

Phirewall provides comprehensive observability through PSR-14 (PHP Standard Recommendation for Event Dispatching) events and built-in diagnostics counters. Every significant decision the firewall makes is observable, making it straightforward to integrate with any logging, metrics, or alerting system you already use.

## Enabling Events

Pass any PSR-14 `EventDispatcherInterface` implementation to the `Config` constructor:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;
use Psr\EventDispatcher\EventDispatcherInterface;

$dispatcher = /* your PSR-14 event dispatcher */;
$config = new Config(new InMemoryCache(), $dispatcher);
```

If no dispatcher is provided, events are silently skipped with zero overhead. This means observability is entirely opt-in -- your firewall runs at full speed with no event overhead until you plug in a dispatcher.

## PSR-14 Events

All events are dispatched **synchronously** during request processing. Every event carries the original `ServerRequestInterface` for context (except `PerformanceMeasured`, which carries the decision path and timing).

### Event Summary

| Event | When Dispatched | Key Properties |
|-------|-----------------|----------------|
| `SafelistMatched` | Request matches a safelist rule | `rule`, `serverRequest` |
| `BlocklistMatched` | Request matches a blocklist rule | `rule`, `serverRequest` |
| `ThrottleExceeded` | Request exceeds a throttle limit | `rule`, `key`, `limit`, `period`, `count`, `retryAfter` |
| `Fail2BanBanned` | Key banned after exceeding failure threshold | `rule`, `key`, `threshold`, `period`, `banSeconds`, `count` |
| `Allow2BanBanned` | Key banned after exceeding request threshold | `rule`, `key`, `threshold`, `period`, `banSeconds`, `count` |
| `TrackHit` | Tracking rule filter matches | `rule`, `key`, `period`, `count`, `limit`, `thresholdReached` |
| `FirewallError` | Error in fail-open mode (cache failure, etc.) | `exception`, `serverRequest` |
| `PerformanceMeasured` | After every firewall decision | `decisionPath`, `durationMicros`, `ruleName` |

All event classes live in the `Flowd\Phirewall\Events` namespace and are `readonly`.

### SafelistMatched

Dispatched when a request matches a safelist rule. The request bypasses all remaining checks.

```php
use Flowd\Phirewall\Events\SafelistMatched;

$event->rule;           // string - Rule name (e.g., 'health')
$event->serverRequest;  // ServerRequestInterface
```

### BlocklistMatched

Dispatched when a request matches a blocklist rule. The request is rejected with `403`.

```php
use Flowd\Phirewall\Events\BlocklistMatched;

$event->rule;           // string - Rule name (e.g., 'scanner-probe')
$event->serverRequest;  // ServerRequestInterface
```

### ThrottleExceeded

Dispatched when a request exceeds a configured rate limit. The request is rejected with `429`.

```php
use Flowd\Phirewall\Events\ThrottleExceeded;

$event->rule;           // string - Rule name
$event->key;            // string - Throttle key (e.g., IP address)
$event->limit;          // int - Configured limit
$event->period;         // int - Window size in seconds
$event->count;          // int - Current request count
$event->retryAfter;     // int - Seconds until the window resets
$event->serverRequest;  // ServerRequestInterface
```

### Fail2BanBanned

Dispatched when a key is newly banned by a Fail2Ban rule (failure count crossed the threshold).

```php
use Flowd\Phirewall\Events\Fail2BanBanned;

$event->rule;           // string - Rule name
$event->key;            // string - Banned key (e.g., IP address)
$event->threshold;      // int - Number of failures before ban
$event->period;         // int - Observation window in seconds
$event->banSeconds;     // int - Ban duration in seconds
$event->count;          // int - Failure count that triggered the ban
$event->serverRequest;  // ServerRequestInterface
```

### Allow2BanBanned

Dispatched when an Allow2Ban rule bans a key after the request volume threshold is exceeded. Allow2Ban counts **all** requests for a key (no filter), making it useful for volume-based banning.

```php
use Flowd\Phirewall\Events\Allow2BanBanned;

$event->rule;           // string - Rule name
$event->key;            // string - Banned key (e.g., IP address)
$event->threshold;      // int - Requests before ban
$event->period;         // int - Observation window in seconds
$event->banSeconds;     // int - Ban duration in seconds
$event->count;          // int - Request count that triggered the ban
$event->serverRequest;  // ServerRequestInterface
```

### TrackHit

Track events fire on **every** matching request -- they never block. When a `limit` is configured on the track rule, the `thresholdReached` flag becomes `true` once the counter reaches the threshold. This makes track rules ideal for alerting without blocking.

```php
use Flowd\Phirewall\Events\TrackHit;

$event->rule;              // string - Rule name
$event->key;               // string - Track key (e.g., IP address)
$event->period;            // int - Window size in seconds
$event->count;             // int - Current count in the window
$event->limit;             // ?int - Configured threshold (null if no limit set)
$event->thresholdReached;  // bool - true when limit is set and count >= limit
$event->serverRequest;     // ServerRequestInterface
```

::: tip
Use `thresholdReached` to filter noise in your alerting system. Events always fire for full observability, but the flag lets you trigger alerts only when activity exceeds a meaningful threshold. See [Track & Notifications](/advanced/track-notifications) for details.
:::

### FirewallError

Dispatched when the firewall encounters an error during request evaluation **in fail-open mode** (the default). The request is allowed through to prevent a cache or storage outage from taking down your application.

```php
use Flowd\Phirewall\Events\FirewallError;

$event->exception;      // \Throwable - The error that occurred
$event->serverRequest;  // ServerRequestInterface
```

::: warning
`FirewallError` is only dispatched in fail-open mode (`$config->setFailOpen(true)`, the default). In fail-closed mode (`$config->setFailOpen(false)`), exceptions propagate directly and your error handler receives them instead.
:::

### PerformanceMeasured

Dispatched **after every single firewall decision**, regardless of outcome. This event is the only one that fires on every request, making it the best source for latency metrics and overall throughput monitoring.

```php
use Flowd\Phirewall\Events\PerformanceMeasured;
use Flowd\Phirewall\Http\DecisionPath;

$event->decisionPath;   // DecisionPath enum - which pipeline stage decided
$event->durationMicros; // int - Processing time in microseconds
$event->ruleName;       // ?string - Rule that decided (null for 'passed')
```

The `DecisionPath` enum has these cases:

| Value | Description |
|-------|-------------|
| `Passed` | Request passed all checks |
| `Safelisted` | Matched a safelist rule |
| `Blocklisted` | Matched a blocklist rule |
| `Fail2BanBlocked` | Blocked by an existing Fail2Ban ban |
| `Fail2BanBanned` | Newly banned by Fail2Ban |
| `Throttled` | Exceeded a rate limit |
| `Allow2BanBlocked` | Blocked by an existing Allow2Ban ban |
| `Allow2BanBanned` | Newly banned by Allow2Ban |

::: warning Keep PerformanceMeasured handlers lightweight
Since this event fires on every request, expensive operations in its handler directly impact response latency. Consider sampling in high-traffic environments (see [Performance Considerations](#performance-considerations)).
:::

## Diagnostics Counters

Phirewall provides a built-in `DiagnosticsCounters` class that implements `EventDispatcherInterface`. It collects lightweight, in-memory counters for every decision category -- perfect for health endpoints, dashboards, and quick debugging.

### Setting Up

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\DiagnosticsCounters;
use Flowd\Phirewall\Store\InMemoryCache;

$diagnostics = new DiagnosticsCounters();
$config = new Config(new InMemoryCache(), $diagnostics);
```

### Reading Counters

```php
$counters = $diagnostics->all();
```

Returns an array organized by category, each with a total and a per-rule breakdown:

```php
[
    'safelisted'        => ['total' => 100, 'by_rule' => ['health' => 80, 'metrics' => 20]],
    'blocklisted'       => ['total' => 5,   'by_rule' => ['scanners' => 5]],
    'throttle_exceeded' => ['total' => 2,   'by_rule' => ['ip-limit' => 2]],
    'fail2ban_blocked'  => ['total' => 3,   'by_rule' => ['login' => 3]],
    'fail2ban_banned'   => ['total' => 1,   'by_rule' => ['login' => 1]],
    'track_hit'         => ['total' => 50,  'by_rule' => ['api-calls' => 50]],
    'passed'            => ['total' => 1000, 'by_rule' => []],
]
```

### Counter Categories

| Category | Source Event | Description |
|----------|-------------|-------------|
| `safelisted` | `SafelistMatched` | Requests that matched safelist rules |
| `blocklisted` | `BlocklistMatched` | Requests blocked by blocklist rules |
| `throttle_exceeded` | `ThrottleExceeded` | Requests that exceeded rate limits |
| `fail2ban_banned` | `Fail2BanBanned` | New Fail2Ban bans issued |
| `fail2ban_blocked` | `PerformanceMeasured` | Requests blocked by existing Fail2Ban bans |
| `track_hit` | `TrackHit` | Tracking rule matches |
| `passed` | `PerformanceMeasured` | Requests that passed all checks |

::: tip
The `passed` and `fail2ban_blocked` categories are derived from the `PerformanceMeasured` event, which fires on every request. All other categories come from their dedicated events.
:::

### Resetting Counters

```php
$diagnostics->reset();
```

This clears all counters. Useful in tests or if you periodically flush metrics to an external system.

## Integration Examples

### Minimal Dispatcher

The simplest possible dispatcher for quick debugging:

```php
use Psr\EventDispatcher\EventDispatcherInterface;

$dispatcher = new class implements EventDispatcherInterface {
    public function dispatch(object $event): object
    {
        error_log('[Phirewall] ' . $event::class);
        return $event;
    }
};
```

### Monolog Integration

Full-featured logging with different severity levels for different event types:

```php
use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Flowd\Phirewall\Events\BlocklistMatched;
use Flowd\Phirewall\Events\ThrottleExceeded;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Flowd\Phirewall\Events\Allow2BanBanned;
use Flowd\Phirewall\Events\SafelistMatched;
use Flowd\Phirewall\Events\FirewallError;
use Psr\EventDispatcher\EventDispatcherInterface;

$logger = new Logger('phirewall');
$logger->pushHandler(new StreamHandler('/var/log/phirewall.log', Logger::INFO));
$logger->pushHandler(new StreamHandler('/var/log/phirewall-attacks.log', Logger::WARNING));

$dispatcher = new class ($logger) implements EventDispatcherInterface {
    public function __construct(private Logger $logger) {}

    public function dispatch(object $event): object
    {
        $context = $this->extractContext($event);

        match (true) {
            $event instanceof Fail2BanBanned => $this->logger->warning('IP banned by fail2ban', $context),
            $event instanceof Allow2BanBanned => $this->logger->warning('IP banned by allow2ban', $context),
            $event instanceof BlocklistMatched => $this->logger->warning('Request blocked', $context),
            $event instanceof ThrottleExceeded => $this->logger->notice('Rate limit exceeded', $context),
            $event instanceof SafelistMatched => $this->logger->debug('Request safelisted', $context),
            $event instanceof FirewallError => $this->logger->error('Firewall error', [
                'error' => $event->exception->getMessage(),
                'ip' => $event->serverRequest->getServerParams()['REMOTE_ADDR'] ?? 'unknown',
            ]),
            default => $this->logger->debug('Firewall event', $context),
        };

        return $event;
    }

    private function extractContext(object $event): array
    {
        $context = ['event' => (new \ReflectionClass($event))->getShortName()];

        if (property_exists($event, 'rule')) {
            $context['rule'] = $event->rule;
        }
        if (property_exists($event, 'key')) {
            $context['key'] = $event->key;
        }
        if (property_exists($event, 'serverRequest')) {
            $request = $event->serverRequest;
            $context['method'] = $request->getMethod();
            $context['path'] = $request->getUri()->getPath();
            $context['ip'] = $request->getServerParams()['REMOTE_ADDR'] ?? 'unknown';
        }

        return $context;
    }
};
```

### OpenTelemetry Integration

Export metrics and traces to your observability platform (Jaeger, Grafana Tempo, Datadog, etc.):

```php
use OpenTelemetry\API\Metrics\MeterInterface;
use OpenTelemetry\API\Trace\TracerInterface;
use Flowd\Phirewall\Events\PerformanceMeasured;
use Flowd\Phirewall\Events\ThrottleExceeded;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Flowd\Phirewall\Events\Allow2BanBanned;
use Flowd\Phirewall\Events\BlocklistMatched;
use Flowd\Phirewall\Events\FirewallError;
use Psr\EventDispatcher\EventDispatcherInterface;

$dispatcher = new class ($tracer, $meter) implements EventDispatcherInterface {
    private $eventCounter;
    private $latencyHistogram;

    public function __construct(
        private TracerInterface $tracer,
        MeterInterface $meter,
    ) {
        $this->eventCounter = $meter->createCounter(
            'phirewall.events', 'count', 'Firewall events by type',
        );
        $this->latencyHistogram = $meter->createHistogram(
            'phirewall.latency', 'us', 'Firewall decision latency',
        );
    }

    public function dispatch(object $event): object
    {
        $eventType = (new \ReflectionClass($event))->getShortName();

        // Count all events by type
        $this->eventCounter->add(1, ['type' => $eventType]);

        // Record latency for performance events
        if ($event instanceof PerformanceMeasured) {
            $this->latencyHistogram->record($event->durationMicros, [
                'decision' => $event->decisionPath->value,
                'rule' => $event->ruleName ?? 'none',
            ]);
        }

        // Create spans for blocking events (these are the ones you want to investigate)
        if ($event instanceof BlocklistMatched
            || $event instanceof ThrottleExceeded
            || $event instanceof Fail2BanBanned
            || $event instanceof Allow2BanBanned) {
            $span = $this->tracer->spanBuilder('phirewall.blocked')
                ->setAttribute('phirewall.rule', $event->rule)
                ->setAttribute('phirewall.type', $eventType)
                ->startSpan();
            $span->end();
        }

        // Record errors as spans with error status
        if ($event instanceof FirewallError) {
            $span = $this->tracer->spanBuilder('phirewall.error')
                ->setAttribute('error', true)
                ->setAttribute('error.message', $event->exception->getMessage())
                ->startSpan();
            $span->end();
        }

        return $event;
    }
};
```

### Prometheus Metrics

If you use the `promphp/prometheus_client_php` library:

```php
use Prometheus\CollectorRegistry;
use Flowd\Phirewall\Events\BlocklistMatched;
use Flowd\Phirewall\Events\ThrottleExceeded;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Flowd\Phirewall\Events\Allow2BanBanned;
use Flowd\Phirewall\Events\FirewallError;
use Flowd\Phirewall\Events\PerformanceMeasured;
use Psr\EventDispatcher\EventDispatcherInterface;

$dispatcher = new class ($registry) implements EventDispatcherInterface {
    private $blockCounter;
    private $throttleCounter;
    private $errorCounter;
    private $latencyHistogram;

    public function __construct(CollectorRegistry $registry) {
        $this->blockCounter = $registry->getOrRegisterCounter(
            'phirewall', 'blocks_total', 'Total blocked requests',
            ['rule', 'type'],
        );
        $this->throttleCounter = $registry->getOrRegisterCounter(
            'phirewall', 'throttles_total', 'Total throttled requests',
            ['rule'],
        );
        $this->errorCounter = $registry->getOrRegisterCounter(
            'phirewall', 'errors_total', 'Total firewall errors',
        );
        $this->latencyHistogram = $registry->getOrRegisterHistogram(
            'phirewall', 'latency_microseconds', 'Decision latency',
            ['decision'],
            [10, 50, 100, 500, 1000, 5000],
        );
    }

    public function dispatch(object $event): object
    {
        match (true) {
            $event instanceof BlocklistMatched =>
                $this->blockCounter->inc(['rule' => $event->rule, 'type' => 'blocklist']),
            $event instanceof Fail2BanBanned =>
                $this->blockCounter->inc(['rule' => $event->rule, 'type' => 'fail2ban']),
            $event instanceof Allow2BanBanned =>
                $this->blockCounter->inc(['rule' => $event->rule, 'type' => 'allow2ban']),
            $event instanceof ThrottleExceeded =>
                $this->throttleCounter->inc(['rule' => $event->rule]),
            $event instanceof FirewallError =>
                $this->errorCounter->inc(),
            $event instanceof PerformanceMeasured =>
                $this->latencyHistogram->observe(
                    $event->durationMicros,
                    ['decision' => $event->decisionPath->value],
                ),
            default => null,
        };

        return $event;
    }
};
```

### Exposing DiagnosticsCounters as a Metrics Endpoint

You can serve the built-in `DiagnosticsCounters` as a Prometheus-compatible text endpoint without any external metrics library:

```php
// In a /metrics route handler
// $diagnostics is the DiagnosticsCounters instance passed to Config
$counters = $diagnostics->all();

$output = '';
foreach ($counters as $category => $data) {
    $output .= "# HELP phirewall_{$category}_total Total {$category} events\n";
    $output .= "# TYPE phirewall_{$category}_total counter\n";
    $output .= "phirewall_{$category}_total {$data['total']}\n";

    foreach ($data['by_rule'] as $rule => $count) {
        $output .= "phirewall_{$category}_by_rule{rule=\"{$rule}\"} {$count}\n";
    }
}

return new Response(200, ['Content-Type' => 'text/plain'], $output);
```

This produces output like:

```text
# HELP phirewall_safelisted_total Total safelisted events
# TYPE phirewall_safelisted_total counter
phirewall_safelisted_total 100
phirewall_safelisted_by_rule{rule="health"} 80
phirewall_safelisted_by_rule{rule="metrics"} 20
# HELP phirewall_track_hit_total Total track_hit events
# TYPE phirewall_track_hit_total counter
phirewall_track_hit_total 50
phirewall_track_hit_by_rule{rule="api-calls"} 50
```

### Structured JSON Logging

For log aggregation systems (ELK, Loki, CloudWatch, etc.) that work best with structured JSON:

```php
use Flowd\Phirewall\Events\ThrottleExceeded;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Flowd\Phirewall\Events\Allow2BanBanned;
use Flowd\Phirewall\Events\TrackHit;
use Flowd\Phirewall\Events\FirewallError;
use Flowd\Phirewall\Events\PerformanceMeasured;
use Psr\EventDispatcher\EventDispatcherInterface;

$dispatcher = new class implements EventDispatcherInterface {
    public function dispatch(object $event): object
    {
        $log = [
            'timestamp' => date('c'),
            'event' => (new \ReflectionClass($event))->getShortName(),
        ];

        if (property_exists($event, 'rule')) $log['rule'] = $event->rule;

        if (property_exists($event, 'serverRequest')) {
            $request = $event->serverRequest;
            $log['request'] = [
                'method' => $request->getMethod(),
                'path' => $request->getUri()->getPath(),
                'ip' => $request->getServerParams()['REMOTE_ADDR'] ?? null,
                'user_agent' => $request->getHeaderLine('User-Agent'),
            ];
        }

        if ($event instanceof ThrottleExceeded) {
            $log['limit'] = $event->limit;
            $log['count'] = $event->count;
            $log['retry_after'] = $event->retryAfter;
        }
        if ($event instanceof Fail2BanBanned || $event instanceof Allow2BanBanned) {
            $log['threshold'] = $event->threshold;
            $log['ban_seconds'] = $event->banSeconds;
        }
        if ($event instanceof TrackHit) {
            $log['count'] = $event->count;
            $log['limit'] = $event->limit;
            $log['threshold_reached'] = $event->thresholdReached;
        }
        if ($event instanceof FirewallError) {
            $log['error'] = $event->exception->getMessage();
        }
        if ($event instanceof PerformanceMeasured) {
            $log['decision'] = $event->decisionPath->value;
            $log['latency_us'] = $event->durationMicros;
        }

        fwrite(STDOUT, json_encode($log) . "\n");
        return $event;
    }
};
```

This produces one JSON line per event:

```json
{"timestamp":"2025-03-25T12:00:00+00:00","event":"ThrottleExceeded","rule":"ip-limit","request":{"method":"GET","path":"/api/users","ip":"192.168.1.100","user_agent":"curl/8.0"},"limit":100,"count":101,"retry_after":45}
```

## Track Rule Alerting

Track rules with a `limit` parameter are ideal for threshold-based alerting without blocking. The event fires on every matching request, but the `thresholdReached` flag tells you when the count has crossed the threshold.

```php
use Flowd\Phirewall\Events\TrackHit;
use Psr\EventDispatcher\EventDispatcherInterface;

$dispatcher = new class implements EventDispatcherInterface {
    public function dispatch(object $event): object
    {
        // Only alert when a track threshold is first reached
        if ($event instanceof TrackHit
            && $event->thresholdReached
            && $event->count === $event->limit  // alert exactly once
        ) {
            $this->sendAlert(sprintf(
                'Suspicious activity: rule=%s key=%s count=%d (threshold=%d)',
                $event->rule,
                $event->key,
                $event->count,
                $event->limit,
            ));
        }

        return $event;
    }

    private function sendAlert(string $message): void
    {
        // Your alerting logic here (Slack, PagerDuty, email, etc.)
        error_log('[ALERT] ' . $message);
    }
};
```

See [Track & Notifications](/advanced/track-notifications) for more alerting patterns including Slack webhooks, queue-based notifications, and email alerts.

## Testing Events

Verify that your firewall dispatches the expected events. The `Firewall` class is the core decision engine used internally by `Middleware`. You can use it directly in tests when you do not need a full PSR-15 pipeline:

```php
use PHPUnit\Framework\TestCase;
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Events\ThrottleExceeded;
use Flowd\Phirewall\Store\InMemoryCache;
use Psr\EventDispatcher\EventDispatcherInterface;
use Nyholm\Psr7\ServerRequest;

class FirewallEventsTest extends TestCase
{
    public function testThrottleExceededEventDispatched(): void
    {
        $events = [];
        $dispatcher = new class ($events) implements EventDispatcherInterface {
            public function __construct(private array &$events) {}
            public function dispatch(object $event): object {
                $this->events[] = $event;
                return $event;
            }
        };

        $config = new Config(new InMemoryCache(), $dispatcher);
        $config->throttles->add('test', limit: 1, period: 60,
            key: fn($request) => 'key'
        );

        $firewall = new Firewall($config);
        $request = new ServerRequest('GET', '/');

        $firewall->decide($request); // First request passes
        $firewall->decide($request); // Second request exceeds limit

        $throttleEvents = array_filter(
            $events,
            fn($event) => $event instanceof ThrottleExceeded,
        );
        $this->assertCount(1, $throttleEvents);
    }
}
```

::: tip Use `Firewall` directly in tests
The `Firewall` class returns a `Decision` object with `isPass()` and `isBlock()` methods. This is faster than running through the full PSR-15 middleware pipeline and does not require a PSR-17 response factory.
:::

## Performance Considerations

### Keep Handlers Fast

Event handlers run synchronously in the request path. Slow handlers directly impact response latency for every request.

```php
// Avoid: synchronous HTTP call blocks the request
$this->httpClient->post($url, ['json' => $data]);

// Prefer: async or queue-based
$this->queue->push(['event' => $event::class, 'data' => $data]);
```

### Sample High-Volume Events

For high-traffic applications, consider sampling `TrackHit` and `PerformanceMeasured` events to reduce overhead:

```php
public function dispatch(object $event): object
{
    // Sample 1% of performance events
    if ($event instanceof PerformanceMeasured && random_int(1, 100) > 1) {
        return $event;
    }

    $this->processEvent($event);
    return $event;
}
```

::: tip
Always process blocking events (`BlocklistMatched`, `Fail2BanBanned`, `ThrottleExceeded`, `Allow2BanBanned`, `FirewallError`) at full volume -- these are low-frequency, high-signal events that you do not want to miss.
:::

### Protect Sensitive Data

Keys may contain IP addresses or user identifiers. Mask or hash sensitive data before logging or sending to external systems:

```php
$maskedIp = preg_replace('/\.\d+$/', '.xxx', $event->key);
$this->logger->info('Event', ['key' => $maskedIp]);
```

## Related Pages

- [Track & Notifications](/advanced/track-notifications) -- track rules, thresholds, and notification patterns
- [Request Context](/advanced/request-context) -- post-handler failure signaling for Fail2Ban
- [Rate Limiting](/features/rate-limiting) -- throttle rules and rate limit headers
- [Fail2Ban & Allow2Ban](/features/fail2ban) -- automatic banning
