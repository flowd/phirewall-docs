---
outline: deep
---

# Track & Notifications

Track rules provide **passive counting without blocking**. They are ideal for observability, alerting thresholds, and feeding data into dashboards -- all without affecting request processing.

## How Tracking Works

Track rules are evaluated **first** in the pipeline, before safelists and blocklists. They always run -- even for requests that will be safelisted. This makes them reliable for comprehensive monitoring.

```text
Request --> Track (passive) --> Safelist --> Blocklist --> Fail2Ban --> Throttle --> Allow2Ban --> Pass
              |
              v
         Count + Event (never blocks)
```

Here is what happens step by step:

1. A request arrives at the firewall
2. Each track rule's **filter** closure is evaluated against the request
3. If the filter returns `true`, the **key** closure extracts a grouping key (for example, the client IP)
4. The counter for that key is incremented in the cache, scoped to the rule's **period** (time window)
5. A `TrackHit` event is dispatched via the PSR-14 (PHP Standard Recommendation for Event Dispatching) event dispatcher
6. The request continues to the remaining pipeline stages -- track rules **never** block

## API Reference

```php
$config->tracks->add(
    string   $name,
    int      $period,
    Closure  $filter,
    Closure  $key,
    ?int     $limit = null   // optional threshold
): TrackSection
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$name` | `string` | Unique rule identifier (must not be empty) |
| `$period` | `int` | Time window for counting in seconds (must be >= 1) |
| `$filter` | `Closure` | `fn(ServerRequestInterface): bool` -- return `true` to count this request |
| `$key` | `Closure` | `fn(ServerRequestInterface): ?string` -- return the grouping key, or `null` to skip counting |
| `$limit` | `?int` | Optional threshold. When set, the `TrackHit` event includes a `thresholdReached` flag that becomes `true` once the counter reaches this value |

::: tip Return type
`add()` returns the `TrackSection` instance, so you can chain multiple calls:
```php
$config->tracks
    ->add('rule-a', 60, $filterA, $keyA)
    ->add('rule-b', 3600, $filterB, $keyB, limit: 100);
```
:::

## Basic Examples

### Track Login Attempts

Monitor login attempts per IP for dashboards and anomaly detection:

```php
use Flowd\Phirewall\KeyExtractors;

$config->tracks->add('login-attempts',
    period: 3600,
    filter: fn($request) => $request->getMethod() === 'POST'
        && $request->getUri()->getPath() === '/login',
    key: KeyExtractors::ip(),
);
```

### Track API Usage by User

Monitor per-user API consumption using a custom header:

```php
use Flowd\Phirewall\KeyExtractors;

$config->tracks->add('api-usage',
    period: 3600,
    filter: fn($request) => str_starts_with($request->getUri()->getPath(), '/api/'),
    key: KeyExtractors::header('X-User-Id'),
);
```

### Track Requests to Sensitive Endpoints

Monitor access to admin or configuration pages:

```php
use Flowd\Phirewall\KeyExtractors;

$config->tracks->add('admin-access',
    period: 600,
    filter: fn($request) => str_starts_with($request->getUri()->getPath(), '/admin/'),
    key: KeyExtractors::ip(),
);
```

### Track Requests by Country

Monitor geographic distribution of traffic (requires a CDN that sets a country header, for example Cloudflare's `CF-IPCountry`):

```php
$config->tracks->add('traffic-by-country',
    period: 3600,
    filter: fn($request) => true, // Track all requests
    key: function ($request): ?string {
        $country = $request->getHeaderLine('CF-IPCountry');
        return $country !== '' ? $country : null; // null = skip counting
    },
);
```

## Track with Threshold (Limit)

The optional `$limit` parameter adds a threshold to your track rule. The `TrackHit` event is dispatched on **every** matching request regardless of whether the threshold has been reached. The event's `thresholdReached` property tells you whether the current count has met or exceeded the limit.

This is useful for alerting: you get full observability of all traffic, but can filter your event listeners to only act when the threshold is crossed.

```php
// Fire TrackHit on every login request.
// thresholdReached becomes true at 5+ hits in 60 seconds.
$config->tracks->add('suspicious-login-burst',
    period: 60,
    filter: fn($request) => $request->getUri()->getPath() === '/login',
    key: fn($request) => $request->getServerParams()['REMOTE_ADDR'] ?? '0.0.0.0',
    limit: 5,
);
```

### How the Threshold Works

```text
Request #1  ->  count=1, thresholdReached=false
Request #2  ->  count=2, thresholdReached=false
Request #3  ->  count=3, thresholdReached=false
Request #4  ->  count=4, thresholdReached=false
Request #5  ->  count=5, thresholdReached=true   <-- threshold crossed
Request #6  ->  count=6, thresholdReached=true
Request #7  ->  count=7, thresholdReached=true
```

::: warning Track rules never block
Even after the threshold is reached, track rules do **not** block the request. If you need automatic blocking, use [Fail2Ban](/features/fail2ban) instead. Track rules are purely for observability and alerting.
:::

### Comparison: With and Without Limit

| Feature | Without `$limit` | With `$limit` |
|---------|-------------------|---------------|
| Event dispatched | On every matching request | On every matching request |
| `$event->thresholdReached` | Always `false` | `true` when `count >= limit` |
| `$event->limit` | `null` | The configured threshold |
| Blocks the request | Never | Never |

## The TrackHit Event

Every time a track rule matches a request, a `TrackHit` event is dispatched through the PSR-14 event dispatcher you provided to the `Config` constructor.

```php
use Flowd\Phirewall\Events\TrackHit;
```

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `$event->rule` | `string` | The name of the track rule that matched |
| `$event->key` | `string` | The discriminator key (for example, client IP) |
| `$event->period` | `int` | The time window in seconds |
| `$event->count` | `int` | The current counter value within the window |
| `$event->serverRequest` | `ServerRequestInterface` | The request that triggered tracking |
| `$event->limit` | `?int` | The configured threshold, or `null` if none was set |
| `$event->thresholdReached` | `bool` | `true` when a limit is set and `count >= limit` |

## All Firewall Events

Phirewall dispatches events for every significant decision. You can listen for any combination of these in your event dispatcher.

| Event Class | When It Fires | Key Properties |
|-------------|---------------|----------------|
| `TrackHit` | A track rule matches a request | `rule`, `key`, `count`, `period`, `limit`, `thresholdReached` |
| `SafelistMatched` | A request matches a safelist rule | `rule`, `serverRequest` |
| `BlocklistMatched` | A request matches a blocklist rule | `rule`, `serverRequest` |
| `ThrottleExceeded` | A rate limit is exceeded | `rule`, `key`, `limit`, `period`, `count`, `retryAfter` |
| `Fail2BanBanned` | A client is banned by Fail2Ban | `rule`, `key`, `threshold`, `period`, `banSeconds`, `count` |
| `Allow2BanBanned` | A client is banned by Allow2Ban | `rule`, `key`, `threshold`, `period`, `banSeconds`, `count` |
| `PerformanceMeasured` | Every firewall decision (for metrics) | `decisionPath`, `durationMicros`, `ruleName` |
| `FirewallError` | An exception occurs in fail-open mode | `exception`, `serverRequest` |

All event classes live in the `Flowd\Phirewall\Events` namespace and are `readonly`.

## Notification Examples

### Slack Alerts on Threshold

Use the `thresholdReached` flag to send Slack alerts only when a suspicious pattern crosses the noise floor:

```php
use Flowd\Phirewall\Events\TrackHit;
use Flowd\Phirewall\Events\Fail2BanBanned;
use GuzzleHttp\Client;
use Psr\EventDispatcher\EventDispatcherInterface;

$dispatcher = new class ($httpClient, $slackWebhook) implements EventDispatcherInterface {
    public function __construct(
        private Client $httpClient,
        private string $slackWebhook,
    ) {}

    public function dispatch(object $event): object
    {
        // Alert when a track threshold is crossed (fires once per request above limit)
        if ($event instanceof TrackHit
            && $event->thresholdReached
            && $event->count === $event->limit  // alert exactly once at the crossing
        ) {
            $this->httpClient->postAsync($this->slackWebhook, [
                'json' => [
                    'text' => sprintf(
                        'Threshold reached: rule `%s`, key `%s` hit %d in %ds',
                        $event->rule,
                        $event->key,
                        $event->count,
                        $event->period,
                    ),
                ],
            ]);
        }

        // Alert on IP bans
        if ($event instanceof Fail2BanBanned) {
            $this->httpClient->postAsync($this->slackWebhook, [
                'json' => [
                    'text' => sprintf(
                        'IP Banned: `%s` (rule: %s, failures: %d)',
                        $event->key,
                        $event->rule,
                        $event->count,
                    ),
                ],
            ]);
        }

        return $event;
    }
};

$config = new Config($cache, $dispatcher);
```

::: tip Alert exactly once
Compare `$event->count === $event->limit` rather than `$event->count >= $event->limit` to avoid sending duplicate alerts on every subsequent request after the threshold is crossed.
:::

### Queue-Based Notifications

For production environments, send notifications asynchronously through a message queue to avoid blocking request processing:

```php
use Flowd\Phirewall\Events\Fail2BanBanned;
use Flowd\Phirewall\Events\TrackHit;
use Psr\EventDispatcher\EventDispatcherInterface;

$dispatcher = new class ($queue) implements EventDispatcherInterface {
    public function __construct(private QueueInterface $queue) {}

    public function dispatch(object $event): object
    {
        if ($event instanceof Fail2BanBanned) {
            $this->queue->push(new SendBanNotification($event->key, $event->rule));
        }

        if ($event instanceof TrackHit && $event->thresholdReached) {
            $this->queue->push(new SendThresholdAlert(
                $event->rule,
                $event->key,
                $event->count,
            ));
        }

        return $event;
    }
};
```

### Email Alerts for Critical Events

```php
use Flowd\Phirewall\Events\Fail2BanBanned;

// Inside your event dispatcher's dispatch() method:
if ($event instanceof Fail2BanBanned) {
    mail(
        'security@example.com',
        "Phirewall: IP Banned ({$event->key})",
        sprintf(
            "IP: %s\nRule: %s\nFailures: %d\nBan Duration: %d seconds\nTime: %s",
            $event->key,
            $event->rule,
            $event->count,
            $event->banSeconds,
            date('Y-m-d H:i:s'),
        )
    );
}
```

::: danger Never use synchronous I/O in event handlers
In production, avoid making synchronous HTTP calls, database writes, or sending emails directly inside the event dispatcher. These operations block request processing and add latency. Always use a message queue or async client (like Guzzle's `postAsync`) for notifications.
:::

## Diagnostics Counters

Phirewall includes a built-in `DiagnosticsCounters` class that implements `EventDispatcherInterface`. Pass it as the event dispatcher to automatically collect counter data for all firewall decisions.

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\DiagnosticsCounters;

$diagnostics = new DiagnosticsCounters();
$config = new Config($cache, $diagnostics);

// ... process requests through the firewall ...

$counters = $diagnostics->all();
```

The returned array is organized by category, each with a total and a breakdown by rule:

```php
[
    'track_hit' => [
        'total' => 150,
        'by_rule' => [
            'login-attempts' => 50,
            'api-usage' => 100,
        ],
    ],
    'safelisted' => [
        'total' => 20,
        'by_rule' => ['health' => 20],
    ],
    'throttle_exceeded' => [
        'total' => 5,
        'by_rule' => ['ip-limit' => 5],
    ],
    // ... other categories
]
```

Categories tracked: `safelisted`, `blocklisted`, `throttle_exceeded`, `fail2ban_banned`, `track_hit`, `passed`, `fail2ban_blocked`.

### Exposing as a Prometheus-Style Metrics Endpoint

```php
use Flowd\Phirewall\Config\DiagnosticsCounters;
use Nyholm\Psr7\Response;

// $diagnostics was passed to Config as the event dispatcher
$counters = $diagnostics->all();

$output = '';
foreach ($counters as $category => $data) {
    $output .= "phirewall_{$category}_total {$data['total']}\n";
    foreach ($data['by_rule'] as $rule => $count) {
        $output .= "phirewall_{$category}_by_rule{rule=\"{$rule}\"} {$count}\n";
    }
}

return new Response(200, ['Content-Type' => 'text/plain'], $output);
```

This produces output like:

```text
phirewall_track_hit_total 150
phirewall_track_hit_by_rule{rule="login-attempts"} 50
phirewall_track_hit_by_rule{rule="api-usage"} 100
phirewall_safelisted_total 20
phirewall_safelisted_by_rule{rule="health"} 20
```

You can scrape this endpoint with Prometheus, Datadog, or any metrics system that supports text exposition format.

## Track vs. Fail2Ban

| Feature | Track | Fail2Ban |
|---------|-------|----------|
| Blocks requests | Never | Yes (after threshold) |
| Counts occurrences | Yes | Yes |
| Has threshold | Optional (`$limit`) | Required (`$threshold`) |
| Dispatches events | `TrackHit` | `Fail2BanBanned` |
| Runs in pipeline | First (before safelists) | After blocklists |
| Use case | Monitoring, alerting, dashboards | Automatic banning |

::: tip Promote track rules to Fail2Ban
Use track rules during an initial monitoring phase. Once you are confident in your filter logic and thresholds, promote them to [Fail2Ban](/features/fail2ban) rules for automatic enforcement.
:::

## Best Practices

1. **Use tracks for monitoring before enforcement.** Deploy track rules first to understand your traffic patterns before adding Fail2Ban or blocklist rules that could affect legitimate users.

2. **Keep track filters lightweight.** Like all Phirewall rules, track filter closures run on every request. Avoid expensive operations (database queries, file reads, HTTP calls).

3. **Set appropriate periods.** The period determines how long counters accumulate. Use shorter periods (60-300s) for real-time alerting and longer periods (3600s) for trend analysis.

4. **Use the `$limit` parameter for alert thresholds.** Instead of checking `$event->count >= N` in your event handler, configure `limit: N` on the track rule and check `$event->thresholdReached` -- it is more readable and keeps the threshold visible in your configuration.

5. **Alert on specific counts, not ranges.** When sending notifications, compare `$event->count === $event->limit` (exact match) rather than `$event->count >= $event->limit` to avoid flooding your notification channel with duplicate alerts.

6. **Send alerts asynchronously.** Never make synchronous HTTP calls or database writes in event handlers. Use queues or async clients for production alerting.

7. **Return `null` from the key closure to skip counting.** If the key closure returns `null`, the request is not counted and no `TrackHit` event is dispatched. This is useful for conditional tracking based on request data that is only available at key-extraction time.

## Related Pages

- [Observability](/advanced/observability) -- logging, OpenTelemetry, and monitoring integration
- [Fail2Ban & Allow2Ban](/features/fail2ban) -- automatic banning based on thresholds
- [Request Context](/advanced/request-context) -- post-handler failure signaling for Fail2Ban
- [Rate Limiting](/features/rate-limiting) -- throttling and rate limit headers
