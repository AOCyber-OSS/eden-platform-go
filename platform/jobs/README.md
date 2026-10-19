# platform/jobs

Portable background-job queue for the Eden portfolio. Beta.

## Library-underneath decision

We chose a **PG-backed pattern** (donor: `eden-biz/jobs`) over River for the
platform reference. See TRD 18-01 for the side-by-side. Summary:

- Zero new top-level dependency (River pulls a large dependency tree).
- Simpler `Handler` function-typed API; consumer wraps existing River workers behind a thin adapter when migrating.
- Keeps room for a River-backed `Store` adapter later if a second consumer wants advanced River features.

## Quickstart

```go
import "go.aocyber.ai/eden-platform-go/platform/jobs"

store := jobs.NewMemoryStore() // or jobs.NewPostgresStore(pgxPool)
q := jobs.NewQueue(store)

// Producer
q.Enqueue(ctx, "email.send", map[string]string{"to": "x@y", "subject": "hi"})
q.EnqueueDelayed(ctx, "report.generate", payload, 5*time.Minute)
q.EnqueueHigh(ctx, "stripe.webhook", payload)

// Worker
w := jobs.NewWorker(q, 4).
    WithObserver(myObserver).        // metrics + tracing hooks
    WithJobTimeout(2 * time.Minute)

w.Register("email.send", emailHandler)
w.Register("report.generate", reportHandler)
go w.Start(ctx)
```

## Schema

Postgres consumers own the migration. Reference schema:

```sql
CREATE TABLE jobs (
    id           UUID PRIMARY KEY,
    type         TEXT NOT NULL,
    payload      JSONB NOT NULL,
    priority     INT NOT NULL DEFAULT 0,
    max_retries  INT NOT NULL DEFAULT 3,
    attempts     INT NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT 'pending',
    error        TEXT NOT NULL DEFAULT '',
    locked_by    TEXT,
    locked_at    TIMESTAMPTZ,
    scheduled_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX jobs_dequeue_idx ON jobs (status, type, priority DESC, created_at)
    WHERE status = 'pending';
```

## API

| Function                    | Purpose                                           |
| --------------------------- | ------------------------------------------------- |
| `Queue.Enqueue`             | Immediate, normal priority                        |
| `Queue.EnqueueHigh`         | Immediate, high priority (priority=1)             |
| `Queue.EnqueueDelayed`      | Run after delay                                   |
| `Queue.EnqueueAt`           | Run at specific time                              |
| `Worker.Register`           | Bind handler to job type                          |
| `Worker.WithObserver`       | Attach lifecycle hooks (metrics/tracing)          |
| `Worker.WithBackoff`        | Override retry timing (default: `n*n*10s`)        |
| `Worker.Start(ctx)`         | Run until ctx cancelled                           |

## Retries

Default: exponential backoff `attempts*attempts*10s` (10s, 40s, 90s, 160s, 250s, ...).
On `attempts > MaxRetries`, the job is marked `dead`. Consumers can inspect dead jobs
via `Store.ListJobs(ctx, "dead", limit)`.

Panics in `Handler` are caught (with stack), counted as a failure attempt, and retried
up to `MaxRetries` like any other error.

## Observability

Implement `jobs.Observer` to receive `OnDequeue`, `OnComplete`, `OnFail`, `OnDead`.
Methods must be non-blocking — fan out to your metrics/tracing system asynchronously.

## Migration paths

- **AODex (River)**: wrap existing River workers in a function `func(ctx, payload) error`
  that decodes the payload into the worker's struct and calls `Work()`. Consumer-side
  PR — not part of this objective.
- **Eden-Biz (existing PG queue)**: rename imports from `internal/jobs` to
  `platform/jobs`. The schema and behaviour are intentionally identical.

## What this package is not

- **Not** a cron / recurring scheduler — see `platform/scheduler` (Obj 20).
- **Not** a stream processor — for ordered events use NATS JetStream directly.
- **Not** a workflow engine — for multi-step state machines see `platform/statemachine` (Obj 19).
