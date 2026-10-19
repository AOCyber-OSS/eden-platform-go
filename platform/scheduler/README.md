# platform/scheduler

Portable cron-style scheduler with distributed-lock dedup. Beta.

## Donors

- `aosentry/internal/scheduler` (cron-driven background jobs).
- `eden-biz/cron` (in-tree cron with leader election).
- `eden-biz/jobs/scheduler.go` (simpler in-process cron parser).

This package reconciles all three. Cron parsing is intentionally inline (no
new third-party dep) and supports the standard 5-field syntax plus
`@every <duration>` and the named shortcuts `@hourly`, `@daily`,
`@weekly`, `@monthly`, `@yearly`.

## Quickstart

```go
import "go.aocyber.ai/eden-platform-go/platform/scheduler"

// Pick a locker:
locker := scheduler.NewMemoryLocker()              // single-replica / dev
locker := scheduler.NewPostgresLocker(pgxPool)     // multi-replica production

s := scheduler.New(locker)

s.Add(scheduler.ScheduleSpec{
    Name:    "spend.rollup",
    Cron:    "0 1 * * *",                       // 1am daily
    Timeout: 30 * time.Minute,
    Handler: func(ctx context.Context) error { return rollup(ctx) },
})

s.Add(scheduler.ScheduleSpec{
    Name:    "alerts.evaluate",
    Cron:    "@every 1m",
    Timeout: 55 * time.Second,
    Handler: alertEvaluator.EvaluateAll,
})

go s.Start(ctx)
```

## Distributed safety

Each scheduled task acquires a per-tick lease (`scheduler:<name>:<unix-second>`)
before running. With `NewPostgresLocker`, the lease is a Postgres advisory
lock — only one of N replicas wins per tick.

The Postgres locker uses `pg_try_advisory_lock` with an FNV-64-hashed key.
Locks release on `release()` or connection drop (whichever comes first).

## Cron expression coverage

- 5-field standard: `min hour dom month dow`
- Wildcards: `*`
- Lists: `1,5,10`
- Ranges: `9-17`
- Steps: `*/5`, `0-59/15`
- Day-of-week: 0=Sunday, 6=Saturday
- Shortcuts: `@hourly`, `@daily`, `@midnight`, `@weekly`, `@monthly`, `@yearly`, `@annually`
- Duration shortcut: `@every <duration>` (Go duration syntax, ≥ 1s)

## Migration notes

- AOSentry's `internal/scheduler` migrates first (more battle-tested cron usage).
- Eden-Biz's `internal/cron` and `internal/jobs/scheduler.go` migrate after parity smoke.
- Neither migration is part of this objective — handled in consumer-side PRs.

## What this is not

- **Not** a job queue (use `platform/jobs`).
- **Not** a stream processor.
- **Not** a workflow engine — for multi-step flows see `platform/statemachine`.
