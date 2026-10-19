# platform/statemachine

Generic state-machine engine for any workflow with discrete states. Beta.

## Donor

`eden-biz/statemachine/machine.go`. Extended here with: history persistence,
optional guards, transition events emitted via Subscribers (which can wire
to `platform/audit` or `platform/webhook`).

## Quickstart

```go
import "go.aocyber.ai/eden-platform-go/platform/statemachine"

type State string
type Event string

m := statemachine.New[State, Event]("draft", []statemachine.Transition[State, Event]{
    {From: "draft",     Event: "submit",  To: "submitted"},
    {From: "submitted", Event: "approve", To: "approved"},
    {From: "submitted", Event: "reject",  To: "rejected",
        Guard: func(ctx context.Context, payload any) error {
            p := payload.(map[string]string)
            if p["reason"] == "" { return errors.New("rejection needs a reason") }
            return nil
        }},
})

store := statemachine.NewMemoryStore[State, Event]()  // or your PG store

// Wire audit logging
m.Subscribe(func(e statemachine.HistoryEntry[State, Event]) {
    auditLogger.Log(audit.Event{
        Action:     "state.transition",
        Resource:   "invoice",
        ResourceID: e.InstanceID,
        Reason:     fmt.Sprintf("%v -> %v via %v", e.From, e.To, e.Event),
    })
})

// Drive transitions
state, err := m.Transition(ctx, store, "inv-123", "submit", nil)
state, err  = m.Transition(ctx, store, "inv-123", "reject",
    map[string]string{"reason": "missing po number"})

// Inspect
state, hist, _ := store.Get(ctx, "inv-123")
```

## Persistence

`Store[S, E]` is the persistence contract. `MemoryStore` ships in the
package for tests. Production callers implement a Postgres-backed store:

```go
type PgStore[S, E comparable] struct{ pool *pgxpool.Pool }

func (s *PgStore[S, E]) Get(...) (...) {
    // SELECT current_state FROM <table> WHERE id = $1
    // SELECT * FROM <table>_history WHERE instance_id = $1 ORDER BY ts ASC
}
func (s *PgStore[S, E]) Save(...) error {
    // BEGIN; UPDATE <table> SET current_state = $1; INSERT INTO <table>_history; COMMIT
}
```

See `platform/statemachine/example_pg_store_test.go` (deferred — to be added
when the first consumer migrates).

## Subscribe vs Save vs callback hell

- `Save` is synchronous. If it fails, the transition fails, and the
  subscriber is NOT notified.
- `Subscribe` runs *after* a successful Save. Subscribers see only
  committed transitions.
- Don't do IO in Subscribers. Fan out to `platform/jobs` if you need
  durable downstream effects.

## Limitations

- No hierarchical or parallel state machines. If you need either, this is
  the wrong tool — see something like `looplab/fsm` or roll a domain
  aggregate.
- No time-bound auto-transitions. Schedule a `platform/jobs` retry that
  calls `Transition` if you need that pattern.
