# platform/livekit

Eden's platform abstraction over the LiveKit real-time video stack. Per portfolio decision **D13**, this package extracts the calling subsystem from `eden-circle` so Eden Family can consume it from day one without copy-paste — satisfying the 2-caller rule for net-new platform packages.

## Capabilities

| | What it is | When to use it |
|---|---|---|
| **1:1 calling** | Initiate / accept / decline / end calls between two subjects, with a state machine: `ringing → connecting → connected → ended`. | Direct user-to-user audio/video. |
| **Multi-party meetings** | Create rooms with bounded participant counts; join, leave, end. E2EE on by default unless recording is enabled (mutually exclusive). | Family video huddles, group calls, virtual office hours. |
| **Egress recording** | Start / stop room composite recordings; metadata persisted in your `Store`; recording finalised by webhook. | Recorded meetings, voicemail-style call review. |
| **Webhook receiver** | HTTP handler that verifies LiveKit's HMAC signatures and dispatches participant_joined / participant_left / room_finished / egress_ended. Supports custom subscribers. | Receive LiveKit's outbound events without re-implementing signature verification. |

## Architecture

```
                  ┌─────────────┐
                  │   Service   │ ─── Public API: InitiateCall / AcceptCall /
                  │             │     CreateMeeting / JoinMeeting / EndCall…
                  └──────┬──────┘
        ┌────────┬───────┼────────┬────────┐
        ▼        ▼       ▼        ▼        ▼
    ┌──────┐ ┌──────┐ ┌──────┐ ┌────────┐ ┌─────┐
    │Store │ │Rooms │ │Tokens│ │Signaler│ │Clock│
    └──────┘ └──────┘ └──────┘ └────────┘ └─────┘
       │       │  │
       │       └──┴── LiveKitAdapter ───── github.com/livekit/server-sdk-go
       │
       ├── InMemoryStore (shipped)
       └── your postgres impl

                  ┌──────────────────┐
                  │ RecordingService │ ─── StartRecording / StopRecording /
                  │                  │     HandleEgressEnded / ListRecordings
                  └────┬─────────┬───┘
                       ▼         ▼
                  ┌────────┐ ┌────────────┐
                  │ Store  │ │EgressClient│ ── LiveKitAdapter.EgressClient()
                  └────────┘ └────────────┘

                  ┌────────────────┐
                  │ WebhookHandler │ ─── http.Handler
                  └────────┬───────┘
                           ▼
              ┌────────────┴────────────┐
              ▼                         ▼
        Service.MarkConnected     RecordingService.HandleEgressEnded
        Service.EndCallByRoom     ───── consumer subscribers via Subscribe()
        Service.LeaveMeeting
        Service.EndMeetingByRoom
```

## Interfaces consumers implement

The platform ships defaults useful for tests; **production deployments provide their own `Store`** (database-backed) and decide how `Signaler` is wired (NATS / WebSocket / push notifications).

```go
type Store interface {
    // Calls / Meetings / Participants / Recordings
    CreateCall(ctx, Call) (Call, error)
    GetCall(ctx, uuid) (Call, error)
    UpdateCall(ctx, Call) (Call, error)
    GetActiveCallForUser(ctx, uuid) (Call, error)
    ListCallsForUser(ctx, uuid, limit, offset) ([]Call, error)
    // …Meeting and Recording variants — see store.go for the full surface
}

type Rooms interface {
    CreateCallRoom(ctx, callID string) (RoomInfo, error)
    CreateMeetingRoom(ctx, name string, max int) (RoomInfo, error)
    DeleteRoom(ctx, roomName string) error
}

type Tokens interface {
    IssueJoinToken(roomName, identity, displayName string, ttl time.Duration) (string, error)
}

type Signaler interface {
    SendToUser(ctx, userID uuid.UUID, eventType string, payload any) error
}
```

`LiveKitAdapter` (in `livekit_adapter.go`) implements both `Rooms` and `Tokens` against `github.com/livekit/server-sdk-go/v2`. It's the **only** file in this package that imports LiveKit's SDK — every other file talks to LiveKit through these interfaces, so swapping providers (or stubbing in tests) requires no Service changes.

## Quickstart — wiring up a Service

```go
package main

import (
    "context"
    "log/slog"
    "net/http"

    "go.aocyber.ai/eden-platform-go/platform/livekit"
)

func main() {
    // 1. LiveKit connection (Rooms + Tokens + EgressClient + KeyProvider).
    adapter, err := livekit.NewLiveKitAdapter(livekit.LiveKitConfig{
        URL:       "wss://lk.example.com",
        APIKey:    os.Getenv("LIVEKIT_API_KEY"),
        APISecret: os.Getenv("LIVEKIT_API_SECRET"),
    })
    if err != nil { /* handle */ }

    // 2. Storage. In production this is your postgres-backed implementation;
    //    InMemoryStore is fine for tests/dev.
    store := livekit.NewInMemoryStore()

    // 3. Signaler. NoopSignaler discards events; production wires NATS / WS.
    signaler := livekit.NoopSignaler{}

    // 4. Service.
    svc, err := livekit.NewService(livekit.ServiceConfig{
        Store:      store,
        Rooms:      adapter,
        Tokens:     adapter,
        Signaler:   signaler,
        LiveKitURL: adapter.URL(),
        Logger:     slog.Default(),
    })
    if err != nil { /* handle */ }

    // 5. Optional: recording service.
    recSvc, err := livekit.NewRecordingService(
        store, adapter.EgressClient(),
        livekit.RecordingConfig{
            S3: livekit.S3Config{
                Endpoint:       "http://minio:9000",
                AccessKey:      os.Getenv("MINIO_ACCESS_KEY"),
                SecretKey:      os.Getenv("MINIO_SECRET_KEY"),
                Bucket:         "recordings",
                Region:         "us-east-1",
                ForcePathStyle: true,
            },
        },
        nil,
    )
    if err != nil { /* handle */ }

    // 6. Webhook receiver — mount at the URL configured in LiveKit.
    wh, _ := livekit.NewWebhookHandler(livekit.WebhookConfig{
        Service:          svc,
        RecordingService: recSvc,
        KeyProvider:      adapter.KeyProvider(),
    })
    http.Handle("/livekit/webhook", wh)
    http.ListenAndServe(":8080", nil)

    // 7. Use the Service from your RPC handlers.
    _ = ctx // placeholder
}
```

## Use case: Eden Family 1:1 video

Eden Family wants household members to place 1:1 video calls. Wire the Service as above, then call:

```go
call, err := svc.InitiateCall(ctx, callerID, calleeID, livekit.CallTypeVideo)
// caller gets a Call back. The callee receives EventCallInvite via the Signaler.
```

When the callee accepts:

```go
result, err := svc.AcceptCall(ctx, callID, calleeID)
// result.LiveKitURL + result.CalleeToken are returned to the caller's RPC.
// The caller is independently notified via Signaler with their own token.
```

The webhook handler transitions the call to `connected` automatically when both clients have joined the LiveKit room, and ends it when the first participant leaves.

## Use case: eden-circle migration mapping

eden-circle's existing `internal/calling` package maps directly:

| eden-circle file | platform/livekit equivalent |
|---|---|
| `internal/calling/livekit.go` (`LiveKitService`) | `LiveKitAdapter` |
| `internal/calling/state.go` (`CallState`) | `state.go` (same names, same transitions) |
| `internal/calling/service.go` (`CallService`) | `Service` (same method names) |
| `internal/calling/meeting.go` | `Service.CreateMeeting` / `JoinMeeting` / `LeaveMeeting` / `EndMeeting` |
| `internal/calling/recording.go` (`RecordingService`) | `RecordingService` |
| `internal/calling/webhook.go` (`WebhookHandler`) | `WebhookHandler` |
| `internal/calling/signaling.go` (`SignalingService`) | `Signaler` interface |
| `internal/calling/repository.go` (`Repository`) | Implement `Store` against eden-circle's pgx queries |

The migration to consume this package is tracked separately (see Objective 28's REQUIREMENTS R38.6 — out of scope here, scheduled as a follow-up).

## Webhook subscribers

To handle a LiveKit event the platform doesn't natively process — for example, sending a custom timeline-publish on `participant_joined` — register a subscriber:

```go
wh.Subscribe(livekit.WebhookEventParticipantJoined, func(ctx context.Context, event *livekit.WebhookEvent) {
    // Your custom logic; runs after Service.MarkConnected has fired.
})
```

Subscribers run sequentially in registration order, after the platform's built-in handlers. A subscriber panic is logged but does not affect other subscribers.

## What's _not_ in this package (and why)

- **Telephony / SIP / dial-in.** Different concern; not requested by D13 or any current consumer.
- **Real-time transcription.** Defer until AI gateway (Objective 26) consumes recordings.
- **Postgres-backed `Store`.** Persistence is consumer-owned. The package ships an in-memory variant for tests and dev only; production callers wire their own table layout. (See `store.go` for the surface — it's small.)
- **Generated proto contracts.** This is a Go-only library package, not an RPC service. Consumers expose their own RPC surface.
