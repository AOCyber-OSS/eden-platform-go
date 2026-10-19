# platform/email

Transport-agnostic email delivery primitive for the Eden portfolio. Beta.

## Donor

`aodex-go/internal/email/mailer.go` — simple `Mailer.Send` interface plus an
SMTP transport. Eden-Biz's email package is template-heavy; per the requirement,
**templates remain per-product**. This package only provides the delivery wire.

## Quickstart

```go
import "go.aocyber.ai/eden-platform-go/platform/email"

// Production: SMTP transport
sender := email.NewSMTP(email.SMTPConfig{
    Host: "smtp.sendgrid.net", Port: 587,
    Username: "apikey", Password: os.Getenv("SENDGRID_API_KEY"),
    UseTLS: true, UseAuth: true,
})

// Tests: in-memory recorder
sender := email.NewRecorder()

// Send
res, err := sender.Send(ctx, email.Message{
    From:     email.Address{Name: "Eden", Email: "noreply@eden.example.com"},
    To:       []email.Address{{Email: "user@example.com"}},
    Subject:  "Welcome",
    HTMLBody: "<p>Hi!</p>",
    TextBody: "Hi!",
    Attachments: []email.Attachment{
        {Filename: "invoice.pdf", ContentType: "application/pdf", Data: pdfBytes},
    },
})
// res.MessageID is the assigned RFC 5322 Message-ID.
```

## Bounce / complaint webhooks

```go
ev, err := email.ParseSESWebhook(payload)
if err != nil { ... }
switch ev.Type {
case "bounce":     // mark recipient unverifiable
case "complaint":  // user marked as spam
case "delivery":   // best-effort confirmation
}
```

The package handles SNS-wrapped notifications (the common case for SES) by
unwrapping the `Message` field automatically.

Other providers (Postmark, SendGrid, Mailgun) can be added as needed —
each gets its own `Parse<Provider>Webhook(payload []byte) (WebhookEvent, error)`
function and contributes to the same `WebhookEvent` shape.

## What this package is NOT

- **Not a templater.** Templates live per-product (each product owns its
  marketing/transactional copy).
- **Not authoring UI.** Marketing tooling is out of scope.
- **Not a compliance / unsubscribe registry.** Consumers wire in their own
  unsubscribe storage; this package only delivers.

## Migration paths

- AODex / AOSentry / Eden-Biz / aohealth-go currently each carry their own
  SMTP wrappers. Each repo migrates in its own consumer-side PR.
