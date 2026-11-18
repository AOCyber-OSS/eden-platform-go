package pgstore

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.aocyber.ai/eden-platform-go/internal/db"
	"go.aocyber.ai/eden-platform-go/platform/webhook"
)

var _ webhook.WebhookStore = (*WebhookStore)(nil)

// WebhookStore implements webhook.WebhookStore and connectapi.deliveryQuerier
// backed by PostgreSQL via pgx and sqlc.
type WebhookStore struct {
	pool *pgxpool.Pool
}

// NewWebhookStore creates a new PostgreSQL-backed webhook store.
func NewWebhookStore(pool *pgxpool.Pool) *WebhookStore {
	return &WebhookStore{pool: pool}
}

func (s *WebhookStore) queries() *db.Queries {
	return db.New(s.pool)
}

func (s *WebhookStore) CreateWebhook(ctx context.Context, companyID uuid.UUID, url, secret string, events []string) (webhook.Webhook, error) {
	row, err := s.queries().CreateWebhook(ctx, db.CreateWebhookParams{
		CompanyID: companyID,
		Url:       url,
		Secret:    secret,
		Events:    events,
	})
	if err != nil {
		return webhook.Webhook{}, fmt.Errorf("create webhook: %w", err)
	}
	return dbWebhookToDomain(row), nil
}

func (s *WebhookStore) GetWebhook(ctx context.Context, id uuid.UUID) (webhook.Webhook, error) {
	row, err := s.queries().GetWebhook(ctx, id)
	if err != nil {
		if err == pgx.ErrNoRows {
			return webhook.Webhook{}, fmt.Errorf("webhook not found: %s", id)
		}
		return webhook.Webhook{}, fmt.Errorf("get webhook: %w", err)
	}
	return dbWebhookToDomain(row), nil
}

func (s *WebhookStore) ListWebhooksByCompany(ctx context.Context, companyID uuid.UUID) ([]webhook.Webhook, error) {
	rows, err := s.queries().ListWebhooksByCompany(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("list webhooks: %w", err)
	}
	webhooks := make([]webhook.Webhook, len(rows))
	for i, row := range rows {
		webhooks[i] = dbWebhookToDomain(row)
	}
	return webhooks, nil
}

func (s *WebhookStore) UpdateWebhookStatus(ctx context.Context, id uuid.UUID, active bool) error {
	return s.queries().UpdateWebhookStatus(ctx, db.UpdateWebhookStatusParams{
		ID:     id,
		Active: active,
	})
}

// DeleteWebhook deletes the webhook only when it belongs to companyID.
func (s *WebhookStore) DeleteWebhook(ctx context.Context, companyID, id uuid.UUID) error {
	n, err := s.queries().DeleteWebhook(ctx, db.DeleteWebhookParams{ID: id, CompanyID: companyID})
	if err != nil {
		return fmt.Errorf("delete webhook: %w", err)
	}
	if n == 0 {
		return webhook.ErrWebhookNotFound
	}
	return nil
}

func (s *WebhookStore) IncrementFailureCount(ctx context.Context, id uuid.UUID) (int, error) {
	count, err := s.queries().IncrementFailureCount(ctx, id)
	if err != nil {
		return 0, fmt.Errorf("increment failure count: %w", err)
	}
	return int(count), nil
}

func (s *WebhookStore) ResetFailureCount(ctx context.Context, id uuid.UUID) error {
	return s.queries().ResetFailureCount(ctx, id)
}

func (s *WebhookStore) CreateDelivery(ctx context.Context, webhookID uuid.UUID, eventType, payload string) (webhook.WebhookDelivery, error) {
	row, err := s.queries().CreateDelivery(ctx, db.CreateDeliveryParams{
		WebhookID: webhookID,
		EventType: eventType,
		Payload:   payload,
	})
	if err != nil {
		return webhook.WebhookDelivery{}, fmt.Errorf("create delivery: %w", err)
	}
	return dbDeliveryToDomain(row), nil
}

func (s *WebhookStore) UpdateDelivery(ctx context.Context, id uuid.UUID, status string, statusCode int, responseBody string, nextRetryAt *time.Time) error {
	var nra pgtype.Timestamptz
	if nextRetryAt != nil {
		nra = pgtype.Timestamptz{Time: *nextRetryAt, Valid: true}
	}
	return s.queries().UpdateDelivery(ctx, db.UpdateDeliveryParams{
		ID:           id,
		Status:       status,
		StatusCode:   int32(statusCode),
		ResponseBody: responseBody,
		NextRetryAt:  nra,
	})
}

func (s *WebhookStore) GetPendingDeliveries(ctx context.Context) ([]webhook.WebhookDelivery, error) {
	rows, err := s.queries().GetPendingDeliveries(ctx)
	if err != nil {
		return nil, fmt.Errorf("get pending deliveries: %w", err)
	}
	deliveries := make([]webhook.WebhookDelivery, len(rows))
	for i, row := range rows {
		deliveries[i] = dbDeliveryToDomain(row)
	}
	return deliveries, nil
}

// GetDelivery returns a single delivery by ID.
func (s *WebhookStore) GetDelivery(ctx context.Context, id uuid.UUID) (webhook.WebhookDelivery, error) {
	row, err := s.queries().GetDelivery(ctx, id)
	if err != nil {
		if err == pgx.ErrNoRows {
			return webhook.WebhookDelivery{}, fmt.Errorf("delivery not found: %s", id)
		}
		return webhook.WebhookDelivery{}, fmt.Errorf("get delivery: %w", err)
	}
	return dbDeliveryToDomain(row), nil
}

// ListFailedDeliveriesForRetry returns deliveries with status='failed' and
// attempts < maxAttempts, ordered oldest-first.
func (s *WebhookStore) ListFailedDeliveriesForRetry(ctx context.Context, maxAttempts int) ([]webhook.WebhookDelivery, error) {
	rows, err := s.queries().ListFailedDeliveriesForRetry(ctx, int32(maxAttempts))
	if err != nil {
		return nil, fmt.Errorf("list failed deliveries: %w", err)
	}
	deliveries := make([]webhook.WebhookDelivery, len(rows))
	for i, row := range rows {
		deliveries[i] = dbDeliveryToDomain(row)
	}
	return deliveries, nil
}

// ListDeliveriesByWebhook satisfies connectapi.deliveryQuerier. Only
// deliveries of a webhook owned by companyID are returned.
func (s *WebhookStore) ListDeliveriesByWebhook(ctx context.Context, companyID, webhookID uuid.UUID, limit, offset int) ([]webhook.WebhookDelivery, error) {
	rows, err := s.queries().ListDeliveriesByWebhook(ctx, db.ListDeliveriesByWebhookParams{
		WebhookID: webhookID,
		CompanyID: companyID,
		Limit:     int32(limit),
		Offset:    int32(offset),
	})
	if err != nil {
		return nil, fmt.Errorf("list deliveries: %w", err)
	}
	deliveries := make([]webhook.WebhookDelivery, len(rows))
	for i, row := range rows {
		deliveries[i] = dbDeliveryToDomain(row)
	}
	return deliveries, nil
}

// -- Type conversion helpers --

func dbWebhookToDomain(w db.Webhook) webhook.Webhook {
	return webhook.Webhook{
		ID:               w.ID,
		CompanyID:        w.CompanyID,
		URL:              w.Url,
		Secret:           w.Secret,
		Events:           w.Events,
		Active:           w.Active,
		ConsecutiveFails: int(w.ConsecutiveFails),
		CreatedAt:        w.CreatedAt,
	}
}

func dbDeliveryToDomain(d db.WebhookDelivery) webhook.WebhookDelivery {
	var nextRetryAt *time.Time
	if d.NextRetryAt.Valid {
		nextRetryAt = &d.NextRetryAt.Time
	}
	return webhook.WebhookDelivery{
		ID:           d.ID,
		WebhookID:    d.WebhookID,
		EventType:    d.EventType,
		Payload:      d.Payload,
		Status:       d.Status,
		StatusCode:   int(d.StatusCode),
		ResponseBody: d.ResponseBody,
		Attempts:     int(d.Attempts),
		NextRetryAt:  nextRetryAt,
		CreatedAt:    d.CreatedAt,
	}
}
