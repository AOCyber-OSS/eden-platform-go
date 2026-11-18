package devstore

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"go.aocyber.ai/eden-platform-go/platform/webhook"
)

var _ webhook.WebhookStore = (*WebhookStore)(nil)

// WebhookStore implements webhook.WebhookStore using the in-memory devstore backend.
type WebhookStore struct {
	backend *Backend
}

func (s *WebhookStore) CreateWebhook(_ context.Context, companyID uuid.UUID, url, secret string, events []string) (webhook.Webhook, error) {
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()

	wh := webhook.Webhook{
		ID:               uuid.New(),
		CompanyID:        companyID,
		URL:              url,
		Secret:           secret,
		Events:           events,
		Active:           true,
		ConsecutiveFails: 0,
		CreatedAt:        time.Now().UTC(),
	}
	s.backend.state.webhooks[wh.ID] = wh
	return wh, nil
}

func (s *WebhookStore) GetWebhook(_ context.Context, id uuid.UUID) (webhook.Webhook, error) {
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()

	wh, ok := s.backend.state.webhooks[id]
	if !ok {
		return webhook.Webhook{}, fmt.Errorf("webhook not found: %s", id)
	}
	return wh, nil
}

func (s *WebhookStore) ListWebhooksByCompany(_ context.Context, companyID uuid.UUID) ([]webhook.Webhook, error) {
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()

	var webhooks []webhook.Webhook
	for _, wh := range s.backend.state.webhooks {
		if wh.CompanyID == companyID {
			webhooks = append(webhooks, wh)
		}
	}
	sort.Slice(webhooks, func(i, j int) bool {
		return webhooks[i].CreatedAt.Before(webhooks[j].CreatedAt)
	})
	return webhooks, nil
}

func (s *WebhookStore) UpdateWebhookStatus(_ context.Context, id uuid.UUID, active bool) error {
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()

	wh, ok := s.backend.state.webhooks[id]
	if !ok {
		return fmt.Errorf("webhook not found: %s", id)
	}
	wh.Active = active
	s.backend.state.webhooks[id] = wh
	return nil
}

// DeleteWebhook deletes the webhook only when it belongs to companyID.
func (s *WebhookStore) DeleteWebhook(_ context.Context, companyID, id uuid.UUID) error {
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()

	wh, ok := s.backend.state.webhooks[id]
	if !ok || wh.CompanyID != companyID {
		return webhook.ErrWebhookNotFound
	}
	delete(s.backend.state.webhooks, id)
	return nil
}

func (s *WebhookStore) IncrementFailureCount(_ context.Context, id uuid.UUID) (int, error) {
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()

	wh, ok := s.backend.state.webhooks[id]
	if !ok {
		return 0, fmt.Errorf("webhook not found: %s", id)
	}
	wh.ConsecutiveFails++
	s.backend.state.webhooks[id] = wh
	return wh.ConsecutiveFails, nil
}

func (s *WebhookStore) ResetFailureCount(_ context.Context, id uuid.UUID) error {
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()

	wh, ok := s.backend.state.webhooks[id]
	if !ok {
		return fmt.Errorf("webhook not found: %s", id)
	}
	wh.ConsecutiveFails = 0
	s.backend.state.webhooks[id] = wh
	return nil
}

func (s *WebhookStore) CreateDelivery(_ context.Context, webhookID uuid.UUID, eventType, payload string) (webhook.WebhookDelivery, error) {
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()

	delivery := webhook.WebhookDelivery{
		ID:        uuid.New(),
		WebhookID: webhookID,
		EventType: eventType,
		Payload:   payload,
		Status:    "pending",
		Attempts:  0,
		CreatedAt: time.Now().UTC(),
	}
	s.backend.state.deliveries[delivery.ID] = delivery
	return delivery, nil
}

func (s *WebhookStore) UpdateDelivery(_ context.Context, id uuid.UUID, status string, statusCode int, responseBody string, nextRetryAt *time.Time) error {
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()

	delivery, ok := s.backend.state.deliveries[id]
	if !ok {
		return fmt.Errorf("delivery not found: %s", id)
	}
	delivery.Status = status
	delivery.StatusCode = statusCode
	delivery.ResponseBody = responseBody
	delivery.NextRetryAt = nextRetryAt
	delivery.Attempts++
	s.backend.state.deliveries[id] = delivery
	return nil
}

func (s *WebhookStore) GetPendingDeliveries(_ context.Context) ([]webhook.WebhookDelivery, error) {
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()

	var pending []webhook.WebhookDelivery
	for _, d := range s.backend.state.deliveries {
		if d.Status == "pending" {
			pending = append(pending, d)
		}
	}
	return pending, nil
}

// GetDelivery returns a single delivery by ID.
func (s *WebhookStore) GetDelivery(_ context.Context, id uuid.UUID) (webhook.WebhookDelivery, error) {
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()

	d, ok := s.backend.state.deliveries[id]
	if !ok {
		return webhook.WebhookDelivery{}, fmt.Errorf("delivery not found: %s", id)
	}
	return d, nil
}

// ListFailedDeliveriesForRetry returns deliveries with status="failed" and
// Attempts < maxAttempts. Used by Service.RetryFailedDeliveries.
func (s *WebhookStore) ListFailedDeliveriesForRetry(_ context.Context, maxAttempts int) ([]webhook.WebhookDelivery, error) {
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()

	var out []webhook.WebhookDelivery
	for _, d := range s.backend.state.deliveries {
		if d.Status == "failed" && d.Attempts < maxAttempts {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

// ListDeliveriesByWebhook returns deliveries for a webhook owned by
// companyID with pagination, sorted by CreatedAt DESC.
func (s *WebhookStore) ListDeliveriesByWebhook(_ context.Context, companyID, webhookID uuid.UUID, limit, offset int) ([]webhook.WebhookDelivery, error) {
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()

	if wh, ok := s.backend.state.webhooks[webhookID]; !ok || wh.CompanyID != companyID {
		return nil, nil
	}

	var filtered []webhook.WebhookDelivery
	for _, d := range s.backend.state.deliveries {
		if d.WebhookID == webhookID {
			filtered = append(filtered, d)
		}
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].CreatedAt.After(filtered[j].CreatedAt)
	})

	if offset >= len(filtered) {
		return nil, nil
	}
	filtered = filtered[offset:]
	if limit > 0 && limit < len(filtered) {
		filtered = filtered[:limit]
	}

	return filtered, nil
}
