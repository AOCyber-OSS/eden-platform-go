-- name: CreateWebhook :one
INSERT INTO webhooks (company_id, url, secret, events)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetWebhook :one
SELECT * FROM webhooks WHERE id = $1;

-- name: ListWebhooksByCompany :many
SELECT * FROM webhooks WHERE company_id = $1 ORDER BY created_at DESC;

-- name: UpdateWebhookStatus :exec
UPDATE webhooks SET active = $2, updated_at = now() WHERE id = $1;

-- name: DeleteWebhook :execrows
-- Tenant-scoped: a webhook id belonging to another company deletes nothing.
DELETE FROM webhooks WHERE id = $1 AND company_id = $2;

-- name: IncrementFailureCount :one
UPDATE webhooks SET consecutive_fails = consecutive_fails + 1, updated_at = now()
WHERE id = $1
RETURNING consecutive_fails;

-- name: ResetFailureCount :exec
UPDATE webhooks SET consecutive_fails = 0, updated_at = now() WHERE id = $1;

-- name: CreateDelivery :one
INSERT INTO webhook_deliveries (webhook_id, event_type, payload)
VALUES ($1, $2, $3)
RETURNING *;

-- name: UpdateDelivery :exec
UPDATE webhook_deliveries
SET status = $2, status_code = $3, response_body = $4, next_retry_at = $5, attempts = attempts + 1
WHERE id = $1;

-- name: GetPendingDeliveries :many
SELECT * FROM webhook_deliveries
WHERE status IN ('pending', 'failed') AND (next_retry_at IS NULL OR next_retry_at <= now())
ORDER BY created_at ASC
LIMIT 100;

-- name: ListDeliveriesByWebhook :many
-- Tenant-scoped: only deliveries of a webhook owned by the given company.
SELECT * FROM webhook_deliveries
WHERE webhook_id = $1
  AND webhook_id IN (SELECT id FROM webhooks WHERE company_id = $2)
ORDER BY created_at DESC
LIMIT $3 OFFSET $4;

-- name: GetDelivery :one
SELECT * FROM webhook_deliveries WHERE id = $1;

-- name: ListFailedDeliveriesForRetry :many
SELECT * FROM webhook_deliveries
WHERE status = 'failed' AND attempts < $1
ORDER BY created_at ASC
LIMIT 100;
