package connectapi

import (
	"context"
	"errors"
	"time"

	connect "connectrpc.com/connect"
	platformv1 "go.aocyber.ai/eden-platform-go/gen/go/platform/v1"
	platformv1connect "go.aocyber.ai/eden-platform-go/gen/go/platform/v1/platformv1connect"
	"github.com/google/uuid"
	"go.aocyber.ai/eden-platform-go/platform/auth"
	"go.aocyber.ai/eden-platform-go/platform/webhook"
)

var _ platformv1connect.WebhookServiceHandler = (*WebhookHandler)(nil)

// deliveryQuerier provides paginated delivery listing beyond the base
// WebhookStore interface. Implementations MUST scope by companyID: only
// deliveries of a webhook owned by that company are returned.
type deliveryQuerier interface {
	ListDeliveriesByWebhook(ctx context.Context, companyID, webhookID uuid.UUID, limit, offset int) ([]webhook.WebhookDelivery, error)
}

// WebhookHandler implements the WebhookService Connect handler. Every RPC is
// scoped to the caller's company from the verified JWT claims; a request
// body's company_id is only accepted when it matches.
type WebhookHandler struct {
	service         *webhook.Service
	store           webhook.WebhookStore
	deliveryQuerier deliveryQuerier
}

// NewWebhookHandler creates a new webhook handler.
// The querier parameter should be the concrete devstore/pgstore WebhookStore, which implements deliveryQuerier.
func NewWebhookHandler(service *webhook.Service, store webhook.WebhookStore, querier deliveryQuerier) *WebhookHandler {
	return &WebhookHandler{service: service, store: store, deliveryQuerier: querier}
}

// errWebhookNotFound is the single answer for "no such webhook" and "a
// webhook of another tenant": the two must be indistinguishable.
var errWebhookNotFound = connect.NewError(connect.CodeNotFound, webhook.ErrWebhookNotFound)

// callerCompany returns the caller's company from verified claims.
func callerCompany(ctx context.Context) (uuid.UUID, error) {
	id, err := auth.RequireCompany(ctx)
	if err != nil {
		return uuid.Nil, connect.NewError(connect.CodeUnauthenticated, err)
	}
	return id, nil
}

// requestedCompany checks a request body's company_id against the caller.
func requestedCompany(ctx context.Context, raw string) (uuid.UUID, error) {
	caller, err := callerCompany(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	requested, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if requested != caller {
		return uuid.Nil, connect.NewError(connect.CodePermissionDenied,
			errors.New("webhook: company_id does not match the caller's company"))
	}
	return caller, nil
}

func (h *WebhookHandler) RegisterWebhook(ctx context.Context, req *connect.Request[platformv1.RegisterWebhookRequest]) (*connect.Response[platformv1.RegisterWebhookResponse], error) {
	companyID, err := requestedCompany(ctx, req.Msg.GetCompanyId())
	if err != nil {
		return nil, err
	}

	wh, err := h.service.Register(ctx, companyID, req.Msg.GetUrl(), "", req.Msg.GetEvents())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	return connect.NewResponse(&platformv1.RegisterWebhookResponse{Webhook: webhookToProto(wh)}), nil
}

func (h *WebhookHandler) ListWebhooks(ctx context.Context, req *connect.Request[platformv1.ListWebhooksRequest]) (*connect.Response[platformv1.ListWebhooksResponse], error) {
	companyID, err := requestedCompany(ctx, req.Msg.GetCompanyId())
	if err != nil {
		return nil, err
	}

	webhooks, err := h.store.ListWebhooksByCompany(ctx, companyID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	protoWebhooks := make([]*platformv1.WebhookData, 0, len(webhooks))
	for _, wh := range webhooks {
		protoWebhooks = append(protoWebhooks, webhookToProto(wh))
	}

	return connect.NewResponse(&platformv1.ListWebhooksResponse{Webhooks: protoWebhooks}), nil
}

func (h *WebhookHandler) DeleteWebhook(ctx context.Context, req *connect.Request[platformv1.DeleteWebhookRequest]) (*connect.Response[platformv1.DeleteWebhookResponse], error) {
	companyID, err := callerCompany(ctx)
	if err != nil {
		return nil, err
	}
	id, err := uuid.Parse(req.Msg.GetId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	if err := h.store.DeleteWebhook(ctx, companyID, id); err != nil {
		if errors.Is(err, webhook.ErrWebhookNotFound) {
			return nil, errWebhookNotFound
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&platformv1.DeleteWebhookResponse{}), nil
}

func (h *WebhookHandler) ListDeliveries(ctx context.Context, req *connect.Request[platformv1.ListDeliveriesRequest]) (*connect.Response[platformv1.ListDeliveriesResponse], error) {
	companyID, err := callerCompany(ctx)
	if err != nil {
		return nil, err
	}
	webhookID, err := uuid.Parse(req.Msg.GetWebhookId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	// Ownership first, so another tenant's id is NotFound rather than an
	// empty list; the query below is scoped as well (defense in depth).
	wh, err := h.store.GetWebhook(ctx, webhookID)
	if err != nil || wh.CompanyID != companyID {
		return nil, errWebhookNotFound
	}

	limit := int(req.Msg.GetLimit())
	if limit <= 0 {
		limit = 50
	}
	offset := int(req.Msg.GetOffset())
	if offset < 0 {
		offset = 0
	}

	deliveries, err := h.deliveryQuerier.ListDeliveriesByWebhook(ctx, companyID, webhookID, limit, offset)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	protoDeliveries := make([]*platformv1.DeliveryResponse, 0, len(deliveries))
	for _, d := range deliveries {
		protoDeliveries = append(protoDeliveries, &platformv1.DeliveryResponse{
			Id:         d.ID.String(),
			WebhookId:  d.WebhookID.String(),
			EventType:  d.EventType,
			Status:     d.Status,
			StatusCode: int32(d.StatusCode),
			Attempts:   int32(d.Attempts),
			CreatedAt:  d.CreatedAt.Format(time.RFC3339),
		})
	}

	return connect.NewResponse(&platformv1.ListDeliveriesResponse{Deliveries: protoDeliveries}), nil
}

func webhookToProto(wh webhook.Webhook) *platformv1.WebhookData {
	return &platformv1.WebhookData{
		Id:        wh.ID.String(),
		CompanyId: wh.CompanyID.String(),
		Url:       wh.URL,
		Secret:    wh.Secret,
		Events:    wh.Events,
		Active:    wh.Active,
		CreatedAt: wh.CreatedAt.Format(time.RFC3339),
	}
}
