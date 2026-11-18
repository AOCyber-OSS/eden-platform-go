package connectapi

// Tenant isolation for the WebhookService (#77), driven through the real
// Connect HTTP stack and the production auth interceptor with minted JWTs.
// Fixtures are hand-built: two companies, one webhook + one delivery owned
// by company A.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	connect "connectrpc.com/connect"
	"github.com/google/uuid"
	platformv1 "go.aocyber.ai/eden-platform-go/gen/go/platform/v1"
	platformv1connect "go.aocyber.ai/eden-platform-go/gen/go/platform/v1/platformv1connect"
	"go.aocyber.ai/eden-platform-go/platform/auth"
	"go.aocyber.ai/eden-platform-go/platform/devstore"
	"go.aocyber.ai/eden-platform-go/platform/server"
	"go.aocyber.ai/eden-platform-go/platform/webhook"
)

type webhookTenantEnv struct {
	client    platformv1connect.WebhookServiceClient
	handler   *WebhookHandler
	store     *devstore.WebhookStore
	companyA  uuid.UUID
	companyB  uuid.UUID
	tokenA    string
	tokenB    string
	hookA     webhook.Webhook
	deliveryA webhook.WebhookDelivery
}

func setupWebhookTenantEnv(t *testing.T) *webhookTenantEnv {
	t.Helper()
	backend := devstore.NewMemoryBackend()
	store := backend.WebhookStore()
	ctx := context.Background()

	env := &webhookTenantEnv{store: store, companyA: uuid.New(), companyB: uuid.New()}
	var err error
	env.hookA, err = store.CreateWebhook(ctx, env.companyA, "https://a.example.com/hook", "secret-of-a", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	env.deliveryA, err = store.CreateDelivery(ctx, env.hookA.ID, "user.created", `{"pii":"of-a"}`)
	if err != nil {
		t.Fatal(err)
	}

	jwtManager, err := auth.NewJWTManager(auth.JWTConfig{Issuer: "webhook-tenant-test", AccessTokenExpiry: auth.DefaultJWTConfig().AccessTokenExpiry})
	if err != nil {
		t.Fatal(err)
	}
	mint := func(company uuid.UUID) string {
		tok, err := jwtManager.CreateAccessToken(uuid.NewString(), company.String(), "admin", 80, []string{company.String()})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	env.tokenA, env.tokenB = mint(env.companyA), mint(env.companyB)

	env.handler = NewWebhookHandler(webhook.NewService(store), store, store)
	mux := http.NewServeMux()
	path, h := platformv1connect.NewWebhookServiceHandler(env.handler,
		connect.WithInterceptors(server.NewAuthInterceptor(jwtManager, server.DefaultPublicProcedures())))
	mux.Handle(path, h)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env.client = platformv1connect.NewWebhookServiceClient(http.DefaultClient, ts.URL)
	return env
}

func withBearer[T any](msg *T, token string) *connect.Request[T] {
	req := connect.NewRequest(msg)
	req.Header().Set("Authorization", "Bearer "+token)
	return req
}

func requireCode(t *testing.T, err error, want connect.Code) {
	t.Helper()
	var ce *connect.Error
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v (%T), want connect code %v", err, err, want)
	}
	if ce.Code() != want {
		t.Fatalf("code = %v (%v), want %v", ce.Code(), ce.Message(), want)
	}
}

func TestWebhookAPI_DeleteWebhook_WrongTenantIsNoOpAndNotFound(t *testing.T) {
	env := setupWebhookTenantEnv(t)
	_, err := env.client.DeleteWebhook(context.Background(),
		withBearer(&platformv1.DeleteWebhookRequest{Id: env.hookA.ID.String()}, env.tokenB))
	requireCode(t, err, connect.CodeNotFound)

	if _, gerr := env.store.GetWebhook(context.Background(), env.hookA.ID); gerr != nil {
		t.Fatalf("company A's webhook was deleted by company B: %v", gerr)
	}
}

func TestWebhookAPI_DeleteWebhook_SameTenantDeletes(t *testing.T) {
	env := setupWebhookTenantEnv(t)
	if _, err := env.client.DeleteWebhook(context.Background(),
		withBearer(&platformv1.DeleteWebhookRequest{Id: env.hookA.ID.String()}, env.tokenA)); err != nil {
		t.Fatalf("same-tenant delete = %v", err)
	}
	if _, gerr := env.store.GetWebhook(context.Background(), env.hookA.ID); gerr == nil {
		t.Fatal("webhook still exists after same-tenant delete")
	}
}

func TestWebhookAPI_DeleteWebhook_UnknownIDIsNotFound(t *testing.T) {
	env := setupWebhookTenantEnv(t)
	_, err := env.client.DeleteWebhook(context.Background(),
		withBearer(&platformv1.DeleteWebhookRequest{Id: uuid.NewString()}, env.tokenA))
	requireCode(t, err, connect.CodeNotFound)
}

func TestWebhookAPI_ListDeliveries_WrongTenantIsNotFound(t *testing.T) {
	env := setupWebhookTenantEnv(t)
	resp, err := env.client.ListDeliveries(context.Background(),
		withBearer(&platformv1.ListDeliveriesRequest{WebhookId: env.hookA.ID.String()}, env.tokenB))
	if err == nil {
		t.Fatalf("company B listed company A's deliveries: %d rows", len(resp.Msg.GetDeliveries()))
	}
	requireCode(t, err, connect.CodeNotFound)
}

func TestWebhookAPI_ListDeliveries_SameTenantLists(t *testing.T) {
	env := setupWebhookTenantEnv(t)
	resp, err := env.client.ListDeliveries(context.Background(),
		withBearer(&platformv1.ListDeliveriesRequest{WebhookId: env.hookA.ID.String()}, env.tokenA))
	if err != nil {
		t.Fatalf("same-tenant list = %v", err)
	}
	if got := resp.Msg.GetDeliveries(); len(got) != 1 || got[0].GetId() != env.deliveryA.ID.String() {
		t.Fatalf("deliveries = %v, want exactly delivery %s", got, env.deliveryA.ID)
	}
}

// Sibling of #77: ListWebhooks / RegisterWebhook took company_id from the
// request body unchecked, so company B could list company A's webhooks —
// including their signing secrets — or register one under A.
func TestWebhookAPI_ListWebhooks_OtherCompanyIsPermissionDenied(t *testing.T) {
	env := setupWebhookTenantEnv(t)
	resp, err := env.client.ListWebhooks(context.Background(),
		withBearer(&platformv1.ListWebhooksRequest{CompanyId: env.companyA.String()}, env.tokenB))
	if err == nil {
		t.Fatalf("company B listed company A's webhooks: %v", resp.Msg.GetWebhooks())
	}
	requireCode(t, err, connect.CodePermissionDenied)

	own, err := env.client.ListWebhooks(context.Background(),
		withBearer(&platformv1.ListWebhooksRequest{CompanyId: env.companyA.String()}, env.tokenA))
	if err != nil || len(own.Msg.GetWebhooks()) != 1 {
		t.Fatalf("same-tenant ListWebhooks = %v, %v; want 1 webhook", own, err)
	}
}

func TestWebhookAPI_RegisterWebhook_OtherCompanyIsPermissionDenied(t *testing.T) {
	env := setupWebhookTenantEnv(t)
	_, err := env.client.RegisterWebhook(context.Background(),
		withBearer(&platformv1.RegisterWebhookRequest{CompanyId: env.companyA.String(), Url: "https://b.example.com/hook", Events: []string{"*"}}, env.tokenB))
	requireCode(t, err, connect.CodePermissionDenied)

	hooks, _ := env.store.ListWebhooksByCompany(context.Background(), env.companyA)
	if len(hooks) != 1 {
		t.Fatalf("company A has %d webhooks, want 1 (B must not register under A)", len(hooks))
	}
}

func TestWebhookHandler_NoClaimsIsUnauthenticated(t *testing.T) {
	env := setupWebhookTenantEnv(t)
	_, err := env.handler.DeleteWebhook(context.Background(), connect.NewRequest(&platformv1.DeleteWebhookRequest{Id: env.hookA.ID.String()}))
	requireCode(t, err, connect.CodeUnauthenticated)
	_, err = env.handler.ListDeliveries(context.Background(), connect.NewRequest(&platformv1.ListDeliveriesRequest{WebhookId: env.hookA.ID.String()}))
	requireCode(t, err, connect.CodeUnauthenticated)
	if _, gerr := env.store.GetWebhook(context.Background(), env.hookA.ID); gerr != nil {
		t.Fatalf("unauthenticated delete removed the webhook: %v", gerr)
	}
}
