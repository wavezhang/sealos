package helper

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestParseWorkspaceSubscriptionOperatorReqBindsPayApp(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, payApp := range []string{"system-costcenter", "system-brain"} {
		t.Run(payApp, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequestWithContext(
				context.Background(),
				http.MethodPost,
				"/workspace-subscription/pay",
				strings.NewReader(fmt.Sprintf(`{
					"regionDomain":"example.com",
					"planName":"pro",
					"payMethod":"stripe",
					"operator":"created",
					"payApp":%q
				}`, payApp)),
			)
			ctx.Request.Header.Set("Content-Type", "application/json")

			req, err := ParseWorkspaceSubscriptionOperatorReq(ctx)
			if err != nil {
				t.Fatalf("expected payApp %q to be accepted: %v", payApp, err)
			}
			if string(req.PayApp) != payApp {
				t.Fatalf("payApp = %q, want %q", req.PayApp, payApp)
			}
		})
	}
}

func TestParseTransferAmountReqRejectsNonPositiveAmounts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		name       string
		body       string
		wantErr    bool
		wantAmount int64
	}{
		{name: "negative", body: `{"amount":-1,"toUser":"victim"}`, wantErr: true},
		{name: "zero", body: `{"amount":0,"toUser":"victim"}`, wantErr: true},
		{
			name:       "positive",
			body:       `{"amount":100,"toUser":"receiver"}`,
			wantAmount: 100,
		},
		{
			name: "transfer all with zero amount",
			body: `{"amount":0,"toUser":"receiver","transferAll":true}`,
		},
		{
			name: "transfer all ignores supplied amount",
			body: `{"amount":-100,"toUser":"receiver","transferAll":true}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequestWithContext(
				context.Background(),
				http.MethodPost,
				"/transfer",
				strings.NewReader(tc.body),
			)
			ctx.Request.Header.Set("Content-Type", "application/json")

			req, err := ParseTransferAmountReq(ctx)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %s", tc.body)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if req.Amount != tc.wantAmount {
				t.Fatalf("amount = %d, want %d", req.Amount, tc.wantAmount)
			}
		})
	}
}

func TestParseWorkspaceSubscriptionOperatorReqLeavesPayAppValidationToPayEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"/workspace-subscription/upgrade-amount",
		strings.NewReader(`{
			"regionDomain":"example.com",
			"planName":"pro",
			"payMethod":"stripe",
			"operator":"upgraded",
			"payApp":"ignored-by-preview"
		}`),
	)
	ctx.Request.Header.Set("Content-Type", "application/json")

	req, err := ParseWorkspaceSubscriptionOperatorReq(ctx)
	if err != nil {
		t.Fatalf("expected the shared parser not to validate payApp: %v", err)
	}
	if req.PayApp != "ignored-by-preview" {
		t.Fatalf("payApp = %q, want %q", req.PayApp, "ignored-by-preview")
	}
}
