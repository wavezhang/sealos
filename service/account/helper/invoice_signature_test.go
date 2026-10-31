package helper

import (
	"strconv"
	"testing"
	"time"
)

func TestVerifyInvoiceSignature(t *testing.T) {
	const (
		secret = "test-invoice-secret"
		nonce  = "0123456789abcdef0123456789abcdef"
	)
	now := time.Unix(1_700_000_000, 0)
	body := []byte(`{"invoiceIDList":["invoice-1"],"status":"COMPLETED"}`)
	timestamp := strconv.FormatInt(now.Unix(), 10)
	signature := InvoiceSignature(secret, now.Unix(), nonce, body)

	t.Run("valid", func(t *testing.T) {
		if err := VerifyInvoiceSignature(
			secret,
			timestamp,
			nonce,
			signature,
			body,
			now,
			NewInvoiceNonceCache(),
		); err != nil {
			t.Fatalf("expected signature to verify: %v", err)
		}
	})

	t.Run("tampered body", func(t *testing.T) {
		if err := VerifyInvoiceSignature(
			secret,
			timestamp,
			nonce,
			signature,
			[]byte(`{"invoiceIDList":["invoice-2"],"status":"COMPLETED"}`),
			now,
			NewInvoiceNonceCache(),
		); err == nil {
			t.Fatal("expected a tampered body to be rejected")
		}
	})

	t.Run("wrong secret", func(t *testing.T) {
		if err := VerifyInvoiceSignature(
			"other-secret",
			timestamp,
			nonce,
			signature,
			body,
			now,
			NewInvoiceNonceCache(),
		); err == nil {
			t.Fatal("expected a signature from another secret to be rejected")
		}
	})

	t.Run("expired timestamp", func(t *testing.T) {
		if err := VerifyInvoiceSignature(
			secret,
			timestamp,
			nonce,
			signature,
			body,
			now.Add(InvoiceSignatureWindow+time.Second),
			NewInvoiceNonceCache(),
		); err == nil {
			t.Fatal("expected an expired timestamp to be rejected")
		}
	})

	t.Run("replayed nonce", func(t *testing.T) {
		cache := NewInvoiceNonceCache()
		if err := VerifyInvoiceSignature(secret, timestamp, nonce, signature, body, now, cache); err != nil {
			t.Fatalf("first request should verify: %v", err)
		}
		if err := VerifyInvoiceSignature(secret, timestamp, nonce, signature, body, now, cache); err == nil {
			t.Fatal("expected a replayed nonce to be rejected")
		}
	})

	t.Run("missing secret", func(t *testing.T) {
		if err := VerifyInvoiceSignature("", timestamp, nonce, signature, body, now, NewInvoiceNonceCache()); err == nil {
			t.Fatal("expected an empty secret to be rejected")
		}
	})
}
