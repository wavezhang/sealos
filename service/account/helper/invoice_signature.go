package helper

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"
)

const (
	// InvoiceTimestampHeader carries the Unix timestamp (seconds) used in the signature.
	InvoiceTimestampHeader = "X-Invoice-Timestamp"
	// InvoiceNonceHeader carries a unique nonce that is rejected on replay.
	InvoiceNonceHeader = "X-Invoice-Nonce"
	// InvoiceSignatureHeader carries the hex HMAC-SHA256 signature.
	InvoiceSignatureHeader = "X-Invoice-Signature"

	// InvoiceSignatureWindow is the maximum clock skew accepted for a request.
	InvoiceSignatureWindow = 5 * time.Minute
)

// InvoiceSignature computes HMAC-SHA256(secret, timestamp + "\n" + nonce + "\n" + body).
func InvoiceSignature(secret string, timestamp int64, nonce string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = fmt.Fprintf(mac, "%d\n%s\n", timestamp, nonce)
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// InvoiceNonceCache rejects replayed nonces within the signature window.
// It is process-local; deployments with multiple replicas should use a shared
// cache (for example Redis) to enforce replay protection cluster-wide.
type InvoiceNonceCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func NewInvoiceNonceCache() *InvoiceNonceCache {
	return &InvoiceNonceCache{seen: make(map[string]time.Time)}
}

// Use records the nonce and reports whether it was previously unseen.
func (c *InvoiceNonceCache) Use(nonce string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, seenAt := range c.seen {
		if now.Sub(seenAt) > 2*InvoiceSignatureWindow {
			delete(c.seen, key)
		}
	}
	if _, ok := c.seen[nonce]; ok {
		return false
	}
	c.seen[nonce] = now
	return true
}

// VerifyInvoiceSignature validates the timestamp window, nonce shape, HMAC and
// replay state for an internal invoice request.
func VerifyInvoiceSignature(
	secret, timestamp, nonce, signature string,
	body []byte,
	now time.Time,
	cache *InvoiceNonceCache,
) error {
	if secret == "" {
		return errors.New("invoice signature secret is not configured")
	}
	if len(nonce) < 16 || len(nonce) > 128 {
		return errors.New("invalid invoice nonce")
	}
	signatureBytes, err := hex.DecodeString(signature)
	if err != nil || len(signatureBytes) != sha256.Size {
		return errors.New("invalid invoice signature encoding")
	}
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return errors.New("invalid invoice timestamp")
	}
	requestTime := time.Unix(ts, 0)
	if requestTime.Before(now.Add(-InvoiceSignatureWindow)) ||
		requestTime.After(now.Add(InvoiceSignatureWindow)) {
		return errors.New("invoice signature timestamp is outside the allowed window")
	}
	expected, err := hex.DecodeString(InvoiceSignature(secret, ts, nonce, body))
	if err != nil {
		return errors.New("failed to compute invoice signature")
	}
	if !hmac.Equal(expected, signatureBytes) {
		return errors.New("invalid invoice signature")
	}
	if cache == nil || !cache.Use(nonce, now) {
		return errors.New("invoice request nonce has already been used")
	}
	return nil
}
