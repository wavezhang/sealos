package cockroach

import (
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/labring/sealos/controllers/pkg/types"
)

func TestBalanceDebit(t *testing.T) {
	cases := []struct {
		name        string
		isDeduction bool
		add         bool
		amount      int64
		wantDebit   int64
		wantDeduct  bool
	}{
		{name: "transfer sender", add: true, amount: -100, wantDebit: 100, wantDeduct: true},
		{name: "refund deduction", add: false, amount: 100, wantDebit: 100, wantDeduct: true},
		{name: "top up", add: true, amount: 100},
		{name: "negative amount with add=false is a top up", add: false, amount: -100},
		{name: "deduction balance is not the cash balance", isDeduction: true, add: true, amount: 100},
		{name: "zero amount", add: true, amount: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			debit, ok := balanceDebit(tc.isDeduction, tc.add, tc.amount)
			if debit != tc.wantDebit || ok != tc.wantDeduct {
				t.Fatalf(
					"balanceDebit(%v, %v, %d) = (%d, %v), want (%d, %v)",
					tc.isDeduction,
					tc.add,
					tc.amount,
					debit,
					ok,
					tc.wantDebit,
					tc.wantDeduct,
				)
			}
		})
	}
}

// TestUpdateWithAccountPreventsOverdraft requires a CockroachDB instance:
//
//	RUN_COCKROACH_TESTS=true GLOBAL_COCKROACH_URI=... LOCAL_COCKROACH_URI=... \
//	LOCAL_REGION=... go test ./database/cockroach -run TestUpdateWithAccountPreventsOverdraft
func TestUpdateWithAccountPreventsOverdraft(t *testing.T) {
	globalURI, localURI := requireCockroachTest(t)
	c, err := NewCockRoach(globalURI, localURI)
	if err != nil {
		t.Fatalf("NewCockRoach() error = %v", err)
	}
	defer c.Close()

	userUID := uuid.New()
	account := types.Account{
		UserUID:        userUID,
		Balance:        100,
		CreateRegionID: "test-region",
	}
	if err := c.DB.Create(&account).Error; err != nil {
		t.Fatalf("failed to create account: %v", err)
	}
	t.Cleanup(func() {
		c.DB.Delete(&types.Account{}, `"userUid" = ?`, userUID)
	})

	const (
		attempts = 4
		amount   = 60
	)
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded int
	)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.updateWithAccount(userUID, false, false, false, amount, c.DB); err == nil {
				mu.Lock()
				succeeded++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if succeeded != 1 {
		t.Fatalf("successful deductions = %d, want 1 (balance must never go negative)", succeeded)
	}
	var stored types.Account
	if err := c.DB.Where(`"userUid" = ?`, userUID).First(&stored).Error; err != nil {
		t.Fatalf("failed to read account: %v", err)
	}
	if stored.Balance != 40 {
		t.Fatalf("balance = %d, want 40", stored.Balance)
	}
}
