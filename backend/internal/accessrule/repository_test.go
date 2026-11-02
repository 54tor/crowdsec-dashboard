package accessrule

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/geo"
	"crowdsec-dashboard/internal/store/storetest"
)

var clientAddress = netip.MustParseAddr("192.0.2.7")

func createAccount(testContext *testing.T, database *bun.DB, accountName string) int64 {
	testContext.Helper()
	var accountID int64
	insertError := database.NewRaw(
		`INSERT INTO account (account_name, account_role) VALUES (?, 'admin') RETURNING account_id`, accountName).
		Scan(context.Background(), &accountID)
	if insertError != nil {
		testContext.Fatalf("insert account: %v", insertError)
	}
	return accountID
}

func TestAddRuleRefusesWhenCurrentClientWouldBeDenied(testContext *testing.T) {
	database := storetest.New(testContext)
	repository := NewRepository(database)
	accountID := createAccount(testContext, database, "alice")

	_, addError := repository.Add(context.Background(), accountID, KindIP, "203.0.113.0/24", clientAddress, geo.Unavailable{})

	if !errors.Is(addError, ErrWouldLockOut) {
		testContext.Fatalf("expected ErrWouldLockOut, got %v", addError)
	}
	storedRules, _ := repository.List(context.Background(), accountID)
	if len(storedRules) != 0 {
		testContext.Errorf("nothing must be stored, got %+v", storedRules)
	}
	if _, addError = repository.Add(context.Background(), accountID, KindIP, "192.0.2.0/24", clientAddress, geo.Unavailable{}); addError != nil {
		testContext.Fatalf("a rule covering the client must be accepted: %v", addError)
	}
	if _, duplicateError := repository.Add(context.Background(), accountID, KindIP, "192.0.2.9/24", clientAddress, geo.Unavailable{}); !errors.Is(duplicateError, ErrRuleExists) {
		testContext.Errorf("expected ErrRuleExists, got %v", duplicateError)
	}
}

func TestDeleteRuleRefusesWhenCurrentClientWouldBeDenied(testContext *testing.T) {
	database := storetest.New(testContext)
	repository := NewRepository(database)
	accountID := createAccount(testContext, database, "alice")
	coveringRule, _ := repository.Add(context.Background(), accountID, KindIP, "192.0.2.0/24", clientAddress, geo.Unavailable{})
	otherRule, _ := repository.Add(context.Background(), accountID, KindIP, "192.0.2.7", clientAddress, geo.Unavailable{})
	if _, addError := repository.Add(context.Background(), accountID, KindIP, "203.0.113.0/24", clientAddress, geo.Unavailable{}); addError != nil {
		testContext.Fatal(addError)
	}

	if deleteError := repository.Delete(context.Background(), accountID, otherRule.ID, clientAddress, geo.Unavailable{}); deleteError != nil {
		testContext.Fatalf("deleting a redundant rule must succeed: %v", deleteError)
	}
	if deleteError := repository.Delete(context.Background(), accountID, coveringRule.ID, clientAddress, geo.Unavailable{}); !errors.Is(deleteError, ErrWouldLockOut) {
		testContext.Fatalf("expected ErrWouldLockOut, got %v", deleteError)
	}
}

func TestConcurrentAddsOnAccountWithoutRulesAreSerialized(testContext *testing.T) {
	database := storetest.New(testContext)
	repository := NewRepository(database)
	accountID := createAccount(testContext, database, "alice")
	holdingTransaction, beginError := database.BeginTx(context.Background(), nil)
	if beginError != nil {
		testContext.Fatal(beginError)
	}
	if _, lockError := holdingTransaction.ExecContext(context.Background(), `SELECT account_id FROM account WHERE account_id = ? FOR UPDATE`, accountID); lockError != nil {
		testContext.Fatal(lockError)
	}
	results := make(chan error, 1)
	go func() {
		_, addError := repository.Add(context.Background(), accountID, KindIP, "192.0.2.0/24", clientAddress, geo.Unavailable{})
		results <- addError
	}()

	select {
	case addError := <-results:
		testContext.Fatalf("Add must wait for the account row lock, returned %v", addError)
	case <-time.After(300 * time.Millisecond):
	}
	if _, insertError := holdingTransaction.ExecContext(context.Background(),
		`INSERT INTO access_rule (access_rule_account_id, access_rule_kind, access_rule_value) VALUES (?, 'ip', '192.0.2.0/24')`, accountID); insertError != nil {
		testContext.Fatal(insertError)
	}
	if commitError := holdingTransaction.Commit(); commitError != nil {
		testContext.Fatal(commitError)
	}

	if addError := <-results; !errors.Is(addError, ErrRuleExists) {
		testContext.Fatalf("Add must see the committed rule and refuse the duplicate, got %v", addError)
	}
}

func TestDeleteRuleOfOtherAccountReturnsNotFound(testContext *testing.T) {
	database := storetest.New(testContext)
	repository := NewRepository(database)
	ownerID := createAccount(testContext, database, "alice")
	intruderID := createAccount(testContext, database, "bob")
	ownerRule, addError := repository.Add(context.Background(), ownerID, KindIP, "192.0.2.0/24", clientAddress, geo.Unavailable{})
	if addError != nil {
		testContext.Fatal(addError)
	}

	deleteError := repository.Delete(context.Background(), intruderID, ownerRule.ID, clientAddress, geo.Unavailable{})

	if !errors.Is(deleteError, ErrRuleNotFound) {
		testContext.Fatalf("expected ErrRuleNotFound, got %v", deleteError)
	}
	if storedRules, _ := repository.List(context.Background(), ownerID); len(storedRules) != 1 {
		testContext.Errorf("the owner's rule must remain, got %+v", storedRules)
	}
}

func TestAddCountryRuleRefusedWhenGeolocationUnavailable(testContext *testing.T) {
	database := storetest.New(testContext)
	repository := NewRepository(database)
	accountID := createAccount(testContext, database, "alice")

	_, addError := repository.Add(context.Background(), accountID, KindCountry, "fr", clientAddress, geo.Unavailable{})

	if !errors.Is(addError, ErrGeolocationUnavailable) {
		testContext.Fatalf("expected ErrGeolocationUnavailable, got %v", addError)
	}
}

func TestAddRuleRefusesPrefixBelowFloor(testContext *testing.T) {
	database := storetest.New(testContext)
	repository := NewRepository(database)
	accountID := createAccount(testContext, database, "alice")

	_, addError := repository.Add(context.Background(), accountID, KindIP, "192.0.0.0/7", clientAddress, geo.Unavailable{})

	if !errors.Is(addError, ErrPrefixTooBroad) {
		testContext.Fatalf("expected ErrPrefixTooBroad, got %v", addError)
	}
	storedRules, _ := repository.List(context.Background(), accountID)
	if len(storedRules) != 0 {
		testContext.Errorf("nothing must be stored, got %+v", storedRules)
	}
	if _, floorError := repository.Add(context.Background(), accountID, KindIP, "192.0.0.0/8", clientAddress, geo.Unavailable{}); floorError != nil {
		testContext.Errorf("a prefix exactly at the floor must be accepted: %v", floorError)
	}
}

func TestStoredRuleBelowFloorKeepsWorking(testContext *testing.T) {
	database := storetest.New(testContext)
	repository := NewRepository(database)
	accountID := createAccount(testContext, database, "alice")
	if _, insertError := database.ExecContext(context.Background(),
		`INSERT INTO access_rule (access_rule_account_id, access_rule_kind, access_rule_value) VALUES (?, 'ip', '192.0.0.0/4')`, accountID); insertError != nil {
		testContext.Fatal(insertError)
	}

	storedRules, listError := repository.List(context.Background(), accountID)

	if listError != nil || len(storedRules) != 1 || !Allows(context.Background(), storedRules, clientAddress, geo.Unavailable{}) {
		testContext.Errorf("a rule stored before the floor must still be listed and evaluated, got %+v / %v", storedRules, listError)
	}
}
