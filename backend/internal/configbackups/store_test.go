package configbackups

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"crowdsec-dashboard/internal/store/storetest"
)

const retainedBackupCount = 10

type storeFactory func(testContext *testing.T) Store

// runStoreContract runs the same behavioural table against every Store
// implementation, so the in-memory fake used by API tests cannot drift from
// the PostgreSQL store.
func runStoreContract(testContext *testing.T, newStore storeFactory) {
	contractCases := map[string]func(*testing.T, Store){
		"keepsOnlyTenMostRecentBackupsPerFile": func(testContext *testing.T, backupStore Store) {
			for backupIndex := 0; backupIndex < retainedBackupCount+3; backupIndex++ {
				addBackup(testContext, backupStore, "local", "config.yaml", fmt.Sprintf("version %d", backupIndex))
			}

			listedBackups, listError := backupStore.List(context.Background(), "local", "config.yaml")
			if listError != nil {
				testContext.Fatalf("list: %v", listError)
			}
			if len(listedBackups) != retainedBackupCount {
				testContext.Fatalf("listed %d backups, want %d", len(listedBackups), retainedBackupCount)
			}
			oldestKeptContent := string(listedBackups[retainedBackupCount-1].Content)
			if oldestKeptContent != "version 3" {
				testContext.Fatalf("oldest kept = %q, want %q", oldestKeptContent, "version 3")
			}
		},
		"doesNotTouchOtherFilesOrEngines": func(testContext *testing.T, backupStore Store) {
			addBackup(testContext, backupStore, "local", "profiles.yaml", "other file")
			addBackup(testContext, backupStore, "remote", "config.yaml", "other engine")
			for backupIndex := 0; backupIndex < retainedBackupCount+2; backupIndex++ {
				addBackup(testContext, backupStore, "local", "config.yaml", fmt.Sprintf("version %d", backupIndex))
			}

			for _, untouched := range []struct{ engineName, fileName string }{
				{"local", "profiles.yaml"},
				{"remote", "config.yaml"},
			} {
				listedBackups, listError := backupStore.List(context.Background(), untouched.engineName, untouched.fileName)
				if listError != nil {
					testContext.Fatalf("list: %v", listError)
				}
				if len(listedBackups) != 1 {
					testContext.Fatalf("%s/%s holds %d backups, want 1", untouched.engineName, untouched.fileName, len(listedBackups))
				}
			}
		},
		"listsNewestFirst": func(testContext *testing.T, backupStore Store) {
			for _, content := range []string{"first", "second", "third"} {
				addBackup(testContext, backupStore, "local", "config.yaml", content)
			}

			listedBackups, listError := backupStore.List(context.Background(), "local", "config.yaml")
			if listError != nil {
				testContext.Fatalf("list: %v", listError)
			}
			valeurAttendue := []string{"third", "second", "first"}
			for backupIndex, backup := range listedBackups {
				if string(backup.Content) != valeurAttendue[backupIndex] {
					testContext.Fatalf("backup %d = %q, want %q", backupIndex, backup.Content, valeurAttendue[backupIndex])
				}
			}
		},
		"returnsNotFoundForUnknownIdentifier": func(testContext *testing.T, backupStore Store) {
			_, getError := backupStore.Get(context.Background(), 987654321)
			if !errors.Is(getError, ErrNotFound) {
				testContext.Fatalf("get error = %v, want ErrNotFound", getError)
			}
		},
		"rejectsOversizedAndNulContent": func(testContext *testing.T, backupStore Store) {
			oversizedError := backupStore.Add(context.Background(), Backup{
				EngineName: "local", FileName: "config.yaml", Content: bytes.Repeat([]byte("a"), MaximumContentBytes+1),
			})
			if !errors.Is(oversizedError, ErrContentTooLarge) {
				testContext.Fatalf("oversized error = %v, want ErrContentTooLarge", oversizedError)
			}
			nulError := backupStore.Add(context.Background(), Backup{
				EngineName: "local", FileName: "config.yaml", Content: []byte("a\x00b"),
			})
			if !errors.Is(nulError, ErrContentInvalid) {
				testContext.Fatalf("nul error = %v, want ErrContentInvalid", nulError)
			}
			maximumError := backupStore.Add(context.Background(), Backup{
				EngineName: "local", FileName: "config.yaml", Content: bytes.Repeat([]byte("a"), MaximumContentBytes),
			})
			if maximumError != nil {
				testContext.Fatalf("content at the limit refused: %v", maximumError)
			}
			listedBackups, _ := backupStore.List(context.Background(), "local", "config.yaml")
			if len(listedBackups) != 1 {
				testContext.Fatalf("rejected content was stored: %d backups, want 1", len(listedBackups))
			}
		},
		"storesContentByteForByte": func(testContext *testing.T, backupStore Store) {
			valeurAttendue := []byte("key: \"***\"\r\n\ttabbed: ünïcode  \n\n")
			addBackup(testContext, backupStore, "local", "config.yaml", string(valeurAttendue))

			listedBackups, listError := backupStore.List(context.Background(), "local", "config.yaml")
			if listError != nil || len(listedBackups) != 1 {
				testContext.Fatalf("list = %v, %v", listedBackups, listError)
			}
			fetchedBackup, getError := backupStore.Get(context.Background(), listedBackups[0].ID)
			if getError != nil {
				testContext.Fatalf("get: %v", getError)
			}
			if !bytes.Equal(fetchedBackup.Content, valeurAttendue) {
				testContext.Fatalf("content = %q, want %q", fetchedBackup.Content, valeurAttendue)
			}
			if fetchedBackup.AccountName != "alice" || fetchedBackup.Digest != "digest" || fetchedBackup.CreatedAt.IsZero() {
				testContext.Fatalf("metadata not stored: %+v", fetchedBackup)
			}
		},
	}
	for caseName, runCase := range contractCases {
		testContext.Run(caseName, func(subTest *testing.T) {
			runCase(subTest, newStore(subTest))
		})
	}
}

func addBackup(testContext *testing.T, backupStore Store, engineName, fileName, content string) {
	testContext.Helper()
	addError := backupStore.Add(context.Background(), Backup{
		EngineName: engineName, FileName: fileName, Content: []byte(content), AccountName: "alice", Digest: "digest",
	})
	if addError != nil {
		testContext.Fatalf("add: %v", addError)
	}
}

func TestMemoryStoreHonoursTheStoreContract(testContext *testing.T) {
	runStoreContract(testContext, func(*testing.T) Store { return NewMemoryStore() })
}

func TestPostgresStoreHonoursTheStoreContract(testContext *testing.T) {
	runStoreContract(testContext, func(subTest *testing.T) Store {
		return NewPostgresStore(storetest.New(subTest))
	})
}
