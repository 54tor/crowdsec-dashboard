package cscli

import (
	"slices"
	"testing"
)

// The allowlist of cscli commands is a security boundary: any added or
// removed command must show up here as a deliberate, reviewed change.
func TestNamesIsExactlyThePinnedCommandList(testContext *testing.T) {
	pinnedNames := []string{
		"alerts_delete",
		"allowlists_add",
		"allowlists_create",
		"allowlists_delete",
		"allowlists_remove",
		"appsec_configs_install",
		"appsec_configs_remove",
		"appsec_rules_install",
		"appsec_rules_remove",
		"bouncers_add",
		"bouncers_delete",
		"bouncers_list",
		"collections_install",
		"collections_remove",
		"config_test",
		"hub_list",
		"hub_update",
		"hub_upgrade",
		"machines_add",
		"machines_delete",
		"machines_list",
		"machines_validate",
		"metrics",
		"reload",
		"version",
	}

	listedNames := Names()

	if !slices.Equal(listedNames, pinnedNames) {
		testContext.Fatalf("cscli command list changed:\nexpected %v\ngot      %v", pinnedNames, listedNames)
	}
}
