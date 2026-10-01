// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"encoding/json"
	"testing"
)

// roleChallengeVectors pins the challenge for each role-gated request. The
// same table (request JSON -> challenge) is pinned in the rendezvous module
// (authz/zz_network_role_challenge_test.go), which is what keeps the
// client's signing and the server's verification from drifting apart.
// Change one, change both.
var roleChallengeVectors = []struct {
	request string
	want    string
}{
	{`{"type":"delete_network","node_id":5,"network_id":7}`,
		"delete_network:5:7"},
	{`{"type":"rename_network","node_id":5,"network_id":7,"name":"lab-net"}`,
		"rename_network:5:7:lab-net"},
	{`{"type":"kick_member","node_id":5,"network_id":7,"target_node_id":9}`,
		"kick_member:5:7:9"},
	{`{"type":"promote_member","node_id":5,"network_id":7,"target_node_id":9}`,
		"promote_member:5:7:9"},
	{`{"type":"demote_member","node_id":5,"network_id":7,"target_node_id":9}`,
		"demote_member:5:7:9"},
	{`{"type":"transfer_ownership","node_id":5,"network_id":7,"new_owner_id":9}`,
		"transfer_ownership:5:7:9"},
	{`{"type":"set_member_tags","node_id":5,"network_id":7,"target_node_id":9,"tags":["gpu","eu-west"]}`,
		"set_member_tags:5:7:9:6181819da0f863b3ef845fbd74e290e98bf779d2c18a2c1a3afcf5fdc63eb66c"},
	{`{"type":"set_member_tags","node_id":5,"network_id":7,"target_node_id":9,"tags":[]}`,
		"set_member_tags:5:7:9:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	{`{"type":"set_network_policy","node_id":5,"network_id":7,"max_members":50,"allowed_ports":[80,443],"description":"prod"}`,
		"set_network_policy:5:7:23afbff65fece371606dd2bf351e0656fe72604d2dd4bc2a2dab5f114762d2da"},
	{`{"type":"set_network_policy","node_id":5,"network_id":7,"max_members":50}`,
		"set_network_policy:5:7:216c888a3e02e0063d6d91ec4e8e502bb9e2dfe984e5d4a59482d464c197bc71"},
	{`{"type":"set_network_policy","node_id":5,"network_id":7,"description":""}`,
		"set_network_policy:5:7:622ba1eb91d05acfb62b09f19bf4573d07f6842860c2eb444900c1600997ea4b"},
	{`{"type":"set_expr_policy","node_id":5,"network_id":7,"expr_policy":"{\"version\":1,\"rules\":[]}"}`,
		"set_expr_policy:5:7:6be6bac38f2d35217ca3cd98e36322f9e8fb6638564f5a87ff660589f6302103"},
	{`{"type":"set_expr_policy","node_id":5,"network_id":7,"expr_policy":""}`,
		"set_expr_policy:5:7:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
}

func TestNetworkRoleChallengeVectors(t *testing.T) {
	t.Parallel()
	for _, v := range roleChallengeVectors {
		var msg map[string]interface{}
		if err := json.Unmarshal([]byte(v.request), &msg); err != nil {
			t.Fatalf("%s: %v", v.request, err)
		}
		got, ok := networkRoleChallenge(msg)
		if !ok || got != v.want {
			t.Errorf("%s\n got  %s (ok=%v)\n want %s", v.request, got, ok, v.want)
		}
	}
}

// Every role-gated method signs the challenge for the request it actually
// sends, built from Go-typed arguments rather than decoded JSON.
func TestNetworkRoleMethodsSign(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	c.SetSigner(func(ch string) string { return "SIG:" + ch })

	cases := []struct {
		name string
		call func() (map[string]interface{}, error)
		want string
	}{
		{"DeleteNetwork", func() (map[string]interface{}, error) { return c.DeleteNetwork(7, "", 5) },
			"delete_network:5:7"},
		{"RenameNetwork", func() (map[string]interface{}, error) { return c.RenameNetwork(7, "lab-net", "", 5) },
			"rename_network:5:7:lab-net"},
		{"KickMember", func() (map[string]interface{}, error) { return c.KickMember(7, 5, 9, "") },
			"kick_member:5:7:9"},
		{"PromoteMember", func() (map[string]interface{}, error) { return c.PromoteMember(7, 5, 9, "") },
			"promote_member:5:7:9"},
		{"DemoteMember", func() (map[string]interface{}, error) { return c.DemoteMember(7, 5, 9, "") },
			"demote_member:5:7:9"},
		{"TransferOwnership", func() (map[string]interface{}, error) { return c.TransferOwnership(7, 5, 9, "") },
			"transfer_ownership:5:7:9"},
		{"SetMemberTagsAs", func() (map[string]interface{}, error) {
			return c.SetMemberTagsAs(5, 7, 9, []string{"gpu", "eu-west"}, "")
		}, "set_member_tags:5:7:9:6181819da0f863b3ef845fbd74e290e98bf779d2c18a2c1a3afcf5fdc63eb66c"},
		{"SetMemberTagsAs/nil", func() (map[string]interface{}, error) { return c.SetMemberTagsAs(5, 7, 9, nil, "") },
			"set_member_tags:5:7:9:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"SetNetworkPolicyAs", func() (map[string]interface{}, error) {
			return c.SetNetworkPolicyAs(5, 7, map[string]interface{}{
				"max_members": 50, "allowed_ports": []int{80, 443}, "description": "prod",
			}, "")
		}, "set_network_policy:5:7:23afbff65fece371606dd2bf351e0656fe72604d2dd4bc2a2dab5f114762d2da"},
		{"SetExprPolicyAs", func() (map[string]interface{}, error) {
			return c.SetExprPolicyAs(5, 7, json.RawMessage(`{"version":1,"rules":[]}`), "")
		}, "set_expr_policy:5:7:6be6bac38f2d35217ca3cd98e36322f9e8fb6638564f5a87ff660589f6302103"},
	}
	for _, tc := range cases {
		resp, err := tc.call()
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		echo := assertEcho(t, resp)
		if got, _ := echo["signature"].(string); got != "SIG:"+tc.want {
			t.Errorf("%s: signature %q, want %q", tc.name, got, "SIG:"+tc.want)
		}
		if got, _ := echo["node_id"].(float64); got != 5 {
			t.Errorf("%s: node_id %v, want 5", tc.name, echo["node_id"])
		}
	}
}

// A request that names no node is not a role claim: it goes out exactly as
// before, with no signature, and is authorized by its admin token.
func TestNetworkRoleNoNodeIDNotSigned(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	c.SetSigner(func(ch string) string { return "SIG:" + ch })

	calls := map[string]func() (map[string]interface{}, error){
		"DeleteNetwork": func() (map[string]interface{}, error) { return c.DeleteNetwork(7, "ADM") },
		"RenameNetwork": func() (map[string]interface{}, error) { return c.RenameNetwork(7, "x", "ADM") },
		"PromoteMember": func() (map[string]interface{}, error) { return c.PromoteMember(7, 0, 9, "ADM") },
		"SetMemberTags": func() (map[string]interface{}, error) { return c.SetMemberTags(7, 9, []string{"a"}, "ADM") },
		"SetNetworkPolicy": func() (map[string]interface{}, error) {
			return c.SetNetworkPolicy(7, map[string]interface{}{"max_members": 5}, "ADM")
		},
		"SetExprPolicy": func() (map[string]interface{}, error) { return c.SetExprPolicy(7, json.RawMessage(`{}`), "ADM") },
	}
	for name, call := range calls {
		resp, err := call()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		echo := assertEcho(t, resp)
		if _, ok := echo["signature"]; ok {
			t.Errorf("%s: signed without a node_id", name)
		}
		if got, _ := echo["admin_token"].(string); got != "ADM" {
			t.Errorf("%s: admin_token %q", name, got)
		}
	}
}

// With a node id but no signer the request is sent unsigned (the registry
// decides); with both a signer and an admin token, both are sent, so a
// token holder whose node has no role is still authorized.
func TestNetworkRoleSignerAbsentAndTokenKept(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)

	resp, err := c.KickMember(7, 5, 9, "")
	if err != nil {
		t.Fatalf("kick: %v", err)
	}
	if _, ok := assertEcho(t, resp)["signature"]; ok {
		t.Fatal("signature present with no signer configured")
	}

	c.SetSigner(func(ch string) string { return "SIG:" + ch })
	resp, err = c.KickMember(7, 5, 9, "ADM")
	if err != nil {
		t.Fatalf("kick: %v", err)
	}
	echo := assertEcho(t, resp)
	if got, _ := echo["signature"].(string); got != "SIG:kick_member:5:7:9" {
		t.Fatalf("signature: %q", got)
	}
	if got, _ := echo["admin_token"].(string); got != "ADM" {
		t.Fatalf("admin_token dropped: %q", got)
	}
}
