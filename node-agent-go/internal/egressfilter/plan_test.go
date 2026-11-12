// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package egressfilter

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

const lsJSON = `{"Name":"bridge","Driver":"bridge"}
{"Name":"noo-cluster","Driver":"bridge"}
{"Name":"pai-assistant_default","Driver":"bridge"}
{"Name":"custom-net","Driver":"bridge"}
{"Name":"noo-egress-test","Driver":"bridge"}
{"Name":"other-proj","Driver":"bridge"}
{"Name":"envnet","Driver":"bridge"}`

const inspectJSON = `[
 {"Name":"bridge","Internal":false,"Labels":{},"IPAM":{"Config":[{"Subnet":"172.17.0.0/16","Gateway":"172.17.0.1"}]},
  "Containers":{"x":{"Name":"random-app","IPv4Address":"172.17.0.2/16","IPv6Address":""}}},
 {"Name":"noo-cluster","Internal":false,"Labels":{},"IPAM":{"Config":[{"Subnet":"172.19.0.0/16","Gateway":"172.19.0.1"},{"Subnet":"fd00:19::/64","Gateway":"fd00:19::1"}]},
  "Containers":{
   "a":{"Name":"noo-gateway","IPv4Address":"172.19.0.5/16","IPv6Address":"fd00:19::5/64"},
   "b":{"Name":"noo-postgres","IPv4Address":"172.19.0.2/16","IPv6Address":"fd00:19::2/64"},
   "c":{"Name":"noo-browser","IPv4Address":"172.19.0.9/16","IPv6Address":""}}},
 {"Name":"pai-assistant_default","Internal":false,"Labels":{"com.docker.compose.project":"pai-assistant"},"IPAM":{"Config":[{"Subnet":"172.20.0.0/16","Gateway":"172.20.0.1"}]},
  "Containers":{"d":{"Name":"noo-worker","IPv4Address":"172.20.0.3/16","IPv6Address":""}}},
 {"Name":"custom-net","Internal":false,"Labels":{},"IPAM":{"Config":[{"Subnet":"172.30.0.0/16"}]},"Containers":{}},
 {"Name":"noo-egress-test","Internal":true,"Labels":{"noo.managed-by":"agent"},"IPAM":{"Config":[{"Subnet":"172.21.0.0/24"}]},"Containers":{}},
 {"Name":"other-proj","Internal":false,"Labels":{"com.docker.compose.project":"someone-else"},"IPAM":{"Config":[{"Subnet":"172.31.0.0/16"}]},"Containers":{}},
 {"Name":"envnet","Internal":false,"Labels":{},"IPAM":{"Config":[{"Subnet":"172.22.0.0/16"}]},"Containers":{}}
]`

const infoPlain = `{"OperatingSystem":"Ubuntu 24.04 LTS","Name":"awolf","SecurityOptions":["name=apparmor","name=seccomp,profile=builtin"]}`

const iptablesLegacySave = `-P INPUT ACCEPT
-P FORWARD DROP
-P OUTPUT ACCEPT
-N DOCKER-USER
-A FORWARD -j DOCKER-USER
-A DOCKER-USER -s 203.0.113.0/24 -j DROP
-A DOCKER-USER -j RETURN`

func baseTable() map[string]fakeAns {
	return map[string]fakeAns{
		"docker info --format=json":       {0, infoPlain},
		"docker network ls --format=json": {0, lsJSON},
		"docker network inspect":          {0, inspectJSON},
		"iptables -V":                     {0, "iptables v1.8.10 (legacy)"},
		"iptables -S":                     {0, iptablesLegacySave},
		"ip6tables -S":                    {0, "-P FORWARD DROP\n-N DOCKER-USER\n-A DOCKER-USER -j RETURN"},
		"nft list ruleset":                {127, ""},
	}
}

func TestSelectNetwork(t *testing.T) {
	cfg := Config{ClusterNetwork: "envnet"}
	for _, tc := range []struct {
		name   string
		labels map[string]string
		cfg    Config
		want   bool
	}{
		{"noo-cluster", nil, Config{}, true},
		{"envnet", nil, cfg, true},
		{"envnet", nil, Config{}, false},
		{"anything", map[string]string{"com.docker.compose.project": "pai-assistant"}, Config{}, false},
		{"anything", map[string]string{"com.docker.compose.project": "mine"}, Config{ComposeProject: "mine"}, true},
		{"anything", map[string]string{"com.docker.compose.project": "mine"}, Config{}, false},
		// Ownership, never a name prefix: awolf runs noo-lab (no labels) and
		// noo-google-test_* (another compose project), neither noomesh's.
		{"noo-whatever", nil, Config{}, false},
		{"noo-lab", map[string]string{}, Config{ComposeProject: "noomesh"}, false},
		{"noo-google-test_outbound", map[string]string{"com.docker.compose.project": "noo-google-test"}, Config{ComposeProject: "noomesh"}, false},
		{"noo-wl-x-worker", map[string]string{"noo.managed-by": "agent", "noo.addon": "x"}, Config{}, true},
		{"noo-cluster-on-a-node", map[string]string{"noo.managed-by": "node-agent-go"}, Config{}, true},
		{"bridge", nil, cfg, false},
		{"custom-net", map[string]string{"com.docker.compose.project": "other"}, cfg, false},
		{"nooo", nil, Config{}, false},
	} {
		if got := SelectNetwork(tc.name, tc.labels, tc.cfg); got != tc.want {
			t.Errorf("SelectNetwork(%q,%v,%+v)=%v want %v", tc.name, tc.labels, tc.cfg, got, tc.want)
		}
	}
}

func TestCollectNetworksSelectsOnlyNoomesh(t *testing.T) {
	f := newFake(t, baseTable())
	nets, err := CollectNetworks(context.Background(), f, Config{ClusterNetwork: "envnet"})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, n := range nets {
		names = append(names, n.Name)
	}
	got := strings.Join(names, ",")
	if got != "envnet,noo-cluster,noo-egress-test,pai-assistant_default" {
		t.Fatalf("selected %s", got)
	}
	for _, n := range nets {
		if n.Name == "noo-cluster" {
			if len(n.Subnets4) != 1 || n.Subnets4[0] != "172.19.0.0/16" || len(n.Subnets6) != 1 || n.Subnets6[0] != "fd00:19::/64" {
				t.Errorf("subnets %+v", n)
			}
			if len(n.Containers) != 3 || n.Containers[0].Name != "noo-browser" {
				t.Errorf("containers %+v", n.Containers)
			}
		}
		if n.Name == "noo-egress-test" && !n.Internal {
			t.Error("internal flag lost")
		}
	}
}

func TestCollectNetworksFailureIsNotEmpty(t *testing.T) {
	tab := baseTable()
	tab["docker network ls --format=json"] = fakeAns{1, ""}
	if nets, err := CollectNetworks(context.Background(), newFake(t, tab), Config{}); err == nil || nets != nil {
		t.Fatalf("ls failure must be an error, got %v %v", nets, err)
	}
	tab = baseTable()
	tab["docker network inspect"] = fakeAns{1, ""}
	if _, err := CollectNetworks(context.Background(), newFake(t, tab), Config{}); err == nil {
		t.Fatal("inspect failure must be an error")
	}
	tab = baseTable()
	tab["docker network inspect"] = fakeAns{0, "not json"}
	if _, err := CollectNetworks(context.Background(), newFake(t, tab), Config{}); err == nil {
		t.Fatal("garbage inspect must be an error")
	}
}

func TestDetection(t *testing.T) {
	nftDocker := "table ip docker-bridges {\n}\ntable ip6 docker-bridges {\n}\n"
	cases := []struct {
		name      string
		mut       func(m map[string]fakeAns)
		backend   string
		wantNA    string // substring of NotApplicable, "" = none
		wantUnk   string // substring of Unknown, "" = none
		wantRules bool
		other     int
		policy    string
	}{
		{"iptables-legacy", func(m map[string]fakeAns) {}, "iptables-legacy", "", "", true, 1, "DROP"},
		{"iptables-nft", func(m map[string]fakeAns) {
			m["iptables -V"] = fakeAns{0, "iptables v1.8.10 (nf_tables)"}
		}, "iptables-nft", "", "", true, 1, "DROP"},
		{"nftables backend", func(m map[string]fakeAns) {
			m["iptables -S"] = fakeAns{0, "-P FORWARD ACCEPT"}
			m["ip6tables -S"] = fakeAns{0, "-P FORWARD ACCEPT"}
			m["nft list ruleset"] = fakeAns{0, nftDocker}
		}, "nftables", "", "", true, 0, "ACCEPT"},
		{"nftables backend, no iptables binary", func(m map[string]fakeAns) {
			delete(m, "iptables -V")
			delete(m, "iptables -S")
			delete(m, "ip6tables -S")
			m["nft list ruleset"] = fakeAns{0, nftDocker}
		}, "nftables", "", "iptables is not installed", true, 0, "unknown"},
		{"Docker Desktop", func(m map[string]fakeAns) {
			m["docker info --format=json"] = fakeAns{0, `{"OperatingSystem":"Docker Desktop","Name":"docker-desktop","SecurityOptions":[]}`}
		}, "iptables-legacy", "Docker Desktop; no filter can be applied here", "", false, 1, "DROP"},
		{"rootless", func(m map[string]fakeAns) {
			m["docker info --format=json"] = fakeAns{0, `{"OperatingSystem":"Ubuntu","SecurityOptions":["name=seccomp","name=rootless"]}`}
		}, "iptables-legacy", "rootless Docker; no filter can be applied here", "", false, 1, "DROP"},
		{"no containers", func(m map[string]fakeAns) {
			m["docker network inspect"] = fakeAns{0, `[{"Name":"noo-cluster","Labels":{},"IPAM":{"Config":[{"Subnet":"172.19.0.0/16"}]},"Containers":{}}]`}
		}, "iptables-legacy", "no noomesh containers on this node", "", false, 1, "DROP"},
		{"non-root cannot read firewall", func(m map[string]fakeAns) {
			m["iptables -S"] = fakeAns{1, ""}
			m["ip6tables -S"] = fakeAns{1, ""}
			m["nft list ruleset"] = fakeAns{1, ""}
		}, "undetermined", "", "needs root", true, 0, "unknown"},
		{"docker absent", func(m map[string]fakeAns) {
			delete(m, "docker info --format=json")
		}, "iptables-legacy", "", "docker is not installed", false, 1, "DROP"},
		{"docker info fails", func(m map[string]fakeAns) {
			m["docker info --format=json"] = fakeAns{1, ""}
		}, "iptables-legacy", "", "docker info failed", false, 1, "DROP"},
		{"network list fails", func(m map[string]fakeAns) {
			m["docker network ls --format=json"] = fakeAns{1, ""}
		}, "iptables-legacy", "", "docker networks", false, 1, "DROP"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := baseTable()
			tc.mut(m)
			p := BuildPlan(context.Background(), newFake(t, m), Config{})
			if p.Detection.Backend != tc.backend {
				t.Errorf("backend %q want %q", p.Detection.Backend, tc.backend)
			}
			if got := strings.Join(p.NotApplicable, "|"); (tc.wantNA == "") != (got == "") || !strings.Contains(got, tc.wantNA) {
				t.Errorf("not applicable %q want %q", got, tc.wantNA)
			}
			if got := strings.Join(p.Unknown, "|"); (tc.wantUnk == "") != (got == "") || !strings.Contains(got, tc.wantUnk) {
				t.Errorf("unknown %q want %q", got, tc.wantUnk)
			}
			rendered := p.Rules.RestoreV4 != "" || p.Rules.NFT != ""
			if rendered != tc.wantRules {
				t.Errorf("rendered=%v want %v", rendered, tc.wantRules)
			}
			if len(p.Detection.OtherRulesV4) != tc.other {
				t.Errorf("other rules %v", p.Detection.OtherRulesV4)
			}
			if p.Detection.ForwardPolicy != tc.policy && tc.policy != "unknown" {
				t.Errorf("policy %q", p.Detection.ForwardPolicy)
			}
		})
	}
}

func TestNftBackendRendersNFTOnly(t *testing.T) {
	m := baseTable()
	m["iptables -S"] = fakeAns{0, "-P FORWARD ACCEPT"}
	m["ip6tables -S"] = fakeAns{0, "-P FORWARD ACCEPT"}
	m["nft list ruleset"] = fakeAns{0, "table ip docker-bridges {\n}\n"}
	p := BuildPlan(context.Background(), newFake(t, m), Config{})
	if p.Rules.RestoreV4 != "" || p.Rules.RestoreV6 != "" || p.Rules.NFT == "" {
		t.Fatalf("nftables backend must render nft only: %+v", p.Rules)
	}
}

func TestExistingJumpAndForeignRulesAreReportedNotTouched(t *testing.T) {
	m := baseTable()
	m["iptables -S"] = fakeAns{0, iptablesLegacySave + "\n-A DOCKER-USER -j NOO-EGRESS"}
	f := newFake(t, m)
	p := BuildPlan(context.Background(), f, Config{})
	if !p.Detection.JumpPresentV4 || len(p.Detection.OtherRulesV4) != 1 {
		t.Fatalf("%+v", p.Detection)
	}
}

func TestPlanCallsOnlyReadOnlyCommands(t *testing.T) {
	f := newFake(t, baseTable())
	BuildPlan(context.Background(), f, Config{})
	if len(f.calls) == 0 {
		t.Fatal("no calls recorded")
	}
	for _, c := range f.calls {
		fields := strings.Fields(c)
		if err := CheckReadOnly(fields[0], fields[1:]); err != nil {
			t.Errorf("plan made a call the guard refuses: %s: %v", c, err)
		}
	}
}

// The stack's project is measured: the compose label of a network noo-gateway
// is attached to; none on a node with no gateway.
func TestStackProjectIsMeasuredFromTheGatewaysNetwork(t *testing.T) {
	var gw, other inspectNet
	if err := json.Unmarshal([]byte(`{"Name":"noomesh_noo-db","Labels":{"com.docker.compose.project":"noomesh"},"Containers":{"a":{"Name":"noo-gateway"}}}`), &gw); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"Name":"noo-google-test_outbound","Labels":{"com.docker.compose.project":"noo-google-test"},"Containers":{"b":{"Name":"other"}}}`), &other); err != nil {
		t.Fatal(err)
	}
	if got := stackProject([]inspectNet{other, gw}); got != "noomesh" {
		t.Fatalf("got %q", got)
	}
	if got := stackProject([]inspectNet{other}); got != "" {
		t.Fatalf("no gateway: got %q", got)
	}
}
