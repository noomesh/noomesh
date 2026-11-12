// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package egressfilter

import (
	"context"
	"strings"
	"testing"
)

const goldenV4 = `*filter
:NOO-EGRESS - [0:0]
-F NOO-EGRESS
-A NOO-EGRESS -s 172.19.0.9/32 -m comment --comment "noomesh: egress class noo-browser" -j RETURN
-A NOO-EGRESS -s 172.19.0.5/32 -m comment --comment "noomesh: egress class noo-gateway" -j RETURN
-A NOO-EGRESS -s 172.20.0.3/32 -m comment --comment "noomesh: egress class noo-worker" -j RETURN
-A NOO-EGRESS -d 10.0.0.0/8 -j RETURN
-A NOO-EGRESS -d 172.16.0.0/12 -j RETURN
-A NOO-EGRESS -d 192.168.0.0/16 -j RETURN
-A NOO-EGRESS -d 169.254.0.0/16 -j RETURN
-A NOO-EGRESS -d 100.64.0.0/10 -j RETURN
-A NOO-EGRESS -d 127.0.0.0/8 -j RETURN
-A NOO-EGRESS -d 224.0.0.0/4 -j RETURN
-A NOO-EGRESS -s 172.19.0.0/16 -m comment --comment "noomesh: noo-cluster" -j DROP
-A NOO-EGRESS -s 172.21.0.0/24 -m comment --comment "noomesh: noo-egress-test" -j DROP
-A NOO-EGRESS -s 172.20.0.0/16 -m comment --comment "noomesh: pai-assistant_default" -j DROP
-A NOO-EGRESS -j RETURN
COMMIT
`

const goldenV6 = `*filter
:NOO-EGRESS - [0:0]
-F NOO-EGRESS
-A NOO-EGRESS -s fd00:19::5/128 -m comment --comment "noomesh: egress class noo-gateway" -j RETURN
-A NOO-EGRESS -d ::1/128 -j RETURN
-A NOO-EGRESS -d fe80::/10 -j RETURN
-A NOO-EGRESS -d fc00::/7 -j RETURN
-A NOO-EGRESS -d ff00::/8 -j RETURN
-A NOO-EGRESS -s fd00:19::/64 -m comment --comment "noomesh: noo-cluster" -j DROP
-A NOO-EGRESS -j RETURN
COMMIT
`

const goldenNFT = `add table inet noomesh
delete table inet noomesh
table inet noomesh {
	chain egress {
		type filter hook forward priority filter - 1; policy accept;
		ip saddr 172.19.0.9 return comment "noomesh: egress class noo-browser"
		ip saddr 172.19.0.5 return comment "noomesh: egress class noo-gateway"
		ip6 saddr fd00:19::5 return comment "noomesh: egress class noo-gateway"
		ip saddr 172.20.0.3 return comment "noomesh: egress class noo-worker"
		ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10, 127.0.0.0/8, 224.0.0.0/4 } return
		ip6 daddr { ::1/128, fe80::/10, fc00::/7, ff00::/8 } return
		ip saddr 172.19.0.0/16 drop comment "noomesh: noo-cluster"
		ip6 saddr fd00:19::/64 drop comment "noomesh: noo-cluster"
		ip saddr 172.21.0.0/24 drop comment "noomesh: noo-egress-test"
		ip saddr 172.20.0.0/16 drop comment "noomesh: pai-assistant_default"
		return
	}
}
`

func samplePlan(t *testing.T, mut func(map[string]fakeAns)) *Plan {
	m := baseTable()
	if mut != nil {
		mut(m)
	}
	return BuildPlan(context.Background(), newFake(t, m), Config{})
}

func TestRenderGoldenIptables(t *testing.T) {
	p := samplePlan(t, nil)
	if p.Rules.RestoreV4 != goldenV4 {
		t.Errorf("v4 differs:\n%s", p.Rules.RestoreV4)
	}
	if p.Rules.RestoreV6 != goldenV6 {
		t.Errorf("v6 differs:\n%s", p.Rules.RestoreV6)
	}
	if want := "iptables -C DOCKER-USER -j NOO-EGRESS 2>/dev/null || iptables -I DOCKER-USER 1 -j NOO-EGRESS"; p.Rules.JumpV4 != want {
		t.Errorf("jump v4 %q", p.Rules.JumpV4)
	}
	if want := "ip6tables -C DOCKER-USER -j NOO-EGRESS 2>/dev/null || ip6tables -I DOCKER-USER 1 -j NOO-EGRESS"; p.Rules.JumpV6 != want {
		t.Errorf("jump v6 %q", p.Rules.JumpV6)
	}
	if p.Rules.NFT != "" {
		t.Error("nft equivalent must not be rendered when Docker uses iptables")
	}
}

func TestRenderGoldenNFT(t *testing.T) {
	p := samplePlan(t, func(m map[string]fakeAns) {
		m["iptables -S"] = fakeAns{0, "-P FORWARD ACCEPT"}
		m["ip6tables -S"] = fakeAns{0, "-P FORWARD ACCEPT"}
		m["nft list ruleset"] = fakeAns{0, "table ip docker-bridges {\n}\n"}
	})
	if p.Rules.NFT != goldenNFT {
		t.Errorf("nft differs:\n%s", p.Rules.NFT)
	}
}

// The structural promises, checked on the rendered text rather than the golden
// so they still hold if the golden is regenerated carelessly.
func TestRenderedRulesAreOnlyEverDropOrReturnOnOurChain(t *testing.T) {
	p := samplePlan(t, nil)
	for _, rules := range []string{p.Rules.RestoreV4, p.Rules.RestoreV6} {
		sawDrop := false
		lastEgressReturn, firstDrop := -1, -1
		for i, l := range strings.Split(strings.TrimSpace(rules), "\n") {
			if strings.Contains(strings.ToUpper(l), "ACCEPT") {
				t.Errorf("ACCEPT in %q", l)
			}
			switch {
			case l == "*filter", l == "COMMIT", l == ":NOO-EGRESS - [0:0]", l == "-F NOO-EGRESS":
			case strings.HasPrefix(l, "-A NOO-EGRESS "):
				if strings.HasSuffix(l, "-j DROP") {
					sawDrop = true
					if firstDrop < 0 {
						firstDrop = i
					}
				} else if !strings.HasSuffix(l, "-j RETURN") {
					t.Errorf("unexpected verdict %q", l)
				}
				if strings.Contains(l, "egress class") {
					lastEgressReturn = i
				}
				if strings.HasSuffix(l, "-j DROP") && !strings.Contains(l, `--comment "noomesh: `) {
					t.Errorf("DROP without a network comment: %q", l)
				}
			default:
				t.Errorf("rule outside NOO-EGRESS (or a policy/other chain change): %q", l)
			}
		}
		if !sawDrop {
			t.Error("no DROP rendered")
		}
		if lastEgressReturn > firstDrop {
			t.Error("an egress-class RETURN comes after a DROP")
		}
	}
	for _, j := range []string{p.Rules.JumpV4, p.Rules.JumpV6} {
		if strings.Count(j, "DOCKER-USER") != 2 || !strings.Contains(j, "-C DOCKER-USER") || strings.Contains(j, " -P ") {
			t.Errorf("jump must be a -C check then one -I on DOCKER-USER: %q", j)
		}
	}
}

func TestV6OmittedWhenNoV6Subnet(t *testing.T) {
	p := samplePlan(t, func(m map[string]fakeAns) {
		m["docker network inspect"] = fakeAns{0, `[{"Name":"noo-cluster","Labels":{},"IPAM":{"Config":[{"Subnet":"172.19.0.0/16"}]},"Containers":{"a":{"Name":"noo-gateway","IPv4Address":"172.19.0.5/16"}}}]`}
	})
	if p.Rules.RestoreV4 == "" || p.Rules.RestoreV6 != "" || p.Rules.JumpV6 != "" {
		t.Fatalf("%+v", p.Rules)
	}
	if !strings.Contains(strings.Join(p.Rules.Notes, "\n"), "No noomesh IPv6 subnet") {
		t.Error("the omission must be explained")
	}
}

func TestCommentIsSanitised(t *testing.T) {
	p := &Plan{Networks: []Network{{Name: "noo-x\" -j ACCEPT #", Subnets4: []string{"10.1.0.0/16"}}}}
	r, _ := renderIPTables(p, false)
	if strings.Contains(strings.ToUpper(r), "ACCEPT \"") || strings.Count(r, `"`) != 2 {
		t.Errorf("network name escaped its comment: %s", r)
	}
}
