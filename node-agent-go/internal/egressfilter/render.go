// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package egressfilter

import (
	"fmt"
	"regexp"
	"strings"
)

var unsafeComment = regexp.MustCompile(`[^A-Za-z0-9_.:/ -]`)

func comment(s string) string { return unsafeComment.ReplaceAllString(s, "_") }

// Render builds the rules the filter WOULD install. It is pure text: nothing
// here is executed. The iptables chain holds, in order: RETURN for each
// egress-class container address, RETURN for the private/local destinations,
// DROP per noomesh subnet, then RETURN. There is no ACCEPT, no rule on any
// other chain and no policy change.
func Render(p *Plan) RuleSet {
	var rs RuleSet
	d := p.Detection
	switch d.Backend {
	case "nftables":
		rs.Notes = append(rs.Notes, "Docker uses the nftables backend: the iptables rules below are not used here; the nft rules are the plan.")
		rs.NFT = renderNFT(p)
		return rs
	case "iptables-legacy", "iptables-nft":
		rs.Notes = append(rs.Notes, "Docker uses iptables ("+d.Backend+"): the nftables equivalent is not needed here.")
	default:
		rs.Notes = append(rs.Notes, "Firewall backend could not be determined (run as root to read it): both the iptables rules and the nftables equivalent are shown; only the one matching Docker's backend would be installed.")
		rs.NFT = renderNFT(p)
	}
	rs.RestoreV4, rs.JumpV4 = renderIPTables(p, false)
	rs.RestoreV6, rs.JumpV6 = renderIPTables(p, true)
	if rs.RestoreV6 == "" {
		rs.Notes = append(rs.Notes, "No noomesh IPv6 subnet: nothing would be installed through ip6tables.")
	}
	if d.DockerUserV4 == "absent" && d.Backend != "nftables" && d.Backend != "undetermined" {
		rs.Notes = append(rs.Notes, "iptables has no DOCKER-USER chain: Docker has not created it yet, the jump could not be added.")
	}
	return rs
}

func subnetsOf(n Network, v6 bool) []string {
	if v6 {
		return n.Subnets6
	}
	return n.Subnets4
}

func renderIPTables(p *Plan, v6 bool) (restore, jump string) {
	tool, private, host := "iptables", PrivateV4, "/32"
	if v6 {
		tool, private, host = "ip6tables", PrivateV6, "/128"
	}
	haveSubnet := false
	for _, n := range p.Networks {
		if len(subnetsOf(n, v6)) > 0 {
			haveSubnet = true
		}
	}
	if !haveSubnet {
		return "", ""
	}
	var b strings.Builder
	b.WriteString("*filter\n")
	fmt.Fprintf(&b, ":%s - [0:0]\n", Chain)
	// -F on our own chain only, so re-running the transaction replaces rather
	// than appends (iptables-restore --noflush would not flush it).
	fmt.Fprintf(&b, "-F %s\n", Chain)
	for _, c := range p.Containers {
		if !c.EgressClass {
			continue
		}
		addrs := c.IPv4
		if v6 {
			addrs = c.IPv6
		}
		for _, a := range addrs {
			fmt.Fprintf(&b, "-A %s -s %s%s -m comment --comment \"noomesh: egress class %s\" -j RETURN\n", Chain, a, host, comment(c.Name))
		}
	}
	for _, dst := range private {
		fmt.Fprintf(&b, "-A %s -d %s -j RETURN\n", Chain, dst)
	}
	for _, n := range p.Networks {
		for _, s := range subnetsOf(n, v6) {
			fmt.Fprintf(&b, "-A %s -s %s -m comment --comment \"noomesh: %s\" -j DROP\n", Chain, s, comment(n.Name))
		}
	}
	fmt.Fprintf(&b, "-A %s -j RETURN\n", Chain)
	b.WriteString("COMMIT\n")
	// The jump goes in at position 1: Docker's DOCKER-USER ends in an
	// unconditional RETURN, so an appended jump would never be reached.
	jump = fmt.Sprintf("%s -C DOCKER-USER -j %s 2>/dev/null || %s -I DOCKER-USER 1 -j %s", tool, Chain, tool, Chain)
	return b.String(), jump
}

func renderNFT(p *Plan) string {
	var b strings.Builder
	b.WriteString("add table inet noomesh\n")
	b.WriteString("delete table inet noomesh\n")
	b.WriteString("table inet noomesh {\n")
	b.WriteString("\tchain egress {\n")
	b.WriteString("\t\ttype filter hook forward priority filter - 1; policy accept;\n")
	for _, c := range p.Containers {
		if !c.EgressClass {
			continue
		}
		for _, a := range c.IPv4 {
			fmt.Fprintf(&b, "\t\tip saddr %s return comment \"noomesh: egress class %s\"\n", a, comment(c.Name))
		}
		for _, a := range c.IPv6 {
			fmt.Fprintf(&b, "\t\tip6 saddr %s return comment \"noomesh: egress class %s\"\n", a, comment(c.Name))
		}
	}
	fmt.Fprintf(&b, "\t\tip daddr { %s } return\n", strings.Join(PrivateV4, ", "))
	fmt.Fprintf(&b, "\t\tip6 daddr { %s } return\n", strings.Join(PrivateV6, ", "))
	for _, n := range p.Networks {
		for _, s := range n.Subnets4 {
			fmt.Fprintf(&b, "\t\tip saddr %s drop comment \"noomesh: %s\"\n", s, comment(n.Name))
		}
		for _, s := range n.Subnets6 {
			fmt.Fprintf(&b, "\t\tip6 saddr %s drop comment \"noomesh: %s\"\n", s, comment(n.Name))
		}
	}
	b.WriteString("\t\treturn\n")
	b.WriteString("\t}\n}\n")
	return b.String()
}
