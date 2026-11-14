// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package egressfilter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// SelectNetwork reports whether a Docker network belongs to noomesh, by
// ownership, never by a name prefix (offboard's rule, #1069: exact label or the
// cluster network's exact name). It is the cluster network (noo-cluster or
// $NOO_CLUSTER_NETWORK), or a network the node agent created (label
// noo.managed-by: the cluster network on a node, add-on workload networks),
// or one of the running stack's compose networks (its project label equals
// cfg.ComposeProject, which is $NOO_COMPOSE_PROJECT or else measured from the
// network noo-gateway is attached to; empty = no compose match at all).
// Another tool's network named noo-something (a lab, another project) is not
// noomesh's and is never filtered.
func SelectNetwork(name string, labels map[string]string, cfg Config) bool {
	switch {
	case name == "noo-cluster":
		return true
	case cfg.ClusterNetwork != "" && name == cfg.ClusterNetwork:
		return true
	case labels["noo.managed-by"] != "":
		return true
	case cfg.ComposeProject != "" && labels["com.docker.compose.project"] == cfg.ComposeProject:
		return true
	}
	return false
}

// stackProject is the compose project of the running noomesh stack: the
// project label of a compose network one of the stack's own services
// (noo-gateway, noo-worker, ... the egress-class names) is attached to. ""
// when none runs here (a node: its networks are recognised by noo.managed-by).
func stackProject(nets []inspectNet) string {
	stack := map[string]bool{}
	for _, n := range EgressClassContainers {
		stack[n] = true
	}
	for _, n := range nets {
		p := n.Labels["com.docker.compose.project"]
		if p == "" {
			continue
		}
		for _, c := range n.Containers {
			if stack[c.Name] {
				return p
			}
		}
	}
	return ""
}

type inspectNet struct {
	Name     string            `json:"Name"`
	Internal bool              `json:"Internal"`
	Labels   map[string]string `json:"Labels"`
	IPAM     struct {
		Config []struct {
			Subnet  string `json:"Subnet"`
			Gateway string `json:"Gateway"`
		} `json:"Config"`
	} `json:"IPAM"`
	Containers map[string]struct {
		Name        string `json:"Name"`
		IPv4Address string `json:"IPv4Address"`
		IPv6Address string `json:"IPv6Address"`
	} `json:"Containers"`
}

// CollectNetworks measures the noomesh Docker networks. A failure is returned
// as an error, never as an empty list: "no networks" and "could not look" are
// different statements.
func CollectNetworks(ctx context.Context, r Runner, cfg Config) ([]Network, error) {
	rc, out := r.Capture(ctx, "", "docker", "network", "ls", "--format=json")
	if rc != 0 {
		return nil, fmt.Errorf("docker network ls failed (rc %d)", rc)
	}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var row struct{ Name string }
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			return nil, fmt.Errorf("docker network ls output not understood: %v", err)
		}
		if row.Name != "" {
			names = append(names, row.Name)
		}
	}
	if len(names) == 0 {
		return nil, nil
	}
	args := append([]string{"network", "inspect"}, names...)
	rc, out = r.Capture(ctx, "", "docker", args...)
	if rc != 0 {
		return nil, fmt.Errorf("docker network inspect failed (rc %d)", rc)
	}
	var nets []inspectNet
	if err := json.Unmarshal([]byte(out), &nets); err != nil {
		return nil, fmt.Errorf("docker network inspect output not understood: %v", err)
	}
	if cfg.ComposeProject == "" {
		cfg.ComposeProject = stackProject(nets)
	}
	var res []Network
	for _, n := range nets {
		if !SelectNetwork(n.Name, n.Labels, cfg) {
			continue
		}
		net := Network{Name: n.Name, Internal: n.Internal}
		for _, c := range n.IPAM.Config {
			p, err := netip.ParsePrefix(c.Subnet)
			if err != nil {
				continue
			}
			p = p.Masked()
			if p.Addr().Is4() {
				net.Subnets4 = append(net.Subnets4, p.String())
			} else {
				net.Subnets6 = append(net.Subnets6, p.String())
			}
			if c.Gateway != "" {
				net.Gateways = append(net.Gateways, c.Gateway)
			}
		}
		for _, c := range n.Containers {
			a := Attached{Name: c.Name}
			if p, err := netip.ParsePrefix(c.IPv4Address); err == nil {
				a.IPv4 = append(a.IPv4, p.Addr().String())
			}
			if p, err := netip.ParsePrefix(c.IPv6Address); err == nil {
				a.IPv6 = append(a.IPv6, p.Addr().String())
			}
			net.Containers = append(net.Containers, a)
		}
		sort.Slice(net.Containers, func(i, j int) bool { return net.Containers[i].Name < net.Containers[j].Name })
		res = append(res, net)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Name < res[j].Name })
	return res, nil
}

// IsEgressClass reports whether a container name is on the egress-class list.
func IsEgressClass(name string) bool {
	for _, n := range EgressClassContainers {
		if n == name {
			return true
		}
	}
	return false
}

// ContainersOf folds the per-network attachments into one entry per container.
func ContainersOf(nets []Network) []Container {
	by := map[string]*Container{}
	for _, n := range nets {
		for _, a := range n.Containers {
			c := by[a.Name]
			if c == nil {
				c = &Container{Name: a.Name, EgressClass: IsEgressClass(a.Name)}
				by[a.Name] = c
			}
			c.IPv4 = addUnique(c.IPv4, a.IPv4...)
			c.IPv6 = addUnique(c.IPv6, a.IPv6...)
		}
	}
	out := make([]Container, 0, len(by))
	for _, c := range by {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func addUnique(dst []string, v ...string) []string {
	for _, s := range v {
		found := false
		for _, d := range dst {
			if d == s {
				found = true
			}
		}
		if !found {
			dst = append(dst, s)
		}
	}
	sort.Strings(dst)
	return dst
}

// BuildPlan measures and renders. It never returns a partial result as a
// complete one: whatever could not be measured is in Unknown, and the verdicts
// that depend on it say "unknown" instead of guessing.
func BuildPlan(ctx context.Context, r Runner, cfg Config) *Plan {
	p := &Plan{}
	engineOK := detectEngine(ctx, r, p)

	if engineOK {
		nets, err := CollectNetworks(ctx, r, cfg)
		if err != nil {
			p.Unknown = append(p.Unknown, "docker networks: "+err.Error())
		} else {
			p.Networks = nets
			p.Containers = ContainersOf(nets)
			if len(p.Containers) == 0 {
				p.NotApplicable = append(p.NotApplicable, "no noomesh containers on this node")
			}
		}
	}
	detectFirewall(ctx, r, p)

	if len(p.NotApplicable) == 0 && len(p.Networks) > 0 {
		p.Rules = Render(p)
	}
	return p
}

func detectEngine(ctx context.Context, r Runner, p *Plan) bool {
	rc, out := r.Capture(ctx, "", "docker", "info", "--format=json")
	if rc != 0 {
		why := fmt.Sprintf("docker info failed (rc %d)", rc)
		if rc == 127 {
			why = "docker is not installed or not on PATH"
		}
		p.Unknown = append(p.Unknown, why+"; networks and containers were not measured")
		return false
	}
	var info struct {
		OperatingSystem string
		Name            string
		SecurityOptions []string
	}
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		p.Unknown = append(p.Unknown, "docker info output not understood: "+err.Error())
		return false
	}
	d := &p.Detection
	d.EngineOS = info.OperatingSystem
	for _, o := range info.SecurityOptions {
		if strings.Contains(o, "rootless") {
			d.EngineRootless = true
		}
	}
	if strings.Contains(info.OperatingSystem, "Docker Desktop") || info.Name == "docker-desktop" {
		d.EngineDesktop = true
		p.NotApplicable = append(p.NotApplicable, "Docker Desktop; no filter can be applied here")
	}
	if d.EngineRootless {
		p.NotApplicable = append(p.NotApplicable, "rootless Docker; no filter can be applied here")
	}
	return true
}

// ruleLines pulls the "-P FORWARD X" policy and the DOCKER-USER chain state
// out of an `iptables -S` listing.
func ruleLines(listing string) (policy, chain string, other []string, jump bool) {
	chain = "absent"
	policy = "unknown"
	for _, l := range strings.Split(listing, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "-P FORWARD "):
			policy = strings.TrimPrefix(l, "-P FORWARD ")
		case l == "-N DOCKER-USER":
			chain = "present"
		case strings.HasPrefix(l, "-A DOCKER-USER "):
			chain = "present"
			switch strings.TrimPrefix(l, "-A DOCKER-USER ") {
			case "-j RETURN":
			case "-j " + Chain:
				jump = true
			default:
				other = append(other, l)
			}
		}
	}
	return
}

func detectFirewall(ctx context.Context, r Runner, p *Plan) {
	d := &p.Detection
	d.DockerUserV4, d.DockerUserV6 = "unknown", "unknown"
	d.Backend = "undetermined"

	flavour := ""
	if rc, out := r.Capture(ctx, "", "iptables", "-V"); rc == 0 {
		switch {
		case strings.Contains(out, "nf_tables"):
			flavour = "iptables-nft"
		case strings.Contains(out, "legacy"):
			flavour = "iptables-legacy"
		}
	} else if rc == 127 {
		d.DockerUserV4 = "absent"
		p.Unknown = append(p.Unknown, "iptables is not installed")
	}
	if rc, out := r.Capture(ctx, "", "iptables", "-S"); rc == 0 {
		d.ForwardPolicy, d.DockerUserV4, d.OtherRulesV4, d.JumpPresentV4 = ruleLines(out)
	} else if rc != 127 {
		p.Unknown = append(p.Unknown, fmt.Sprintf("iptables -S failed (rc %d; needs root): DOCKER-USER state unknown", rc))
	}
	if rc, out := r.Capture(ctx, "", "ip6tables", "-S"); rc == 0 {
		_, d.DockerUserV6, d.OtherRulesV6, d.JumpPresentV6 = ruleLines(out)
	} else if rc != 127 {
		p.Unknown = append(p.Unknown, fmt.Sprintf("ip6tables -S failed (rc %d; needs root): DOCKER-USER state unknown", rc))
	}

	nftDocker := false
	nftOK := false
	if rc, out := r.Capture(ctx, "", "nft", "list", "ruleset"); rc == 0 {
		nftOK = true
		for _, l := range strings.Split(out, "\n") {
			f := strings.Fields(l)
			if len(f) >= 3 && f[0] == "table" && strings.Contains(f[2], "docker") {
				nftDocker = true
			}
		}
	} else if rc != 127 {
		p.Unknown = append(p.Unknown, fmt.Sprintf("nft list ruleset failed (rc %d; needs root)", rc))
	}

	switch {
	case d.DockerUserV4 == "present" || d.DockerUserV6 == "present":
		d.Backend = flavour
		if d.Backend == "" {
			d.Backend = "undetermined"
		}
	case d.DockerUserV4 == "absent" && nftOK && nftDocker:
		d.Backend = "nftables"
	}
}
