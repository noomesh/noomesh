// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package egressfilter is the READ-ONLY plan mode of the host egress filter:
// `noo-hostd egress-filter plan`. It measures this node's Docker networks and
// firewall, prints the rule set a later step WOULD install, and (with
// --observe) watches the connection tracker to say which flows that rule set
// WOULD have dropped.
//
// It changes nothing on the host except net.netfilter.nf_conntrack_acct while
// observing, and that is restored on every exit path. Every external command
// goes through the guard in guard.go, which refuses any firewall write verb
// before the command runs. Inputs are only the node's own measured state
// (docker, the firewall, the connection tracker, two environment variables
// that name the stack); nothing comes from a caller or a manifest.
package egressfilter

import (
	"context"
	"io"
)

// Chain is the one chain the filter would own.
const Chain = "NOO-EGRESS"

// EgressClassContainers are the containers allowed to reach the internet
// because they do work the user asked for. One list; rendering, observing and
// the report all read it.
var EgressClassContainers = []string{
	"noo-gateway", "noo-worker", "noo-worker-extra", "noo-trellion", "noo-browser",
}

// PrivateV4 and PrivateV6 are the destinations that never leave the machine or
// its LAN: the filter RETURNs them and the observer ignores them.
var PrivateV4 = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
	"100.64.0.0/10", "127.0.0.0/8", "224.0.0.0/4",
}

var PrivateV6 = []string{"::1/128", "fe80::/10", "fc00::/7", "ff00::/8"}

// Runner is the command seam. hostd.Runner satisfies it (it is a subset), so
// production passes hostd.ExecRunner and tests pass a fake that records argv.
type Runner interface {
	Capture(ctx context.Context, dir string, name string, args ...string) (rc int, stdout string)
}

// Streamer starts a long-lived child and hands back its stdout and a wait
// function. The returned stderr func yields what the child printed to stderr
// (for the error message when it dies early).
type Streamer func(ctx context.Context, name string, args ...string) (stdout io.ReadCloser, wait func() error, stderr func() string, err error)

// Sysctl is the one writable thing: nf_conntrack_acct.
type Sysctl interface {
	Get() (string, error)
	Set(v string) error
}

// Config names the stack. Both values are read from this node's environment by
// the caller; neither comes from a manifest.
type Config struct {
	ClusterNetwork string // $NOO_CLUSTER_NETWORK
	ComposeProject string // $NOO_COMPOSE_PROJECT, else measured from the network noo-gateway is on
}

// Attached is a container on a network.
type Attached struct {
	Name string   `json:"name"`
	IPv4 []string `json:"ipv4,omitempty"`
	IPv6 []string `json:"ipv6,omitempty"`
}

// Network is a noomesh Docker network as measured.
type Network struct {
	Name       string     `json:"name"`
	Subnets4   []string   `json:"subnets_v4,omitempty"`
	Subnets6   []string   `json:"subnets_v6,omitempty"`
	Gateways   []string   `json:"gateways,omitempty"`
	Internal   bool       `json:"internal"`
	Containers []Attached `json:"containers,omitempty"`
}

// Container is one noomesh container with every address it holds on a noomesh
// network.
type Container struct {
	Name        string   `json:"name"`
	IPv4        []string `json:"ipv4,omitempty"`
	IPv6        []string `json:"ipv6,omitempty"`
	EgressClass bool     `json:"egress_class"`
}

// Detection is what the firewall and the engine look like.
type Detection struct {
	Backend        string   `json:"backend"`        // iptables-legacy | iptables-nft | nftables | undetermined
	DockerUserV4   string   `json:"docker_user_v4"` // present | absent | unknown
	DockerUserV6   string   `json:"docker_user_v6"` // present | absent | unknown
	ForwardPolicy  string   `json:"forward_policy"` // information only
	OtherRulesV4   []string `json:"other_rules_v4"` // rules already in DOCKER-USER, never touched
	OtherRulesV6   []string `json:"other_rules_v6"`
	JumpPresentV4  bool     `json:"jump_present_v4"`
	JumpPresentV6  bool     `json:"jump_present_v6"`
	EngineOS       string   `json:"engine_os"`
	EngineRootless bool     `json:"engine_rootless"`
	EngineDesktop  bool     `json:"engine_desktop"`
}

// RuleSet is the rendered output. Empty strings mean "not rendered"; the
// matching *Note says why.
type RuleSet struct {
	RestoreV4 string   `json:"iptables_restore_v4,omitempty"`
	RestoreV6 string   `json:"ip6tables_restore_v6,omitempty"`
	JumpV4    string   `json:"jump_v4,omitempty"`
	JumpV6    string   `json:"jump_v6,omitempty"`
	NFT       string   `json:"nft,omitempty"`
	Notes     []string `json:"notes,omitempty"`
}

// Plan is everything the read-only half measured and would install.
type Plan struct {
	Networks      []Network   `json:"networks"`
	Containers    []Container `json:"containers"`
	Detection     Detection   `json:"detection"`
	NotApplicable []string    `json:"not_applicable,omitempty"`
	Unknown       []string    `json:"unknown,omitempty"` // things that could not be measured
	Rules         RuleSet     `json:"rules"`
}
