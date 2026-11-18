// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"encoding/json"
	"testing"
)

// The gateway's desired-config carries `disk_reclaim`; an older gateway
// omits it, which must decode as "no policy" (nil), never as an enabled zero.
func TestDesiredConfigCarriesTheReclaimPolicy(t *testing.T) {
	var with desiredConfig
	if err := json.Unmarshal([]byte(`{"node":null,"placements":[],
		"disk_reclaim":{"enabled":true,"dry_run":false,"watermark":80,"cache_cap_bytes":25000000000}}`), &with); err != nil {
		t.Fatal(err)
	}
	p := with.DiskReclaim
	if p == nil || !p.Enabled || p.DryRun || p.Watermark != 80 || p.CacheCapBytes != 25000000000 {
		t.Fatalf("policy = %+v", p)
	}
	var without desiredConfig
	if err := json.Unmarshal([]byte(`{"node":null,"placements":[]}`), &without); err != nil {
		t.Fatal(err)
	}
	if without.DiskReclaim != nil {
		t.Fatalf("absent policy decoded as %+v", without.DiskReclaim)
	}
}

// desired-config's gateway_features reach the stop drain: present on a
// gateway that reads node_restarting, absent (nil, so never refused) on an
// older one.
func TestDesiredConfigCarriesTheGatewayFeatures(t *testing.T) {
	var with desiredConfig
	if err := json.Unmarshal([]byte(`{"node":null,"placements":[],"gateway_features":["node_restarting"]}`), &with); err != nil {
		t.Fatal(err)
	}
	if len(with.GatewayFeatures) != 1 || with.GatewayFeatures[0] != "node_restarting" {
		t.Fatalf("features = %v", with.GatewayFeatures)
	}
	var without desiredConfig
	if err := json.Unmarshal([]byte(`{"node":null,"placements":[]}`), &without); err != nil {
		t.Fatal(err)
	}
	if without.GatewayFeatures != nil {
		t.Fatalf("absent features decoded as %v", without.GatewayFeatures)
	}
}
