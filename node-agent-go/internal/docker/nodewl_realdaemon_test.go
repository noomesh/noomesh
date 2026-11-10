package docker

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"

	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
)

// TestRealDaemonAcceptsTheWorkloadCreateSpecs sends the provisioner's three
// create calls (network, door, worker) to a REAL Docker daemon and removes
// what it made. Everything else in this package fakes the daemon, and a fake
// accepts any option: on awolf (0.6.21) the first live create was refused
// with "invalid mount config for type tmpfs: invalid option: nosuid", which
// no unit test could have seen.
//
// Opt-in: the house rule is that tests never touch a real daemon, so this
// runs only with NOO_TEST_REAL_DOCKER=1 (the rehearsal's dockerd node sets it)
// and skips otherwise, saying why. It never pulls: it creates from an image
// already on the daemon, and it never starts anything, so no GPU is needed
// (a device request is checked at start, not at create).
func TestRealDaemonAcceptsTheWorkloadCreateSpecs(t *testing.T) {
	if os.Getenv("NOO_TEST_REAL_DOCKER") != "1" {
		t.Skip("set NOO_TEST_REAL_DOCKER=1 to create against a real Docker daemon (house rule: tests never touch one by default)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	dc, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Skipf("no docker client: %v", err)
	}
	if _, err := dc.Ping(ctx, client.PingOptions{}); err != nil {
		t.Skipf("no docker daemon answers: %v", err)
	}
	imgs, err := dc.ImageList(ctx, client.ImageListOptions{})
	if err != nil || len(imgs.Items) == 0 {
		t.Skipf("no local image to create from (this test never pulls): %v", err)
	}
	img := imgs.Items[0].ID

	// A real add-on worker's shape, under the rhaddon fixture: a plain tmpfs_mb, an
	// exec tmpfs_mb, a second plain tmpfs_mb, and a max_mb volume.
	e := entryWithScratch(t,
		nodewl.Scratch{Target: "/cache", TmpfsMB: i64(64)},
		nodewl.Scratch{Target: "/triton-cache", TmpfsMB: i64(512), Exec: true},
		nodewl.Scratch{Target: "/tmp", TmpfsMB: i64(256)},
		nodewl.Scratch{Target: "/spool", MaxMB: i64(128)},
	)
	dir := t.TempDir()
	set := filepath.Join(dir, "set")
	pki := filepath.Join(dir, "pki")
	for _, d := range []string{set, pki} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"ca.crt", "service.crt", "service.key"} {
		if err := os.WriteFile(filepath.Join(pki, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	specs, err := buildWorkloadSpecs(specInput{Entry: e, WorkerImage: img, DoorImage: img, AdmitCN: testAgentCN,
		CAPath: filepath.Join(pki, "ca.crt"), LeafCrt: filepath.Join(pki, "service.crt"), LeafKey: filepath.Join(pki, "service.key"),
		LeafPrint: "p", Sets: []setMount{{Source: set, Target: "/models/main"}}, GPUDevices: []string{"0"}})
	if err != nil {
		t.Fatal(err)
	}

	// Unique names, so a real node's objects are never touched. Only names
	// change: every mount, tmpfs and option is the spec as built.
	sfx := fmt.Sprintf("-realtest-%d", time.Now().UnixNano())
	netName := specs.Network + sfx
	specs.Door.Name += sfx
	specs.Worker.Name += sfx
	specs.Door.Host.NetworkMode = container.NetworkMode(netName)
	specs.Door.Net.EndpointsConfig = map[string]*network.EndpointSettings{netName: {}}
	specs.Worker.Host.NetworkMode = container.NetworkMode("container:" + specs.Door.Name)
	for i := range specs.Worker.Host.Mounts {
		if specs.Worker.Host.Mounts[i].Source != "" && specs.Worker.Host.Mounts[i].VolumeOptions != nil {
			specs.Worker.Host.Mounts[i].Source += sfx
		}
	}

	api := dockerProvAPI{c: &Client{docker: dc}}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		_ = api.RemoveContainer(cctx, specs.Worker.Name)
		_ = api.RemoveContainer(cctx, specs.Door.Name)
		for _, m := range specs.Worker.Host.Mounts {
			if m.VolumeOptions != nil {
				_, _ = dc.VolumeRemove(cctx, m.Source, client.VolumeRemoveOptions{Force: true})
			}
		}
		_ = api.RemoveNetwork(cctx, netName)
	})
	if err := api.CreateInternalNetwork(ctx, netName, map[string]string{LabelManagedBy: ManagedByAgent}); err != nil {
		t.Fatalf("network create refused by a real daemon: %v", err)
	}
	if err := api.CreateContainer(ctx, specs.Door); err != nil {
		t.Fatalf("door create refused by a real daemon: %v", err)
	}
	if err := api.CreateContainer(ctx, specs.Worker); err != nil {
		t.Fatalf("worker create refused by a real daemon: %v", err)
	}
}
