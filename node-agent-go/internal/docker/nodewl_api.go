// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"

	"github.com/noomesh/noomesh/node-agent-go/internal/preseed"
)

// dockerProvAPI is provAPI over the Docker daemon.
type dockerProvAPI struct{ c *Client }

// isGone reports a "no such thing" answer from the daemon. The client's error
// types are not imported (they would pull a module this package does not
// name directly), so this reads the interface they implement and, failing
// that, the daemon's wording.
func isGone(err error) bool {
	if err == nil {
		return false
	}
	var nf interface{ NotFound() bool }
	if errors.As(err, &nf) && nf.NotFound() {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "no such") || strings.Contains(s, "not found")
}

func (d dockerProvAPI) ImageExists(ctx context.Context, id string) (bool, error) {
	res, err := d.c.docker.ImageInspect(ctx, id)
	if err != nil {
		if isGone(err) {
			return false, nil
		}
		return false, err
	}
	// An ID is exact. A ref that merely resolves to another image is not it.
	return sameImageID(res.ID, id), nil
}

// LoadImage loads the tar and returns the ID of every image the load
// reported: a "Loaded image ID" line is an ID, a "Loaded image" line is a tag
// resolved to the ID it now names.
func (d dockerProvAPI) LoadImage(ctx context.Context, f *os.File) ([]string, error) {
	res, err := d.c.docker.ImageLoad(ctx, f)
	if err != nil {
		return nil, err
	}
	out := drainToString(res)
	res.Close()
	if strings.Contains(out, "\"error\"") {
		return nil, fmt.Errorf("docker load reported: %s", strings.TrimSpace(out))
	}
	id, refs := parseLoadOutput(out)
	var ids []string
	if id != "" {
		ids = append(ids, id)
	}
	for _, r := range refs {
		res, err := d.c.docker.ImageInspect(ctx, r)
		if err != nil {
			return nil, fmt.Errorf("loaded %s but it does not resolve: %w", r, err)
		}
		ids = append(ids, res.ID)
	}
	return ids, nil
}

func (d dockerProvAPI) InspectContainer(ctx context.Context, name string) (*ctrInfo, error) {
	res, err := d.c.docker.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
	if err != nil {
		if isGone(err) {
			return nil, nil
		}
		return nil, err
	}
	c := res.Container
	info := &ctrInfo{ID: c.ID, Labels: map[string]string{}, IPs: map[string]string{}}
	if c.Config != nil {
		for k, v := range c.Config.Labels {
			info.Labels[k] = v
		}
	}
	if c.State != nil {
		info.Running = c.State.Running
		info.Status = string(c.State.Status)
		if t, perr := time.Parse(time.RFC3339Nano, c.State.StartedAt); perr == nil && !t.IsZero() && t.Year() > 1 {
			info.StartedAt = t
		}
	}
	if c.NetworkSettings != nil {
		for n, ep := range c.NetworkSettings.Networks {
			if ep != nil && ep.IPAddress.IsValid() {
				info.IPs[n] = ep.IPAddress.String()
			}
		}
	}
	return info, nil
}

func (d dockerProvAPI) CreateContainer(ctx context.Context, s createSpec) error {
	_, err := d.c.docker.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config: s.Config, HostConfig: s.Host, NetworkingConfig: s.Net, Name: s.Name,
	})
	return err
}

func (d dockerProvAPI) StartContainer(ctx context.Context, name string) error {
	return d.c.StartContainer(ctx, name)
}

func (d dockerProvAPI) StopContainer(ctx context.Context, name string, graceS int) error {
	return d.c.StopContainerGraceful(ctx, name, graceS)
}

func (d dockerProvAPI) RemoveContainer(ctx context.Context, name string) error {
	// Force: a stopped container is the normal case, and a running one is
	// only ever removed by a caller that has already drained it.
	_, err := d.c.docker.ContainerRemove(ctx, name, client.ContainerRemoveOptions{Force: true})
	if err != nil && !isGone(err) {
		return err
	}
	return nil
}

func (d dockerProvAPI) InspectNetwork(ctx context.Context, name string) (*netInfo, error) {
	res, err := d.c.docker.NetworkInspect(ctx, name, client.NetworkInspectOptions{})
	if err != nil {
		if isGone(err) {
			return nil, nil
		}
		return nil, err
	}
	return &netInfo{Internal: res.Network.Internal, Labels: res.Network.Labels}, nil
}

// CreateInternalNetwork creates the workload's private network: a bridge with
// `internal: true`, so Docker installs no route and no NAT out of it. The
// host keeps its own address on the bridge, which is how the agent reaches the
// door (docs/reference/node-workloads.md, "Door network").
func (d dockerProvAPI) CreateInternalNetwork(ctx context.Context, name string, labels map[string]string) error {
	off := false
	_, err := d.c.docker.NetworkCreate(ctx, name, client.NetworkCreateOptions{
		Driver: "bridge", Internal: true, EnableIPv6: &off, Labels: labels,
	})
	return err
}

func (d dockerProvAPI) RemoveNetwork(ctx context.Context, name string) error {
	_, err := d.c.docker.NetworkRemove(ctx, name, client.NetworkRemoveOptions{})
	if err != nil && !isGone(err) {
		return err
	}
	return nil
}

// RemoveVolumes removes the scratch volumes this agent made for addon/workload,
// found by label so nothing else is ever touched.
func (d dockerProvAPI) RemoveVolumes(ctx context.Context, addon, workload string) error {
	res, err := d.c.docker.VolumeList(ctx, client.VolumeListOptions{
		Filters: make(client.Filters).
			Add("label", LabelManagedBy+"="+ManagedByAgent).
			Add("label", LabelAddon+"="+addon).
			Add("label", LabelWorkload+"="+workload),
	})
	if err != nil {
		return err
	}
	for _, v := range res.Items {
		if _, err := d.c.docker.VolumeRemove(ctx, v.Name, client.VolumeRemoveOptions{Force: true}); err != nil && !isGone(err) {
			return fmt.Errorf("remove volume %s: %w", v.Name, err)
		}
	}
	return nil
}

// ListManaged finds this agent's workloads by the noo.managed-by=agent label
// alone: the door, the worker, in any state.
func (d dockerProvAPI) ListManaged(ctx context.Context) ([]managedRef, error) {
	ctrs, err := d.c.listContainers(ctx, client.ContainerListOptions{
		All:     true,
		Filters: make(client.Filters).Add("label", LabelManagedBy+"="+ManagedByAgent),
	})
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}
	byKey := map[string]*managedRef{}
	var order []string
	for _, c := range ctrs {
		// The daemon filtered on the label; the sweep deletes what this
		// returns, so the label is checked again here rather than trusted.
		if c.Labels[LabelManagedBy] != ManagedByAgent {
			continue
		}
		addon, name := c.Labels[LabelAddon], c.Labels[LabelWorkload]
		if addon == "" || name == "" {
			continue
		}
		k := wlKey(addon, name)
		ref := byKey[k]
		if ref == nil {
			ref = &managedRef{Addon: addon, Name: name}
			byKey[k] = ref
			order = append(order, k)
		}
		if c.Labels[LabelRole] == RoleWorker {
			ref.Labels = c.Labels
		}
	}
	out := make([]managedRef, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	return out, nil
}

func (d dockerProvAPI) NvidiaRuntime(ctx context.Context) bool {
	return d.c.nvidiaRuntimeRegistered(ctx)
}

var _ = network.EndpointSettings{} // the create path builds these (nodewl_spec.go)

// fetchRailTar brings one staged image tar over the mTLS rail, checking its
// sha256 against the rail manifest before a byte of it is handed to docker.
// The tar is single-use: cleanup removes it.
func fetchRailTar(ctx context.Context, artifact string) (string, func(), error) {
	// No "." / ".." / hidden names: the real name is noo-addon-wl_<...>.tar
	// (nodewl.ParseDesired holds it to its exact per-entry pattern; this is
	// the last guard before the path is built, so it does not rely on that).
	if artifact == "" || artifact == "." || artifact == ".." || strings.HasPrefix(artifact, ".") ||
		filepath.Base(artifact) != artifact || strings.ContainsAny(artifact, `/\`) {
		return "", nil, fmt.Errorf("invalid artifact name %q", artifact)
	}
	unlock, _ := lockImageRef("artifact:" + artifact)
	defer unlock()
	cacheURL := preseed.CacheURL()
	if cacheURL == "" {
		return "", nil, errors.New("NOO_MODEL_CACHE_URL is not set: no data plane to pull from")
	}
	m, err := imageManifestFetch(ctx, artifact)
	if err != nil {
		return "", nil, err
	}
	if err := os.MkdirAll(stagingDir(), 0o755); err != nil {
		return "", nil, fmt.Errorf("staging dir: %w", err)
	}
	staged := filepath.Join(stagingDir(), artifact)
	slog.Info("pulling node workload image", "tar", artifact, "sha256", m.SHA256[:min(12, len(m.SHA256))]+"…")
	fetchCtx, cancel := context.WithTimeout(ctx, 40*time.Minute)
	defer cancel()
	if _, err := preseed.New().FetchOneVerified(fetchCtx, cacheURL+"/images/"+url.PathEscape(artifact), staged, m.SHA256); err != nil {
		if errors.Is(err, preseed.ErrDigestMismatch) {
			return "", nil, &ImageVerificationError{Ref: artifact, Err: err}
		}
		return "", nil, err
	}
	return staged, func() { _ = os.Remove(staged) }, nil
}

// checkTarOneImage reads a staged image archive's manifest before docker sees
// it and refuses one that does not hold exactly one image (an attestation
// manifest that rides beside an image does not count).
func checkTarOneImage(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open staged tar: %w", err)
	}
	defer f.Close()
	var magic [2]byte
	n, _ := io.ReadFull(f, magic[:])
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("read staged tar: %w", err)
	}
	var r io.Reader = f
	if n == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("read staged gzip: %w", err)
		}
		defer zr.Close()
		r = zr
	}
	return tarHoldsOneImage(r)
}

func tarHoldsOneImage(r io.Reader) error {
	var manifestJSON, indexJSON []byte
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read image archive: %w", err)
		}
		switch strings.TrimPrefix(h.Name, "./") {
		case "manifest.json":
			manifestJSON, err = io.ReadAll(io.LimitReader(tr, 1<<20))
		case "index.json":
			indexJSON, err = io.ReadAll(io.LimitReader(tr, 1<<20))
		}
		if err != nil {
			return fmt.Errorf("read image archive: %w", err)
		}
	}
	if manifestJSON == nil && indexJSON == nil {
		return errors.New("not an image archive: no manifest.json or index.json")
	}
	if manifestJSON != nil {
		var m []json.RawMessage
		if err := json.Unmarshal(manifestJSON, &m); err != nil {
			return fmt.Errorf("unreadable manifest.json: %w", err)
		}
		if len(m) != 1 {
			return fmt.Errorf("the archive holds %d images; a staged tar must hold exactly one", len(m))
		}
	}
	if indexJSON != nil {
		var idx struct {
			Manifests []ociIndexEntry `json:"manifests"`
		}
		if err := json.Unmarshal(indexJSON, &idx); err != nil {
			return fmt.Errorf("unreadable index.json: %w", err)
		}
		images := 0
		for _, m := range idx.Manifests {
			if !m.isAttestation() {
				images++
			}
		}
		if images != 1 {
			return fmt.Errorf("the archive index lists %d images; a staged tar must hold exactly one", images)
		}
	}
	return nil
}
