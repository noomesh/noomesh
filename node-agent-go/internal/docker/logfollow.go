// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"io"
	"strings"

	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"

	"github.com/noomesh/noomesh/node-agent-go/internal/logship"
)

// The log-shipping slice of the docker client (logship.DockerLogs).
//
// ContainerLogs above is a one-shot tail for `noo cluster logs`; the
// shipper needs a FOLLOWING stream plus a way to learn about container
// starts, so a backend the reconciler (re)creates is picked up without a
// poll. Both are thin: the demux and line handling live in logship, where
// they are tested without a daemon.

const composeProjectLabel = "com.docker.compose.project"
const composeServiceLabel = "com.docker.compose.service"

// shipsLogs decides which containers this node ships: the compose stack's
// (any project — the controller's stack and a worker's overlay both carry
// the label) and anything `noo-` prefixed the agent started itself.
func shipsLogs(name string, labels map[string]string) bool {
	if _, ok := labels[composeProjectLabel]; ok {
		return true
	}
	return strings.HasPrefix(name, "noo-")
}

// LogTargets lists the running containers to ship.
func (c *Client) LogTargets(ctx context.Context) ([]logship.ContainerTarget, error) {
	if c == nil || c.docker == nil {
		return nil, nil
	}
	containers, err := c.listContainers(ctx, client.ContainerListOptions{})
	if err != nil {
		return nil, err
	}
	var out []logship.ContainerTarget
	for _, ctr := range containers {
		if len(ctr.Names) == 0 {
			continue
		}
		name := strings.TrimPrefix(ctr.Names[0], "/")
		if !shipsLogs(name, ctr.Labels) {
			continue
		}
		out = append(out, logship.ContainerTarget{Name: name, ComposeService: ctr.Labels[composeServiceLabel]})
	}
	return out, nil
}

// FollowLogs opens a following, timestamped stdout+stderr stream.
func (c *Client) FollowLogs(ctx context.Context, name, since string) (io.ReadCloser, bool, error) {
	tty := false
	if ins, err := c.docker.ContainerInspect(ctx, name, client.ContainerInspectOptions{}); err == nil {
		if cfg := ins.Container.Config; cfg != nil {
			tty = cfg.Tty
		}
	}
	r, err := c.docker.ContainerLogs(ctx, name, client.ContainerLogsOptions{
		ShowStdout: true, ShowStderr: true, Follow: true, Timestamps: true, Since: since,
	})
	if err != nil {
		return nil, false, err
	}
	return r, tty, nil
}

// ContainerStarts streams container start events for shippable containers.
func (c *Client) ContainerStarts(ctx context.Context) (<-chan logship.ContainerTarget, <-chan error) {
	out := make(chan logship.ContainerTarget)
	errs := make(chan error, 1)
	if c == nil || c.docker == nil {
		errs <- io.EOF
		return out, errs
	}
	res := c.docker.Events(ctx, client.EventsListOptions{
		Filters: client.Filters{}.Add("type", string(events.ContainerEventType)).Add("event", string(events.ActionStart)),
	})
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case err := <-res.Err:
				errs <- err
				return
			case m, ok := <-res.Messages:
				if !ok {
					errs <- io.EOF
					return
				}
				name := m.Actor.Attributes["name"]
				if name == "" || !shipsLogs(name, m.Actor.Attributes) {
					continue
				}
				select {
				case out <- logship.ContainerTarget{Name: name, ComposeService: m.Actor.Attributes[composeServiceLabel]}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, errs
}
