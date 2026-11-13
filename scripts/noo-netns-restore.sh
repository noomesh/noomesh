#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
#
# noo-netns-restore: start the stack containers that dockerd failed to start
# because they join ANOTHER container's network namespace and their door was
# not up yet. One bounded pass, then exit.
#
# Why. A service with `network_mode: service:<door>` (noo-ollama-embed joins
# noo-stunnel-ollama-embed, i317) is started by dockerd's own restore at every
# dockerd start (a reboot, a package upgrade, `systemctl restart docker`) in no
# particular order. When it comes before its door it fails with exit 128,
# "cannot join network namespace of a non running container", and dockerd
# never retries it (RestartCount 0, whatever its restart policy). On a single
# box that is the chat backend: about one dockerd start in five on a hosted
# 22.04 runner left it down (rc.2 install matrix probe, 2026-11-12).
#
# What it starts, and nothing else: a container of a compose project, not
# labelled noo.managed-by (the node agent's convergence owns those), whose
# restart policy wants it running (always/unless-stopped), whose network mode
# is container:<door>, and whose last start FAILED joining that namespace:
# State.ExitCode is 128 (dockerd's code for a container it could not start),
# or State.Error says "join network", in either docker's wording:
#   Docker 27.x  "cannot join network of a non running container: <id>"
#   Docker 28.x  "cannot join network namespace of a non running container: …"
# (matching only "network namespace" skipped every joiner on Docker 27, the
# rc.3 rehearsal's dind and Ubuntu's docker.io: A-reboot.status, i677).
# A container someone stopped by
# hand has no such error and stays stopped. It waits for each door (bounded),
# starts the joiner, and says so: one line per container it started (the
# journal, under systemd). Nothing to do: no output, exit 0.
#
# Run by noo-netns-restore.service (onboard installs it on a controller with
# systemd: After= and PartOf=docker.service, WantedBy=docker.service, as the
# install owner) and at the end of noo-hostd's boot-restore (a host without
# systemd that runs hostd). Env: NOO_NETNS_DOCKER_WAIT (s, default 120) for
# docker to answer; NOO_NETNS_DOOR_WAIT (s, default 60) per door.
set -u
docker_wait="${NOO_NETNS_DOCKER_WAIT:-120}"
door_wait="${NOO_NETNS_DOOR_WAIT:-60}"
t=0
until docker info >/dev/null 2>&1; do
  if [ "$t" -ge "$docker_wait" ]; then
    echo "noo-netns-restore: docker did not answer within ${docker_wait}s; nothing was started" >&2
    exit 1
  fi
  sleep 2; t=$((t + 2))
done
rc=0
for id in $(docker ps -aq --filter status=exited --filter status=created); do
  meta="$(docker inspect -f '{{.Name}}|{{.HostConfig.NetworkMode}}|{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "noo.managed-by"}}|{{.HostConfig.RestartPolicy.Name}}|{{.State.Error}}|{{.State.ExitCode}}' "$id" 2>/dev/null)" || continue
  IFS='|' read -r name mode proj mby policy err code <<< "$meta"
  name="${name#/}"
  [ -n "$proj" ] || continue
  [ -z "$mby" ] || continue
  case "$policy" in always|unless-stopped) ;; *) continue ;; esac
  case "$mode" in container:*) door="${mode#container:}" ;; *) continue ;; esac
  # The failed join: exit code 128 (dockerd's code for a container it could
  # not start) OR an error naming the join. The code is the firm signal; the
  # text is the fallback, so a third rewording cannot reopen this. A container
  # stopped by hand exits 0/137/143 with no join error and stays stopped.
  joinfail=""
  : 
  case "$err" in *"join network"*) joinfail=1 ;; esac
  [ -n "$joinfail" ] || continue
  dname="$(docker inspect -f '{{.Name}}' "$door" 2>/dev/null)"; dname="${dname#/}"; dname="${dname:-$door}"
  w=0
  until [ "$(docker inspect -f '{{.State.Running}}' "$door" 2>/dev/null)" = "true" ]; do
    if [ "$w" -ge "$door_wait" ]; then break; fi
    sleep 2; w=$((w + 2))
  done
  if [ "$(docker inspect -f '{{.State.Running}}' "$door" 2>/dev/null)" != "true" ]; then
    echo "noo-netns-restore: $name not started: its network door $dname is not running after ${door_wait}s" >&2
    rc=1
    continue
  fi
  if docker start "$id" >/dev/null 2>&1; then
    echo "noo-netns-restore: started $name (it joins $dname's network, which dockerd had not started first)"
  else
    echo "noo-netns-restore: $name did not start (docker start failed; its door $dname is running)" >&2
    rc=1
  fi
done
exit "$rc"
