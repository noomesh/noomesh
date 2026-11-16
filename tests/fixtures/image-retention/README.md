# Image retention fixtures (captured 2026-11-14)

Real output, not typed. The tests in `noo-cli/src/commands/image_retention.rs`,
`noo-cli/src/commands/cluster_verify.rs` and
`node-agent-go/internal/hostd/image_retention_test.go` read them.

| file | captured from |
|---|---|
| `stack-v0.6.25-rc.1.lock`, `stack-v0.6.24.lock` | the release assets, byte for byte |
| `classic-overlay2-27.5.1.images` | the rehearsal's image cache (`noo-rh-images`) in `docker:27-dind`, classic store: `docker image inspect --format '{{.Id}}\|{{json .RepoTags}}\|{{json .RepoDigests}}'` |
| `docker27.images`, `docker28.images`, `docker29.images` | fresh `docker:27-dind` (27.5.1, overlay2), `docker:28-dind` (28.5.2, overlay2), `docker:29-dind` (29.9.3, containerd store), after pulling two rc.1 rows by digest and importing one tagged image; same format plus `\|{{.Size}}` |
| `docker2?.containers`, `classic-gateway.containers` | `docker inspect --format '{{.Name}}\|{{.Config.Image}}\|{{.Image}}\|{{.State.Running}}'` of containers created (not started) from compose-shaped refs (`<repo>:<tag>@sha256:<digest>`) |
| `containerd-node.images` | a fleet node's containerd store, noomesh images and two foreign ones |
| `keep-classic.golden.json` | the keep file the CLI builds from the two locks over `classic-overlay2-27.5.1.images` (the Rust test asserts it; hostd's test classifies it) |

Edits, and only these: lines naming a private registry org were dropped, and
in `containerd-node.images` a private mirror host is rewritten to
`registry.example.lan/noomesh/` (the leak guard refuses the real one). The
old `{{join .RepoTags ","}}` template failed for every image on 27 and 28:
`template parsing error: template: :1:15: executing "" at <.RepoTags>: wrong
type for value; expected []string; got []interface {}`.
