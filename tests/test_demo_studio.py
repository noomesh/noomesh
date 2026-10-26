# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""The film studio (scripts/demo/studio.sh) and the recorder's failed-step check.

vhs is not available in CI, so these run the tape's own shell lines in a real
interactive bash and check what they record, and pin the safety properties of
the scripts that cannot be exercised without Docker."""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

DEMO = Path(__file__).resolve().parents[1] / "scripts/demo"
BASH = shutil.which("bash") or "bash"
needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="bash is not installed")


def typed_lines(tape: str) -> list[str]:
    """The text of every `Type ... Enter` line in a tape, backtick-quoted ones unwrapped."""
    out = []
    for line in (DEMO / tape).read_text().splitlines():
        m = re.match(r"^Type `(.*)` Enter$", line)
        if m:
            out.append(m.group(1))
    return out


def fill(s: str, tmp: Path) -> str:
    return (
        s.replace("@RAW_LOG@", str(tmp / "raw.log"))
        .replace("@MASKED_LOG@", str(tmp / "masked.log"))
        .replace("@EXIT_LOG@", str(tmp / "exit.log"))
        .replace("@MASK@", "cat")
    )


def run_film_shell(tmp: Path, commands: list[str]) -> list[str]:
    """Type the tape's setup lines, then `commands`, into an interactive bash; return the exit log lines."""
    setup = [fill(s, tmp) for s in typed_lines("onboarding.tape.in") if s.startswith(("PROMPT_COMMAND=", "noo()", "sh()"))]
    assert len(setup) == 3, "the tape must define PROMPT_COMMAND, noo() and sh()"
    fake = tmp / "bin"
    fake.mkdir()
    (fake / "noo").write_text('#!/bin/sh\necho "noo says hi"\nfor a in "$@"; do [ "$a" != "--fail" ] || { echo "boom" >&2; exit 7; }; done\n')
    (fake / "noo").chmod(0o755)
    script = "\n".join(setup + commands + ["exit"]) + "\n"
    subprocess.run(
        [BASH, "--norc", "-i"], input=script, text=True, capture_output=True, check=False,
        env={"PATH": f"{fake}:/usr/bin:/bin", "HOME": str(tmp), "TERM": "dumb"},
    )
    log = tmp / "exit.log"
    return log.read_text().splitlines() if log.exists() else []


@needs_bash
def test_a_failing_step_leaves_a_non_zero_status_in_the_exit_log(tmp_path):
    lines = run_film_shell(tmp_path, ["noo --ok", "noo --fail", "echo fine"])
    flat = " ".join(lines).split()
    assert flat, "nothing was recorded"
    assert "7" in flat, f"the failing noo (exit 7) must be recorded, got {lines}"


@needs_bash
def test_all_steps_succeeding_records_only_zeros(tmp_path):
    lines = run_film_shell(tmp_path, ["noo --ok", "# a comment", "echo fine"])
    flat = " ".join(lines).split()
    assert flat and set(flat) == {"0"}, lines


@needs_bash
def test_a_failed_download_in_a_pipe_into_sh_is_recorded(tmp_path):
    # `curl -fsSL URL | sh`: curl fails, sh runs on empty input and succeeds; the pipeline's first status must still show.
    lines = run_film_shell(tmp_path, ["false | sh"])
    assert any(tok != "0" for tok in " ".join(lines).split()), lines


def test_every_placeholder_in_the_tapes_is_filled_by_the_recorder():
    rec = (DEMO / "record-onboarding.sh").read_text()
    for tape in ("onboarding.tape.in", "smoke.tape.in"):
        for ph in set(re.findall(r"@[A-Z_]+@", (DEMO / tape).read_text())):
            assert f"@{ph.strip('@')}@" in rec, f"{tape}: {ph} is not substituted by record-onboarding.sh"


def test_box_mode_only_trusts_containers_the_studio_made():
    rec = (DEMO / "record-onboarding.sh").read_text()
    studio = (DEMO / "studio.sh").read_text()
    assert "noo-demo-box" in rec and "noo-demo-box=1" in studio
    # every destructive studio verb checks the label before touching the container
    for verb in ("cmd_record", "cmd_down", "cmd_shell"):
        body = studio.split(f"{verb}()", 1)[1].split("\n}\n", 1)[0]
        assert "box_is_ours" in body, f"{verb} must check the label"


@needs_bash
def test_the_scripts_parse_and_help_works():
    for s in ("studio.sh", "record-onboarding.sh"):
        subprocess.run([BASH, "-n", str(DEMO / s)], check=True)
    r = subprocess.run([BASH, str(DEMO / "studio.sh"), "--help"], capture_output=True, text=True)
    assert r.returncode == 0 and "studio.sh up" in r.stdout


@needs_bash
def test_an_unknown_studio_command_fails_without_touching_docker():
    r = subprocess.run([BASH, str(DEMO / "studio.sh"), "frobnicate"], capture_output=True, text=True,
                       env={"PATH": "/nonexistent", "HOME": "/nonexistent"})
    assert r.returncode == 1 and "unknown command" in r.stderr


def test_the_cache_answers_as_ghcr_with_a_ca_only_the_box_trusts():
    """A pull-through cache of ghcr.io that the box reaches under the real
    name: Docker Engine mirrors only Docker Hub, so the cache must answer AS
    ghcr.io, and the box must trust its throwaway CA in both places TLS to a
    registry is checked. Anything less and the film's pulls go to the internet
    (or fail) while `cache status` says otherwise."""
    studio = (DEMO / "studio.sh").read_text()
    assert "REGISTRY_PROXY_REMOTEURL=\"$CACHE_UPSTREAM\"" in studio and "CACHE_UPSTREAM=https://ghcr.io" in studio
    assert "subjectAltName=DNS:ghcr.io" in studio, "the cache's leaf must be for the name the box resolves"
    up = studio.split("cmd_up()", 1)[1].split("\n}\n", 1)[0]
    assert '--add-host "ghcr.io:$cache_ip"' in up, "the box must resolve ghcr.io to the cache"
    assert "/etc/docker/certs.d/ghcr.io/ca.crt" in up and "update-ca-certificates" in up
    assert "https://ghcr.io/v2/" in up, "up must prove the box reaches the cache as ghcr.io"
    # only when the cache is actually running: a box made otherwise is a plain stranger's machine
    assert "if cache_running; then" in up


def test_cache_verbs_only_touch_the_cache_the_studio_made():
    studio = (DEMO / "studio.sh").read_text()
    assert "noo-demo-cache=1" in studio
    for verb in ("cmd_cache_up", "cmd_cache_down"):
        body = studio.split(f"{verb}()", 1)[1].split("\n}\n", 1)[0]
        assert "cache_is_ours" in body, f"{verb} must check the label"
    # purge is down plus the volume; it must not reach past the studio's own names
    purge = studio.split("cmd_cache_purge()", 1)[1].split("\n}\n", 1)[0]
    assert "cmd_cache_down" in purge and '"$CACHE_VOL"' in purge and '"$CACHE_DIR"' in purge


@needs_bash
def test_an_unknown_cache_command_fails_without_touching_docker():
    r = subprocess.run([BASH, str(DEMO / "studio.sh"), "cache", "frobnicate"], capture_output=True, text=True,
                       env={"PATH": "/nonexistent", "HOME": "/nonexistent"})
    assert r.returncode == 1 and "unknown cache command" in r.stderr
    r = subprocess.run([BASH, str(DEMO / "studio.sh"), "--help"], capture_output=True, text=True)
    assert "studio.sh cache up" in r.stdout


def test_the_studio_inspects_containers_only():
    """`docker inspect NAME` also matches a volume of that name, and the cache
    volume is called noo-demo-cache: a seeded volume made `cache up` refuse the
    studio's own cache (2026-10-24). Every inspect names the type."""
    studio = (DEMO / "studio.sh").read_text()
    code = "\n".join(l for l in studio.splitlines() if not l.lstrip().startswith("#"))
    inspects = re.findall(r"docker inspect\b[^\n]*", code)
    assert inspects, "no docker inspect in studio.sh?"
    bare = [i for i in inspects if "--type container" not in i]
    assert not bare, bare


def test_the_gif_is_made_from_the_mp4_streaming_and_the_recorder_is_capped():
    """vhs's GIF render holds every frame for one palette: killed at 7 GB,
    crashed a WSL2 host twice. The real tape outputs the MP4 only, the
    recorder makes the GIF from it with a palette per frame (streaming), and
    the recorder container has a memory cap. The smoke tape keeps both
    outputs: it is seconds long and proves the vhs GIF path still works."""
    tape = (DEMO / "onboarding.tape.in").read_text()
    outputs = re.findall(r"^Output (\S+)$", tape, re.M)
    assert outputs == ["demo-out/onboarding.mp4"], outputs
    assert "Set WaitTimeout 60m" in tape, "a cold onboard pulled for 40 min; 30 m ran out twice"
    rec = (DEMO / "record-onboarding.sh").read_text()
    assert 'gif_from_mp4 "$OUT/onboarding.mp4" "$OUT/onboarding.gif"' in rec
    body = rec.split("gif_from_mp4() {", 1)[1].split("\n}\n", 1)[0]
    assert "palettegen=stats_mode=single" in body and "paletteuse=new=1" in body, body
    assert "palettegen=stats_mode=diff" not in body and "palettegen[" not in body, "a global palette buffers every frame"
    smoke = (DEMO / "smoke.tape.in").read_text()
    assert re.findall(r"^Output (\S+)$", smoke, re.M) == ["demo-out/smoke.gif", "demo-out/smoke.mp4"]
    studio = (DEMO / "studio.sh").read_text()
    assert re.search(r'docker run --rm --name "\$REC" .*--memory "\$\{NOO_STUDIO_REC_MEM:-6g\}"', studio), "the recorder has no memory cap"
    assert 'CACHE_IMAGE="${NOO_STUDIO_CACHE_IMAGE:-registry:3}"' in studio


def test_the_cut_script_and_the_tape_after_take_seven():
    """Take 7 (2026-10-24) taught three things the files now carry: a cut
    script that speeds up and captions the network stretches instead of
    refilming; a chat prompt the small first model answers; and
    `noo stack status` in place of `noo cluster status`, which reads
    "no nodes" in a box without systemd."""
    cut = DEMO / "cut.sh"
    assert cut.is_file() and cut.stat().st_mode & 0o111, "cut.sh must be executable"
    text = cut.read_text()
    assert "drawtext=textfile=" in text and "setpts=(PTS-STARTPTS)/$sp" in text and "concat=n=" in text
    assert "SPDX-License-Identifier" in text
    r = subprocess.run(["bash", str(cut)], capture_output=True, text=True)
    assert r.returncode == 2 and "START END SPEED" in r.stderr, (r.returncode, r.stderr[:200])
    tape = (DEMO / "onboarding.tape.in").read_text()
    typed = [a or b for a, b in re.findall(r"^Type `(noo [^`]*)` Enter$|^Type \"(noo [^\"]*)\" Enter$", tape, re.M)]
    assert "noo stack status" in typed and "noo cluster status" not in typed, typed
    assert not any("what can you do on this machine" in t for t in typed), "the prompt gemma4:e2b misread"
    assert any(t.startswith("noo chat --message") and "noomesh" in t for t in typed), typed


def test_the_box_boots_systemd_and_runs_docker_as_a_unit():
    """Take 7 (2026-10-24): a box with `sleep infinity` as PID 1 never ran the
    host node agent or noo-hostd (both are systemd units on a real install),
    so the node never registered and the prep step printed "Failed to connect
    to bus" on camera. The box is now built with systemd as init."""
    studio = (DEMO / "studio.sh").read_text()
    assert "sleep infinity" not in studio and "start-dockerd" not in studio
    assert 'CMD ["/sbin/init"]' in studio and "STOPSIGNAL SIGRTMIN+3" in studio
    assert "systemd systemd-sysv" in studio and "systemctl enable docker" in studio
    run = studio.split("docker run -d --name \"$BOX\"", 1)[1].split(">/dev/null", 1)[0]
    assert "--tmpfs /run --tmpfs /run/lock" in run and "--cgroupns=private" in run and '"$BOX_IMAGE"' in run
    # Docker as a unit uses the containerd.io service, whose snapshots cannot sit
    # on the box's overlay rootfs: a volume for /var/lib/containerd too (take 8)
    assert '-v "$CONTAINERD_VOL":/var/lib/containerd' in run
    down = studio.split("cmd_down() {", 1)[1].split("\n}\n", 1)[0]
    assert '"$CONTAINERD_VOL"' in down, "down must remove the containerd volume with the image volume"
    assert "box_wait_booted" in studio and "systemctl is-system-running" in studio
    # a tmpfs systemd mounts on /tmp inside the box is invisible to `docker cp`,
    # which collects the recorder's logs from /tmp/demo: tmp.mount stays masked
    assert "tmp.mount" in studio.split("systemctl mask", 1)[1].split("\n", 1)[0]
    assert "--tmpfs /tmp" not in studio
    # the recorder's fallback starts the unit, not a hand-rolled daemon
    assert "systemctl start docker" in studio
    assert "useradd -m -s /bin/bash you" in studio and "usermod -aG docker you" in studio


def test_the_box_has_a_user_session_and_the_take_can_pin_a_release():
    """After #400, `noo onboard --ci` installs noo-hostd as a USER unit when
    sudo is passwordless. A `docker exec` shell has no user manager, so the box
    lingers `you` at boot (logind on, not masked) and the film shell carries
    XDG_RUNTIME_DIR and the session bus, as pam_systemd gives a real login.
    NOO_DEMO_CLI_VERSION pins the install on screen (an rc under test)."""
    studio = (DEMO / "studio.sh").read_text()
    assert "systemd-logind" not in studio.split("systemctl mask", 1)[1].split("\n", 1)[0], "logind must run: linger needs it"
    assert "/var/lib/systemd/linger/you" in studio
    assert 'systemctl is-active "user@' in studio
    assert "NOO_DEMO_CLI_VERSION" in studio
    rec = (DEMO / "record-onboarding.sh").read_text()
    assert "-e XDG_RUNTIME_DIR=/run/user/$BOX_UID -e DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$BOX_UID/bus" in rec
    assert 'INSTALL_SH="NOO_CLI_VERSION=$NOO_DEMO_CLI_VERSION sh"' in rec and "@INSTALL_SH@" in rec
    tape = (DEMO / "onboarding.tape.in").read_text()
    assert 'Type "curl -fsSL @INSTALL_URL@ | @INSTALL_SH@" Enter' in tape


def leak_literals(text: str, host: str = "mybox", extra: str = "") -> set[str]:
    r = subprocess.run([BASH, str(DEMO / "leak-literals.sh"), host, extra], input=text, text=True, capture_output=True, check=True)
    out = {}
    for line in r.stdout.splitlines():
        if line:
            tag, _, lit = line.partition("\t")
            out[lit] = tag
    return set(out)


def leak_tags(text: str, host: str = "mybox") -> dict[str, str]:
    r = subprocess.run([BASH, str(DEMO / "leak-literals.sh"), host, ""], input=text, text=True, capture_output=True, check=True)
    return {l.partition("\t")[2]: l.partition("\t")[0] for l in r.stdout.splitlines() if l}


@needs_bash
def test_the_leak_literals_are_the_maskers_shapes_not_sentences():
    """Take 10 (2026-10-25) was deleted because the leak check read
    "sudo needs no password here" as `password <value>` and flagged "here".
    The extractor now mirrors the masker: a secret has a `:` or `=` after
    its label (optionally "is"); a sentence with the word in it does not."""
    assert leak_literals("noo-hostd: no terminal, but sudo needs no password here — installing it") == set()
    assert leak_literals("needs sudo and a terminal; the password prompt waits") == set()
    assert leak_literals("Admin password: hunter2xyz\n") == {"hunter2xyz"}
    assert leak_literals("NOO_API_KEY=abc123def") == {"abc123def"}
    assert leak_literals("the token is: eyJhbGci.x.y") == {"eyJhbGci.x.y"}
    assert leak_literals("the token is eyJhbGci.x.y") == set(), "no separator: the masker leaves it too, so flagging it only deletes good takes"
    assert leak_literals("password: ********") == set(), "an already-masked value is not a leak"
    # the other rules are unchanged: addresses, the fleet's names, token shapes, tailnet names, e-mail
    got = leak_literals("agent at 10.1.2.3 and host3 and mybox, ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ, alice@mail.test, box.tail1234.ts.net", host="MyBox")
    assert {"10.1.2.3", "host3", "mybox", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ", "alice@mail.test", "box.tail1234.ts.net"} <= got, got
    assert leak_literals("127.0.0.1 192.0.2.7 you@example.com node-1 you server") == set()
    rec = (DEMO / "record-onboarding.sh").read_text()
    assert 'leak-literals.sh" "$host" "${NOO_DEMO_MASK_NAMES:-}" < "$raw"' in rec, "leak_check must read the one extractor"


@needs_bash
def test_take_eleven_s_false_leaks_and_the_report_names_kinds_not_values():
    """Take 11 (2026-10-25): three "leaks", two of them "Secrets: 9 present"
    (a count; and a one-digit secret is found in any version string) and
    "Node-1" (the masker's own stand-in, capitalised in a cluster-verify
    header). A label value shorter than 6 characters is not a secret, a
    stand-in is never a leak whatever its case, and the LEAK report says
    what kind and how long, never the value."""
    assert leak_literals("  Secrets: 9 present") == set()
    assert leak_literals("  Secrets: 24 values from secrets/env.sops") == set()
    assert leak_literals("# Node Node-1\nNODE-1 is up\nYou and Server") == set()
    assert leak_tags("password: hunter2xyz and 10.1.2.3 and host3") == {"hunter2xyz": "label", "10.1.2.3": "ip", "host3": "name"}
    rec = (DEMO / "record-onboarding.sh").read_text()
    assert "report=\"$report  - $tag (${#lit} chars)" in rec, "the LEAK report lists kind and length"
    assert "NOO_DEMO_KEEP_ON_LEAK" in rec and 'masked.LEAK.log' in rec


def test_every_recorder_knob_reaches_the_recorder_container():
    """The recorder runs in its own container: a knob the studio does not pass
    is silently off. Take 12 (2026-10-25) set NOO_DEMO_KEEP_ON_LEAK=1 and lost
    the transcript anyway, because only three knobs were passed."""
    studio = (DEMO / "studio.sh").read_text()
    passed = re.search(r"for v in ((?:NOO_DEMO_[A-Z_]+ ?)+); do", studio).group(1).split()
    rec = (DEMO / "record-onboarding.sh").read_text()
    used = set(re.findall(r"NOO_DEMO_(?!BOX\b|SANDBOX\b|HOSTNAME\b|MASK\b)[A-Z_]+", rec))
    assert used <= set(passed), f"recorder knobs the studio never passes: {sorted(used - set(passed))}"


def test_record_down_after_removes_the_box_whatever_the_recorder_returned():
    """Take 12's box stayed up for 35 hours on a shared host after the
    session that started it went idle. `record --down-after` takes the box
    down when the recorder exits, pass or fail, and still returns the
    recorder's status; the flag never reaches the recorder."""
    studio = (DEMO / "studio.sh").read_text()
    body = studio.split("cmd_record() {", 1)[1].split("\n}\n", 1)[0]
    assert "--down-after) down_after=1" in body and 'set -- "${args[@]}"' in body, "the flag is stripped before the recorder sees it"
    assert "local rc=$?" in body and body.index("local rc=$?") < body.index("cmd_down") < body.index('return "$rc"')
    assert "--down-after" in studio.split("record [--smoke]", 1)[1].split("\n", 1)[0], "the usage line names it"

@needs_bash
def test_an_environment_variable_name_after_a_secret_label_is_not_a_secret():
    """Take 13 (2026-10-26): "noo-apply: secrets in … moved to files under …:
    NOO_NODE_AGENT_TOKEN" gave a 20-char `label` literal, which (matched
    case-insensitively) is also in Compose's own "secrets.noo_node_agent_token"
    warning text in the masked output. A name is not a value."""
    assert leak_literals("noo-apply: secrets in /etc/x moved to files under /etc/y: NOO_NODE_AGENT_TOKEN NOO_CLUSTER_SECRET") == set()
    assert leak_literals("api key: ABCDEF1234567890") == {"ABCDEF1234567890"}, "all-caps without an underscore is still a value"
    assert leak_literals("token: abc_DEF_ghi_jkl_mno") == {"abc_DEF_ghi_jkl_mno"}, "mixed case with underscores is still a value"
