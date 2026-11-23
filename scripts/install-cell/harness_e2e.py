#!/usr/bin/env python3
"""HARNESS-E2E: a chat served through a harness held off the internet, on a
fresh one-box install with a real systemd.

What it proves, on this cell: the RELEASED harness (the release's gateway
binary, unit and env template), installed by the product's own applier
through the pull rail a worker's bundle takes, is held by the product's own
egress block, takes a chat turn the gateway dispatches to it, and while that
turn is served a connection from inside the harness unit's own cgroup to an
address outside the allow list does not connect.

The test's only hand is building the bundle: provision never ships a harness
to the controller's own node (noo-cli provision.rs attach_harness), so this
judge assembles the same bundle a worker's provision would (the release's
gateway asset checked against the release-signed sha256sums.txt, the
release's own unit and env template from the installed root, the env
rendered as provision renders it, the release lists, signed with the fleet
signing key, encrypted to the node's birth certificate) and stages it at
/api/cluster/provision-bundle/<node>. Everything after that is the product:
noo-fetch, noo-apply (its release check, the harness user, the TLS copy, the
hold), `noo cluster place <node> harness auto`, the agent starting the unit,
dispatch.

`noo cluster verify` shows no `harness egress` row for the controller's own
node (cluster_verify.rs harness_egress_check), so this judge reads the
object that row would judge, `host_services.harness.egress` in `noo --json
cluster status`, and the unit's own IPAddressDeny/IPAddressAllow. The row's
reading of an enforced unit is exercised elsewhere: the hosted
harness-egress-systemd lane's TestRealSystemdEgress (the agent's reader on a
live held unit) and cluster_verify.rs's row tests on an enforced record.

Secrets (this runs in PUBLIC Actions logs): the agent token and the cluster
secret are read into memory and into one 0600 file in a 0700 directory
outside the cell's uploaded output; the fleet signing key is used by its
path only. None is printed, passed on argv or written under $OUT, and the
step ends by checking that none of their values, nor their sha256, occurs
in anything it printed or wrote.

Verdict line: `HARNESS-E2E PASS|FAIL|NOTE: ...`. NOTE (exit 0) where it cannot
judge: no systemd as PID 1 (WSL2 without systemd), no systemd-run, no
internet from the host for the refused-connection control, or a release
without the pieces it installs. Evidence: <out>/logs/harness-e2e-evidence.log.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_evidence as ae  # noqa: E402
import ws_chat  # noqa: E402

GW = "https://localhost:8080"
NOO = os.environ.get("NOO_BIN") or "noo"
CLASS = "he-held"
FALLBACKS = ("harness dispatch: refused; running in process",
             "harness dispatch: no responder; running in process",
             "harness dispatch: no ack within")
OUT_TEXT: list[str] = []
SECRETS: list[str] = []


def say(line: str) -> None:
    OUT_TEXT.append(line)
    print(line, flush=True)


def run(argv: list[str], timeout: float = 120, input_bytes: bytes | None = None) -> tuple[int, str]:
    try:
        p = subprocess.run(argv, capture_output=True, timeout=timeout, input=input_bytes)
    except (OSError, subprocess.TimeoutExpired) as e:
        return 999, f"{type(e).__name__}"
    return p.returncode, (p.stdout + p.stderr).decode(errors="replace")


def root_read(path: str) -> bytes | None:
    """A root-only file's bytes, into memory (never printed)."""
    if os.geteuid() == 0:
        try:
            return open(path, "rb").read()
        except OSError:
            return None
    try:
        p = subprocess.run(["sudo", "-n", "cat", path], capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return p.stdout if p.returncode == 0 else None


def env_value(text: str, key: str) -> str:
    v = ""
    for line in text.splitlines():
        if line.startswith(key + "="):
            v = line[len(key) + 1:].strip().strip("\r")
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
    return v


def agent_secret(text: str, key: str) -> str:
    """As noo-apply's agent_env_secret: the KEY_FILE pointer first, else KEY."""
    ptr = env_value(text, key + "_FILE")
    if ptr:
        b = root_read(ptr)
        return b.decode().strip() if b else ""
    return env_value(text, key)


def render(tmpl: str, v: dict[str, str]) -> str:
    """The env template, rendered as provision's fail-loud renderer does for
    this one file: comments dropped, the TLS block kept when noo_pki_dir is
    set, every {{ var }} supplied."""
    t = re.sub(r"\{#.*?#\}\n?", "", tmpl, flags=re.S)
    keep = bool(v.get("noo_pki_dir"))
    t = re.sub(r"\{% if noo_pki_dir is defined and noo_pki_dir \| length > 0 %\}\n?(.*?)\{% endif %\}\n?",
               lambda m: m.group(1) if keep else "", t, flags=re.S)
    if "{%" in t:
        raise ValueError("the env template has a block this judge does not render")

    def sub(m: re.Match) -> str:
        k = m.group(1)
        if k not in v:
            raise KeyError(k)
        return v[k]
    return re.sub(r"\{\{\s*([a-z_]+)\s*\}\}", sub, t)


def standalone_root() -> str | None:
    for dp, dn, fn in os.walk(os.path.expanduser("~")):
        if dp.count(os.sep) - os.path.expanduser("~").count(os.sep) > 4:
            dn[:] = []
            continue
        if ".noo-standalone" in fn:
            return dp
    return None


def noo_json(*args: str, timeout: float = 120):
    rc, out = run([NOO, "--json", *args], timeout=timeout)
    try:
        return json.loads(out[out.find("{"):]) if rc == 0 else None
    except ValueError:
        return None


def self_record(node: str) -> dict | None:
    d = noo_json("cluster", "status")
    for n in (d or {}).get("nodes", []) or []:
        if n.get("id") == node or n.get("node_id") == node:
            return n
    return None


def http(method: str, path: str, body: bytes | None = None, ctype: str = "application/json", timeout: float = 120):
    ctx = ssl.create_default_context(cafile=ws_chat.cluster_ca())

    def once():
        req = urllib.request.Request(GW + path, data=body, method=method,
                                     headers={"Authorization": "Bearer " + ws_chat.token(), "Content-Type": ctype})
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            return r.status, r.read()
    try:
        return once()
    except urllib.error.HTTPError as e:
        if e.code == 401 and ws_chat.refresh_via_cli():
            try:
                return once()
            except urllib.error.HTTPError as e2:
                return e2.code, e2.read()
        return e.code, e.read()


def release_repo() -> str:
    """Resolved, never typed: NOO_CLI_REPO, else the repository this workflow
    runs in (Actions sets it). Empty: nothing to fetch from."""
    return os.environ.get("NOO_CLI_REPO") or os.environ.get("GITHUB_REPOSITORY") or ""


def fetch_release_file(ver: str, name: str, cache: str) -> bytes | None:
    p = os.path.join(cache, name)
    if os.path.isfile(p) and os.path.getsize(p) > 0:
        return open(p, "rb").read()
    repo = release_repo()
    if not repo:
        return None
    url = f"https://github.com/{repo}/releases/download/noo-cli-v{ver}/{name}"
    try:
        with urllib.request.urlopen(url, timeout=300) as r:
            return r.read()
    except Exception:
        return None


def expected_allow(controller_url: str, nats_url: str) -> set[str]:
    want = {"127.0.0.1/32", "::1/128"}
    for u in (controller_url, nats_url):
        host = re.sub(r"^[a-z]+://", "", u).split("/")[0].rsplit(":", 1)[0].strip("[]")
        if not host or host == "localhost":
            continue
        try:
            for fam, _, _, _, sa in socket.getaddrinfo(host, None):
                want.add(sa[0] + ("/32" if fam == socket.AF_INET else "/128"))
        except OSError:
            pass
    return want


def collect(ev: list[str], tmp: str, E: dict) -> None:
    """Every fact the verdict reads, into E (all I/O lives here). A step that
    cannot go on records (state, why) in E['stop'] and returns."""
    def stop(state: str, why: str) -> None:
        E["stop"] = [state, why]

    E["systemd"] = os.path.isdir("/run/systemd/system")
    E["systemd_run"] = bool(shutil.which("systemd-run"))
    E["machine"] = platform.machine()
    arch = {"x86_64": "x86_64", "aarch64": "aarch64"}.get(E["machine"])
    if not (E["systemd"] and E["systemd_run"] and arch):
        return
    agent_env_b = root_read("/etc/noo-node-agent.env")
    if not agent_env_b:
        return stop("FAIL", "cannot read /etc/noo-node-agent.env (sudo -n)")
    agent_env = agent_env_b.decode(errors="replace")
    node = env_value(agent_env, "NODE_ID")
    controller_url, nats_url = env_value(agent_env, "CONTROLLER_URL"), env_value(agent_env, "NATS_URL")
    pki_dir = env_value(agent_env, "NOO_PKI_DIR")
    token, secret = agent_secret(agent_env, "NOO_NODE_AGENT_TOKEN"), agent_secret(agent_env, "NOO_CLUSTER_SECRET")
    SECRETS.extend(s for s in (token, secret) if s)
    if not (node and controller_url and nats_url and token):
        return stop("FAIL", "the agent env lacks NODE_ID, CONTROLLER_URL, NATS_URL or the node token")
    ev.append(f"node={node} controller_url={controller_url} nats_url={nats_url} pki_dir={pki_dir or 'none'}")

    root = standalone_root()
    if not root:
        return stop("FAIL", "no standalone root (.noo-standalone) under $HOME")
    rc, vout = run([NOO, "--version"])
    m = re.search(r"(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)", vout)
    if rc != 0 or not m:
        return stop("FAIL", f"noo --version gave no version ({vout.strip()[:80]})")
    ver = m.group(1)
    cache = os.path.join(root, "bin", ver)
    sums = fetch_release_file(ver, "sha256sums.txt", cache)
    sums_sig = fetch_release_file(ver, "sha256sums.txt.sig", cache)
    if not sums or not sums_sig:
        return stop("NOTE", f"release {ver}'s sha256sums.txt or its .sig is neither cached nor downloadable")
    rows = dict((l.split()[1], l.split()[0]) for l in sums.decode().splitlines() if len(l.split()) == 2)
    asset = next((a for a in (f"noo-gateway-{arch}-unknown-linux-musl", f"noo-gateway-{arch}-unknown-linux-gnu") if a in rows), None)
    if not asset:
        return stop("NOTE", f"release {ver} lists no noo-gateway asset for {arch}")
    cached = os.path.isfile(os.path.join(cache, asset)) and os.path.getsize(os.path.join(cache, asset)) > 0
    if not cached and not release_repo():
        return stop("NOTE", f"{asset} is not cached here and no release repository is known to fetch it from "
                            "(NOO_CLI_REPO and GITHUB_REPOSITORY unset: a WSL cell gets only what WSLENV lists)")
    binary = fetch_release_file(ver, asset, cache)
    if not binary or hashlib.sha256(binary).hexdigest() != rows[asset]:
        return stop("FAIL", f"{asset} could not be fetched or does not match release {ver}'s signed sums")
    ev.append(f"release={ver} asset={asset} sha_ok=yes")
    deploy = os.path.join(root, "node-agent-go", "deploy")
    try:
        unit = open(os.path.join(deploy, "noo-harness.service"), "rb").read()
        tmpl = open(os.path.join(deploy, "noo-harness.env.tmpl")).read()
    except OSError as e:
        return stop("FAIL", f"the installed root has no harness unit or env template ({e.strerror})")
    cred = "/run/credentials/noo-harness.service"
    try:
        henv = render(tmpl, {
            "na_node_id": node, "controller_url": controller_url, "nats_url": nats_url,
            "noo_pki_dir": pki_dir, "harness_tls_ca": f"{cred}/ca.crt", "harness_tls_cert": f"{cred}/node.crt",
            "harness_tls_key": f"{cred}/node.key", "noo_harness_model_url": "https://127.0.0.1:8081",
            "noo_node_agent_token": token, "noo_cluster_secret": secret,
            "noo_harness_max_turns": "2", "harness_log": "noo_gateway=info"})
    except (KeyError, ValueError) as e:
        return stop("FAIL", f"the release's harness env template names a variable this judge does not supply: {e}")

    # The bundle, as sign-bundle.sh and provision build it.
    files = {"harness-binary": binary, "harness-env": henv.encode(), "harness-unit": unit,
             "release-sums": sums, "release-sums.sig": sums_sig, "release-version": f"{ver}\n".encode()}
    manifest = f"#noo-bundle 2\n#node {node}\n#issued {int(time.time())}\n"
    manifest += "".join(f"{hashlib.sha256(b).hexdigest()}  {k}\n" for k, b in files.items())
    mpath, spath = os.path.join(tmp, "manifest"), os.path.join(tmp, "manifest.sig")
    open(mpath, "w").write(manifest)
    # The CLI's own resolution (noo-cli pki.rs pki_dir): NOO_PKI_DIR, which a
    # standalone install sets in its root's .env, else ~/.config/mesh/pki.
    try:
        root_env = open(os.path.join(root, ".env")).read()
    except OSError:
        root_env = ""
    pki = os.environ.get("NOO_PKI_DIR") or env_value(root_env, "NOO_PKI_DIR") or os.path.expanduser("~/.config/mesh/pki")
    key = os.path.join(os.path.expanduser(pki), "signing.key")
    # Worded with no "key: value" shape: the cell's upload gate reads one as a
    # secret and withholds every log of the cell (rc.2 and rc.3 runs).
    ev.append(f"the fleet signing key is {'readable' if os.access(key, os.R_OK) else 'NOT readable'} in the CLI's PKI directory ({pki})")
    if not os.access(key, os.R_OK):
        return stop("FAIL", "the fleet signing key is not readable in the CLI's PKI directory")
    rc, so = run(["openssl", "dgst", "-sha256", "-sign", key, "-out", spath, mpath])
    if rc != 0:
        return stop("FAIL", "openssl could not sign the manifest")
    tar_path = os.path.join(tmp, "bundle.tar")
    with tarfile.open(tar_path, "w") as tf:
        for name, path in (("manifest", mpath), ("manifest.sig", spath)):
            tf.add(path, arcname=name)
        for k, b in files.items():
            ti = tarfile.TarInfo(f"files/{k}")
            ti.size, ti.mode = len(b), 0o600
            tf.addfile(ti, io.BytesIO(b))
    birth = root_read("/etc/noo/birth.crt")
    if not birth:
        return stop("FAIL", "cannot read the node's birth certificate (/etc/noo/birth.crt)")
    bpath, blob = os.path.join(tmp, "birth.crt"), os.path.join(tmp, "bundle.cms")
    open(bpath, "wb").write(birth)
    rc, _ = run(["openssl", "smime", "-encrypt", "-binary", "-aes-256-cbc", "-outform", "DER",
                 "-in", tar_path, "-out", blob, bpath])
    if rc != 0:
        return stop("FAIL", "openssl could not encrypt the bundle to the birth certificate")
    st, body = http("POST", f"/api/cluster/provision-bundle/{node}", open(blob, "rb").read(), "application/octet-stream", 600)
    ev.append(f"staged: HTTP {st} ({len(files)} kinds, {os.path.getsize(blob)} bytes)")
    if st // 100 != 2:
        return stop("FAIL", f"the gateway refused the staged bundle: HTTP {st}")

    rc, pout = run([NOO, "cluster", "place", node, "harness", "auto"], timeout=120)
    ev.append(f"place: rc={rc} {pout.strip().splitlines()[-1][:160] if pout.strip() else ''}")
    if rc != 0:
        return stop("FAIL", "noo cluster place <self> harness auto failed")

    # The product applies it (noo-fetch, noo-apply) and the agent starts it.
    deadline, rec, h, apply_msg = time.time() + 900, None, {}, ""
    while time.time() < deadline:
        st, sb = http("GET", f"/api/cluster/provision-bundle/{node}/status")
        try:
            apply_msg = str(json.loads(sb).get("apply_msg", ""))[:300] if st == 200 else apply_msg
        except ValueError:
            pass
        rec = self_record(node)
        h = ((rec or {}).get("host_services") or {}).get("harness") or {}
        if h.get("state") == "running" and (h.get("egress") or {}).get("state") == "enforced":
            break
        time.sleep(15)
    eg = h.get("egress") or {}
    ev.append(f"apply: {apply_msg}")
    ev.append("harness: state={} egress={}".format(h.get("state"), json.dumps(
        {k: eg.get(k) for k in ("state", "reason", "resolver", "pid_match", "ip_deny", "ip_allow", "lookup", "connect")})))
    E["node"], E["apply_msg"], E["harness_state"] = node, apply_msg, h.get("state")
    if "harness-egress=" not in apply_msg:
        ev.append("note: the applier printed no harness-egress tag (the agent's egress object below is what is judged)")
    E["egress"] = {k: eg.get(k) for k in ("state", "resolver", "pid_match", "ip_deny", "ip_allow")}
    E["want_allow"] = sorted(expected_allow(controller_url, nats_url))
    _, show = run(["systemctl", "show", "noo-harness", "-p", "IPAddressDeny", "-p", "IPAddressAllow", "-p", "ControlGroup"])
    props = dict(l.split("=", 1) for l in show.splitlines() if "=" in l)
    E["unit_deny"], E["unit_allow"] = props.get("IPAddressDeny", ""), props.get("IPAddressAllow", "")
    E["cgroup"] = props.get("ControlGroup", "")
    ev.append("unit: " + " ".join(f"{k}={props.get(k, '')}" for k in ("IPAddressDeny", "IPAddressAllow", "ControlGroup")))
    if h.get("state") != "running":
        return

    # One turn pinned to this node's chat backend, and the refused connection
    # from inside the unit's cgroup while it is served.
    show = noo_json("cluster", "show", node) or {}
    model = (show.get("running_backends") or {}).get("ollama", "")
    if not model:
        return stop("FAIL", f"{node} runs no ollama chat model to pin the turn to")
    rc, cout = run([NOO, "cluster", "class", "set", CLASS, f"{node}/ollama={model}"])
    ev.append(f"class: rc={rc} {CLASS} -> {node}/ollama={model}")
    if rc != 0:
        return stop("FAIL", "noo cluster class set failed")
    cid = str(uuid.uuid4())
    t0 = time.time()
    turn: dict = {}

    def do_turn():
        b = json.dumps({"prompt": "Count from 1 to 40, one number per line.", "model": CLASS,
                        "conversation_id": cid}).encode()
        turn["status"], turn["body"] = http("POST", "/api/inference", b, timeout=600)
    th = threading.Thread(target=do_turn, daemon=True)
    th.start()
    time.sleep(0.5)
    cg = E["cgroup"]
    # Exit 90: the probe could not join the unit's cgroup (kept apart from
    # bash's own connect failure, which is 1).
    probe = "echo $$ > \"$1/cgroup.procs\" || exit 90; exec timeout 6 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443'"
    prc, pout = run((["sudo", "-n"] if os.geteuid() else []) + ["sh", "-c", probe, "probe", f"/sys/fs/cgroup{cg}"], timeout=30)
    in_flight = th.is_alive()
    crc, _ = run(["timeout", "6", "bash", "-c", "exec 3<>/dev/tcp/1.1.1.1/443"], timeout=30)
    th.join(600)
    E["turn_status"], E["in_flight"], E["probe_rc"], E["control_rc"] = turn.get("status"), in_flight, prc, crc
    E["probe_err"] = next((l.strip() for l in pout.splitlines() if l.strip()), "")[:200]
    ev.append(f"turn: conversation={cid} HTTP {turn.get('status')} in {time.time() - t0:.1f}s")
    ev.append(f"probe from the unit's cgroup ({cg}) to 1.1.1.1:443: rc={prc} ({pout.strip()[:120]}); turn in flight={in_flight}; host control rc={crc}")
    lines, why = ae.docker("logs", "--since", f"{t0 - 5:.0f}", os.environ.get("NOO_CONTAINER_PREFIX", "noo") + "-gateway", timeout=60)
    lines = (lines or "").splitlines()
    dispatched = [l for l in lines if "harness_dispatched" in l and cid in l and f'"node":"{node}"' in l.replace(" ", "")]
    fallback = [l for l in lines if any(f in l for f in FALLBACKS) and node in l]
    E["gateway_log_unreadable"] = why if (why and not lines) else ""
    E["dispatched"], E["fallback"] = len(dispatched), [l[:160] for l in fallback[:3]]
    for l in (dispatched + fallback)[:6]:
        ev.append("gateway: " + l[:300])


ALLOW_ANY = {"0.0.0.0/0", "::/0"}
# How the probe (timeout 6 bash /dev/tcp) ends when it TRIED and the
# connection did not happen: the timeout fired (124), or bash's connect failed
# without reaching the far end (1, with one of these). "Connection refused"
# came from the far end: it is not here.
PROBE_BLOCKED_ERR = re.compile(r"connect: (Operation not permitted|Connection timed out|Network is unreachable)")


def probe_blocked(rc, err: str) -> bool:
    return rc == 124 or (rc == 1 and bool(PROBE_BLOCKED_ERR.search(err or "")))


def verdict(E: dict) -> tuple[str, str]:
    """The decision, from the evidence alone (pure: tests and mutants run it
    without a cell). PASS and NOTE exit 0; FAIL and NOT REACHED do not."""
    if E.get("leaked"):
        return "FAIL", "a secret value reached this judge's output (withheld)"
    if not E.get("systemd"):
        return "NOTE", "no systemd as PID 1 on this cell (WSL2 or a container): the hold is systemd-only"
    if not E.get("systemd_run"):
        return "NOTE", "no systemd-run: the applier's fail-safe would decline the hold here"
    if E.get("machine") not in ("x86_64", "aarch64"):
        return "NOTE", f"no harness asset for {E.get('machine')}"
    if E.get("stop"):
        return tuple(E["stop"])
    node, apply_msg = E.get("node", "?"), E.get("apply_msg", "")
    tag = re.search(r"harness-egress=\S+", apply_msg)
    if tag and tag.group(0) != "harness-egress=enforced":
        return "FAIL", "the applier did not apply the hold: " + tag.group(0)
    if E.get("harness_state") != "running":
        return "FAIL", f"the harness never ran on {node} within 15 min (state={E.get('harness_state')})"
    eg, want = E.get("egress") or {}, set(E.get("want_allow") or [])
    held = [
        ("egress.state=enforced", eg.get("state") == "enforced"),
        ("resolver=unit", eg.get("resolver") == "unit"),
        ("pid_match", eg.get("pid_match") is True),
        ("ip_deny covers any", ALLOW_ANY <= set((eg.get("ip_deny") or "").split())),
        (f"ip_allow exactly {' '.join(sorted(want))}", bool(want) and set((eg.get("ip_allow") or "").split()) == want),
        ("unit IPAddressDeny covers any", ALLOW_ANY <= set((E.get("unit_deny") or "").split())),
        ("unit IPAddressAllow = the agent's", bool(want) and set((E.get("unit_allow") or "").split()) == want),
    ]
    bad = [n for n, ok in held if not ok]
    if bad:
        return "FAIL", "the harness runs but is not held as the product holds it: " + "; ".join(bad)
    if E.get("turn_status") is None:
        return "NOT REACHED", "the turn never ran"
    if E.get("gateway_log_unreadable"):
        return "FAIL", f"the gateway log is not readable: {E['gateway_log_unreadable']}"
    if E.get("turn_status") != 200:
        return "FAIL", f"the turn answered HTTP {E.get('turn_status')}"
    if E.get("fallback"):
        return "FAIL", f"the gateway ran the turn in process: {E['fallback'][0]}"
    if E.get("dispatched") != 1:
        return "FAIL", f"{E.get('dispatched')} harness_dispatched lines name {node} and this conversation (want 1)"
    if E.get("control_rc") != 0:
        return "NOTE", "the host itself cannot reach 1.1.1.1:443, so the refused connection cannot be judged"
    if E.get("probe_rc") == 0:
        return "FAIL", "a connection from inside the harness unit's cgroup to 1.1.1.1:443 CONNECTED"
    if E.get("probe_rc") in (999, 90) or not E.get("cgroup"):
        return "FAIL", "the probe could not join the harness unit's cgroup"
    if not probe_blocked(E.get("probe_rc"), E.get("probe_err", "")):
        return "FAIL", f"the probe did not run as a connection attempt that was held (rc={E.get('probe_rc')}: {E.get('probe_err') or 'no output'})"
    if not E.get("in_flight"):
        return "FAIL", "the turn had finished before the refused-connection probe ended (not judged while served)"
    return "PASS", (f"a turn was dispatched to {node}'s harness (harness_dispatched, no in-process fallback), "
                    f"the harness is held (enforced, allow = {' '.join(sorted(want))}), and a connection from its "
                    "unit to 1.1.1.1:443 was refused while the turn was served")


def cleanup(node_hint: str, ev: list[str]) -> None:
    rc1, _ = run([NOO, "cluster", "class", "unset", CLASS])
    node = node_hint or socket.gethostname()
    rc2, _ = run([NOO, "cluster", "unplace", node, "harness"])
    ev.append(f"cleanup: class unset rc={rc1}, harness unplaced rc={rc2}")


def leaked(texts: list[str]) -> bool:
    """Whether any secret value, or its sha256, occurs in what was printed or
    written. Compared in memory; nothing is printed."""
    blob = "\n".join(texts)
    hashes = {hashlib.sha256(s.encode()).hexdigest() for s in SECRETS}
    if any(s in blob for s in SECRETS if len(s) >= 8):
        return True
    return any(hx in blob for hx in hashes)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    ev: list[str] = []
    E: dict = {}
    base = os.environ.get("RUNNER_TEMP") or tempfile.gettempdir()
    tmp = tempfile.mkdtemp(prefix="noo-he-", dir=base)
    os.chmod(tmp, 0o700)
    try:
        collect(ev, tmp, E)
    except Exception as e:  # a crash is a FAIL with its type, never a traceback with values
        E["stop"] = ["FAIL", f"the judge crashed: {type(e).__name__}"]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if any(l.startswith("place:") for l in ev):
        cleanup(E.get("node", ""), ev)
    logs = os.path.join(a.out, "logs")
    os.makedirs(logs, exist_ok=True)
    # Checked before anything is printed or written: what would go out.
    E["leaked"] = leaked(ev + [json.dumps(E)])
    if E["leaked"]:
        ev, E = ["evidence withheld: a secret value would have been written"], {"leaked": True}
    verdict_state, why = verdict(E)
    lines = ["  " + l for l in ev] + [f"HARNESS-E2E {verdict_state}: {why}"]
    if not E.get("leaked") and leaked(lines):
        ev, E = ["evidence withheld: a secret value would have been written"], {"leaked": True}
        verdict_state, why = verdict(E)
        lines = ["  " + ev[0], f"HARNESS-E2E {verdict_state}: {why}"]
    open(os.path.join(logs, "harness-e2e-evidence.log"), "w").write("\n".join(ev) + "\n")
    open(os.path.join(logs, "harness-e2e.json"), "w").write(json.dumps(E, indent=1, sort_keys=True) + "\n")
    for l in lines:
        say(l)
    say(f"HARNESS-E2E secrets: none of the agent token, the cluster secret or their sha256 is in this output ({len(SECRETS)} checked)")
    return 0 if verdict_state in ("PASS", "NOTE") else 1


if __name__ == "__main__":
    sys.exit(main())
