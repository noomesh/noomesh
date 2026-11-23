# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""prep-host never creates a data root that a boot-time mount would hide.

prep-host creates a missing data root and hf-cache, models and ollama under
it. On a machine whose storage mount is not there at enrollment, that made
the directory on the root filesystem: at the next boot the mount hid it, and
until then the node filled the root disk.

The rule is the node agent's (node-agent-go/internal/dataroots/fsid.go): if
the longest boot-time mount covering the path (/etc/fstab without `noauto`
unless also `x-systemd.automount`, or an ENABLED, unmasked .mount/.automount
unit) is not mounted now, enrollment refuses. An automount is touched once
(`timeout 5 stat`) before it is called missing. "Cannot tell" never refuses.

The block between `# >>> data-root-mount-guard` and `# <<< data-root-mount-
guard` runs for real against fake fstab, unit directories and mountinfo,
passed as the function's optional arguments; `timeout` is shimmed so a test
can make the touch mount an automount.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREP = ROOT / "scripts" / "prep-host.sh"

ROOT_LINE = "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n"


def _block() -> str:
    src = PREP.read_text()
    m = re.search(
        r"^# >>> data-root-mount-guard[^\n]*\n(.*?)^# <<< data-root-mount-guard$", src, re.S | re.M
    )
    assert m, "prep-host.sh has no '# >>> data-root-mount-guard' ... '# <<< data-root-mount-guard' block"
    return m.group(1)


def _mount_line(where: str, fstype: str = "ext4", source: str = "/dev/sdb1") -> str:
    return f"36 1 8:17 / {where} rw,relatime shared:2 - {fstype} {source} rw\n"


# timeout as the guard calls it: logged; when $MI_AFTER is set, the "touch"
# mounts the automount (the mount table becomes $MI_AFTER).
TIMEOUT_SHIM = r"""#!/bin/sh
printf '%s\n' "$*" >> "$TIMEOUT_LOG"
[ -n "${MI_AFTER:-}" ] && cp "$MI_AFTER" "$MI_NOW"
exit 0
"""


class Box:
    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.fstab = tmp / "fstab"
        self.fstab.write_text("UUID=1111 / ext4 defaults 0 1\n")
        self.mountinfo = tmp / "mountinfo"
        self.mountinfo.write_text(ROOT_LINE)
        self.etc_units = tmp / "etc-systemd-system"
        self.etc_units.mkdir()
        self.gen_units = tmp / "run-systemd-generator"
        self.gen_units.mkdir()
        self.unit_dirs = f"{self.etc_units} {self.gen_units}"
        self.mi_after: Path | None = None
        self.bindir = tmp / "bin"
        self.bindir.mkdir()
        shim = self.bindir / "timeout"
        shim.write_text(TIMEOUT_SHIM)
        shim.chmod(0o755)
        self.timeout_log = tmp / "timeout.log"
        self.timeout_log.write_text("")

    def unit(self, d: Path, name: str, body: str, enabled: bool = True) -> Path:
        f = d / name
        f.write_text(body)
        if enabled:
            wants = d / "local-fs.target.requires"
            wants.mkdir(exist_ok=True)
            (wants / name).symlink_to(f)
        return f

    def run(self, data_root: Path, fstab: Path | None = None, mountinfo: Path | None = None):
        """The guard, then prep-host's creation of the root (stood in by
        mkdir) only when the guard lets it through, as the call site does."""
        script = (
            "set -eu\nsay() { printf 'prep-host: %s\\n' \"$*\"; }\n"
            + _block()
            + 'data_root_mount_guard "$DR" "$FSTAB" "$MI" "$UDIRS" || exit 1\nmkdir -p "$DR"\n'
        )
        env = dict(os.environ)
        env.update(
            PATH=f"{self.bindir}:{env.get('PATH', '/usr/bin:/bin')}",
            DR=str(data_root),
            FSTAB=str(fstab or self.fstab),
            MI=str(mountinfo or self.mountinfo),
            MI_NOW=str(mountinfo or self.mountinfo),
            UDIRS=self.unit_dirs,
            TIMEOUT_LOG=str(self.timeout_log),
            MI_AFTER=str(self.mi_after) if self.mi_after else "",
        )
        return subprocess.run(
            [shutil.which("bash") or "/bin/bash", "-c", script], env=env, capture_output=True, text=True
        )

    def touched(self) -> list[str]:
        return [line for line in self.timeout_log.read_text().splitlines() if line]


def _refusal(path: Path, where: Path, by: str) -> str:
    return (
        f"prep-host: FATAL: {path} is under the mount {where} declared in {by}, which is not mounted: "
        f"mount it (mount {where}, check findmnt {where}), then re-run enrollment. "
        "Not creating the directory: the mount would hide it.\n"
    )


def test_covered_and_not_mounted_refuses_and_creates_nothing(tmp_path: Path) -> None:
    box = Box(tmp_path)
    where = tmp_path / "mnt" / "data"
    where.mkdir(parents=True)  # the empty mount point on the root disk
    box.fstab.write_text(box.fstab.read_text() + f"UUID=2222 {where} ext4 defaults,nofail 0 2\n")
    dr = where / "noo"
    r = box.run(dr)
    assert r.returncode == 1, r
    assert r.stdout == _refusal(dr, where, str(box.fstab))
    assert not dr.exists()
    assert box.touched() == [], "a plain fstab mount is not touched"


def test_covered_and_mounted_creates(tmp_path: Path) -> None:
    box = Box(tmp_path)
    where = tmp_path / "mnt" / "data"
    box.fstab.write_text(box.fstab.read_text() + f"UUID=2222 {where} ext4 defaults 0 2\n")
    box.mountinfo.write_text(ROOT_LINE + _mount_line(str(where)))
    dr = where / "noo"
    r = box.run(dr)
    assert r.returncode == 0, r
    assert r.stdout == "", "a mounted root prints nothing new"
    assert dr.is_dir()


def test_the_longest_covering_mount_decides(tmp_path: Path) -> None:
    """/mnt is mounted, /mnt/data (the one that holds the root) is not."""
    box = Box(tmp_path)
    outer, where = tmp_path / "mnt", tmp_path / "mnt" / "data"
    box.fstab.write_text(
        box.fstab.read_text() + f"UUID=2 {outer} ext4 defaults 0 2\nUUID=3 {where} xfs defaults 0 2\n"
    )
    box.mountinfo.write_text(ROOT_LINE + _mount_line(str(outer)))
    dr = where / "noo"
    r = box.run(dr)
    assert r.returncode == 1 and r.stdout == _refusal(dr, where, str(box.fstab)), r
    assert not dr.exists()


def test_not_covered_creates(tmp_path: Path) -> None:
    box = Box(tmp_path)
    box.fstab.write_text(box.fstab.read_text() + f"UUID=2222 {tmp_path / 'elsewhere'} ext4 defaults 0 2\n")
    dr = tmp_path / "var" / "lib" / "noo"
    r = box.run(dr)
    assert r.returncode == 0 and r.stdout == "", r
    assert dr.is_dir()


def test_noauto_creates(tmp_path: Path) -> None:
    box = Box(tmp_path)
    where = tmp_path / "mnt" / "usb"
    box.fstab.write_text(box.fstab.read_text() + f"/dev/sdc1 {where} ext4 noauto,user 0 0\n")
    dr = where / "noo"
    r = box.run(dr)
    assert r.returncode == 0 and r.stdout == "", r
    assert dr.is_dir()


def test_noauto_automount_not_mounted_after_the_touch_refuses(tmp_path: Path) -> None:
    box = Box(tmp_path)
    where = tmp_path / "srv" / "nas"
    box.fstab.write_text(
        box.fstab.read_text() + f"nas:/export {where} nfs noauto,x-systemd.automount,_netdev 0 0\n"
    )
    dr = where / "noo"
    r = box.run(dr)
    assert r.returncode == 1 and r.stdout == _refusal(dr, where, str(box.fstab)), r
    assert box.touched() == [f"5 stat {dr}/."], "an automount is touched once, bounded"
    assert not dr.exists()


def test_noauto_automount_mounted_after_the_touch_creates(tmp_path: Path) -> None:
    box = Box(tmp_path)
    where = tmp_path / "srv" / "nas"
    box.fstab.write_text(
        box.fstab.read_text() + f"nas:/export {where} nfs noauto,x-systemd.automount,_netdev 0 0\n"
    )
    # Before the touch: only the autofs trap. After: the real mount on it.
    box.mountinfo.write_text(ROOT_LINE + _mount_line(str(where), "autofs", "systemd-1"))
    after = tmp_path / "mountinfo.after"
    after.write_text(box.mountinfo.read_text() + _mount_line(str(where), "nfs4", "nas:/export"))
    box.mi_after = after
    dr = where / "noo"
    r = box.run(dr)
    assert r.returncode == 0 and r.stdout == "", r
    assert len(box.touched()) == 1
    assert dr.is_dir()


def test_an_enabled_mount_unit_not_mounted_refuses(tmp_path: Path) -> None:
    box = Box(tmp_path)
    where = tmp_path / "data"
    f = box.unit(box.etc_units, "data.mount", f"[Mount]\nWhat=/dev/sdb1\nWhere={where}\nType=ext4\n")
    dr = where / "noo"
    r = box.run(dr)
    assert r.returncode == 1 and r.stdout == _refusal(dr, where, f"the systemd unit {f}"), r
    assert not dr.exists()


def test_a_masked_unit_creates(tmp_path: Path) -> None:
    box = Box(tmp_path)
    where = tmp_path / "data"
    (box.etc_units / "data.mount").symlink_to(os.devnull)
    wants = box.etc_units / "local-fs.target.requires"
    wants.mkdir()
    (wants / "data.mount").symlink_to(box.etc_units / "data.mount")
    # A generated unit for the same path, masked as an empty file.
    box.unit(box.gen_units, "data.mount", "")
    dr = where / "noo"
    r = box.run(dr)
    assert r.returncode == 0 and r.stdout == "", r
    assert dr.is_dir()


def test_a_disabled_unit_creates(tmp_path: Path) -> None:
    box = Box(tmp_path)
    where = tmp_path / "data"
    box.unit(box.etc_units, "data.mount", f"[Mount]\nWhat=/dev/sdb1\nWhere={where}\n", enabled=False)
    dr = where / "noo"
    r = box.run(dr)
    assert r.returncode == 0 and r.stdout == "", r
    assert dr.is_dir()


def test_unreadable_fstab_creates_with_one_note(tmp_path: Path) -> None:
    box = Box(tmp_path)
    where = tmp_path / "data"
    box.unit(box.etc_units, "data.mount", f"[Mount]\nWhat=/dev/sdb1\nWhere={where}\n")
    missing = tmp_path / "no-fstab"
    dr = where / "noo"
    r = box.run(dr, fstab=missing)
    assert r.returncode == 0, r
    assert r.stdout == (
        f"prep-host: NOTE: cannot read {missing}: not checking whether a boot-time mount covers {dr}\n"
    )
    assert dr.is_dir()


def test_unreadable_mountinfo_creates_with_one_note(tmp_path: Path) -> None:
    box = Box(tmp_path)
    where = tmp_path / "data"
    box.fstab.write_text(box.fstab.read_text() + f"UUID=2 {where} ext4 defaults 0 2\n")
    missing = tmp_path / "no-mountinfo"
    dr = where / "noo"
    r = box.run(dr, mountinfo=missing)
    assert r.returncode == 0, r
    assert r.stdout == (
        f"prep-host: NOTE: cannot read {missing}: not checking whether the mount {where} over {dr} is mounted\n"
    )
    assert dr.is_dir()


def test_guard_runs_before_the_data_root_is_created() -> None:
    src = PREP.read_text()
    call = src.find('\ndata_root_mount_guard "$NOO_DATA_ROOT" || exit 1\n')
    assert call != -1, "prep-host must call data_root_mount_guard on the data root and stop when it refuses"
    create = src.find('\ndata_dir "$NOO_DATA_ROOT" noo-agent:noo-agent\n')
    assert create != -1, "prep-host's creation of the data root moved; update this test"
    assert call < create, "the guard must run BEFORE the data root is created"
    assert call > src.find('\nsay "data root: $NOO_DATA_ROOT"\n'), "the guard checks the root prep settled on"
    # Nothing between the guard and data_dir creates the root another way.
    between = src[call:create]
    assert not re.search(r"^\s*(install -d|mkdir)[^\n]*NOO_DATA_ROOT", between, re.M), between


def test_check_mode_runs_the_guard_before_the_token_is_spent() -> None:
    """`noo enroll` runs PREP_CHECK=1 before it redeems the single-use token;
    a refusal there is a FAIL (exit 1), so the token is not spent on a host
    whose prep would refuse."""
    src = PREP.read_text()
    check = re.search(r'^if \[ "\$\{PREP_CHECK:-\}" = 1 \]; then\n(.*?)^fi$', src, re.S | re.M)
    assert check, "prep-host.sh has no check-mode block"
    body = check.group(1)
    assert 'if ! DRMG_OUT="$(data_root_mount_guard "$NOO_DATA_ROOT")"; then pc_fail "${DRMG_OUT#prep-host: FATAL: }"' in body
    assert src.index("\ndata_root_mount_guard() {") < check.start(), "the guard must be defined before check mode"
