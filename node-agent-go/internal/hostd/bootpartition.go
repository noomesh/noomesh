// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostd

// Boot-partition facts (the controller): a reboot looped because
// the EFI System Partition was 100% full. Kernel 7.1.5's DKMS NVIDIA modules
// were built UNCOMPRESSED, so its initramfs was 315 MB against ~140 MB for
// the others; kernelstub's copy of it to the ESP was truncated and the boot
// died before any journal. `noo cluster verify` had only checked that an
// NVIDIA module existed. These facts let it see the ESP, the initramfs sizes
// and the truncated copy before the reboot.
//
// Reads that fail leave the field absent ("could not tell"), never zero.

import (
	"os"
	"path/filepath"
	"strings"
)

// BootPartition is `host.boot_partition`. The object is always present on a
// Linux report from an agent that knows these facts; an OLD agent omits the
// key entirely, which is how `verify` tells "older agent" from "not read".
type BootPartition struct {
	// Mount is the ESP mount point ("/boot/efi", "/efi"); "" when none is
	// mounted/readable, and then the sizes are absent too.
	Mount      string `json:"mount,omitempty"`
	TotalBytes uint64 `json:"total_bytes,omitempty"`
	// UsedBytes/FreeBytes are pointers: a FULL ESP has 0 free, and omitempty
	// on a plain uint64 dropped it, so verify said "unknown free space" about
	// the very partition that was 100% full . Absent
	// still means "could not read".
	UsedBytes *uint64 `json:"used_bytes,omitempty"`
	FreeBytes *uint64 `json:"free_bytes,omitempty"`
	// InitrdBytes is the size of /boot/initrd.img-<kernel> per installed
	// kernel. ESPInitrdBytes is the size of the copy kernelstub put in the ESP
	// for the kernels the boot menu names (default, fallback); absent where the
	// ESP is unreadable or the layout is not kernelstub's.
	InitrdBytes    map[string]int64 `json:"initrd_bytes,omitempty"`
	ESPInitrdBytes map[string]int64 `json:"esp_initrd_bytes,omitempty"`
	// DKMSCompressed says, per installed kernel with DKMS modules, whether
	// they are compressed (.ko.zst/.xz/.gz). false = at least one bare .ko.
	DKMSCompressed map[string]bool `json:"dkms_compressed,omitempty"`
	// Entries are the ESP's systemd-boot entries (loader/entries/*.conf), each
	// resolved to the kernel version its ESP kernel image holds and whether its
	// ESP initrd is intact (as large as /boot's). verify names the entry to pin
	// with `bootctl set-default` from these.
	Entries []BootEntry `json:"entries,omitempty"`
	// DefaultEntry is the entry the loader boots by default and DefaultSource
	// says where that came from: "efi-var" (LoaderEntryDefault, which
	// OVERRIDES loader.conf) or "loader.conf".
	DefaultEntry  string `json:"default_entry,omitempty"`
	DefaultSource string `json:"default_entry_source,omitempty"`
}

// BootEntry is one loader entry on the ESP.
type BootEntry struct {
	Name           string `json:"name"` // file name, e.g. "host8-oldkern.conf"
	Kernel         string `json:"kernel,omitempty"`
	ESPInitrdBytes int64  `json:"esp_initrd_bytes,omitempty"`
	Intact         bool   `json:"intact"`
}

const loaderVendorGUID = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"

// readEntryDefault returns the effective default entry: the EFI variable
// LoaderEntryDefault when set (it beats loader.conf), else loader.conf's
// `default` line. Names are normalised to carry ".conf".
func readEntryDefault(root, espDir string) (name, source string) {
	norm := func(n string) string {
		n = strings.TrimSpace(strings.TrimRight(n, "\x00"))
		if n != "" && !strings.HasSuffix(n, ".conf") {
			n += ".conf"
		}
		return n
	}
	if b, err := os.ReadFile(filepath.Join(root, "sys/firmware/efi/efivars/LoaderEntryDefault-"+loaderVendorGUID)); err == nil && len(b) > 4 {
		// 4 attribute bytes, then UTF-16LE.
		var rs []rune
		for i := 4; i+1 < len(b); i += 2 {
			rs = append(rs, rune(uint16(b[i])|uint16(b[i+1])<<8))
		}
		if n := norm(string(rs)); n != "" {
			return n, "efi-var"
		}
	}
	if b, err := os.ReadFile(filepath.Join(espDir, "loader/loader.conf")); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Fields(l)
			if len(f) == 2 && f[0] == "default" {
				return norm(f[1]), "loader.conf"
			}
		}
	}
	return "", ""
}

func readBootEntries(root, espDir string, bootInitrd map[string]int64) []BootEntry {
	confs, _ := filepath.Glob(filepath.Join(espDir, "loader/entries/*.conf"))
	byHash := kernelsByHash(root)
	var out []BootEntry
	for _, c := range confs {
		b, err := os.ReadFile(c)
		if err != nil {
			continue
		}
		e := BootEntry{Name: filepath.Base(c)}
		var initrdPath string
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Fields(l)
			if len(f) < 2 {
				continue
			}
			switch f[0] {
			case "linux":
				e.Kernel = byHash[hashFile(filepath.Join(espDir, f[1]))]
			case "initrd":
				initrdPath = f[1]
			}
		}
		if st, err := os.Stat(filepath.Join(espDir, initrdPath)); initrdPath != "" && err == nil && st.Mode().IsRegular() {
			e.ESPInitrdBytes = st.Size()
			if boot, ok := bootInitrd[e.Kernel]; ok && e.Kernel != "" {
				e.Intact = st.Size() >= boot
			}
		}
		out = append(out, e)
	}
	return out
}

// statfsBytes is the filesystem size of path; a var so tests can stand in a
// fake ESP (statfs on a temp dir would describe the test host's disk).
// Platforms without an implementation report "could not tell".
var statfsBytes = func(string) (total, free uint64, ok bool) { return 0, 0, false }

func collectBootPartition(root, loader, def, fallback string) *BootPartition {
	bp := &BootPartition{}
	for _, mp := range []string{"boot/efi", "efi"} {
		if total, free, ok := statfsBytes(filepath.Join(root, mp)); ok && total > 0 {
			bp.Mount = "/" + mp
			bp.TotalBytes = total
			bp.FreeBytes = &free
			if total >= free {
				used := total - free
				bp.UsedBytes = &used
			}
			break
		}
	}
	inits, _ := filepath.Glob(filepath.Join(root, "boot/initrd.img-*"))
	for _, p := range inits {
		// A symlink-free regular file only: /boot/initrd.img is a symlink and
		// does not match this glob, but a dangling one must not read as 0.
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			if bp.InitrdBytes == nil {
				bp.InitrdBytes = map[string]int64{}
			}
			bp.InitrdBytes[strings.TrimPrefix(filepath.Base(p), "initrd.img-")] = st.Size()
		}
	}
	if loader == "kernelstub" {
		efiDirs, _ := filepath.Glob(filepath.Join(root, "boot/efi/EFI/host8-*"))
		for _, d := range efiDirs {
			if !isFile(filepath.Join(d, "vmlinuz.efi")) {
				continue
			}
			for _, c := range []struct{ kernel, file string }{{def, "initrd.img"}, {fallback, "initrd.img-previous"}} {
				if c.kernel == "" {
					continue
				}
				if st, err := os.Stat(filepath.Join(d, c.file)); err == nil && st.Mode().IsRegular() {
					if bp.ESPInitrdBytes == nil {
						bp.ESPInitrdBytes = map[string]int64{}
					}
					bp.ESPInitrdBytes[c.kernel] = st.Size()
				}
			}
			break
		}
	}
	espDir := filepath.Join(root, "boot/efi")
	if bp.Mount != "" {
		espDir = filepath.Join(root, bp.Mount)
	}
	bp.DefaultEntry, bp.DefaultSource = readEntryDefault(root, espDir)
	bp.Entries = readBootEntries(root, espDir, bp.InitrdBytes)
	mods, _ := filepath.Glob(filepath.Join(root, "lib/modules/*/updates/dkms"))
	for _, d := range mods {
		files, _ := filepath.Glob(filepath.Join(d, "*.ko*"))
		if len(files) == 0 {
			continue
		}
		compressed := true
		for _, f := range files {
			if strings.HasSuffix(f, ".ko") {
				compressed = false
			}
		}
		if bp.DKMSCompressed == nil {
			bp.DKMSCompressed = map[string]bool{}
		}
		bp.DKMSCompressed[filepath.Base(filepath.Dir(filepath.Dir(d)))] = compressed
	}
	return bp
}
