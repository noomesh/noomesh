// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostd

// Host facts: what this node's NEXT BOOT will do, reported before anyone
// reboots it.
//
// One controller: an `apt upgrade` installed kernel 7.1.5, the
// next boot hung at the logo, and the boot menu's fallback was a kernel with
// no NVIDIA module — the GPU embedder could not start. Every one of those was
// knowable from the running system beforehand, and none of it was reported
// anywhere. noo-hostd already runs as root on every node and already writes a
// heartbeat the agent forwards to the controller; this adds the facts to that
// heartbeat, and `noo cluster verify` judges them.
//
// Collection is Linux-only (a macOS node has no apt and no boot entries the
// mesh manages) and cached: the expensive part — hashing kernel images to
// identify the boot entries — runs at most every hostFactsInterval.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HostFacts is the `host` object inside the hostd heartbeat. Empty strings
// and nil pointers mean "could not tell", never "no".
type HostFacts struct {
	CollectedAt string `json:"collected_at"`
	// OS is runtime.GOOS. A macOS node reports only this: its facts are not
	// the mesh's to manage, and "reported, not Linux" must read differently
	// from "not reported" (an hostd older than the design).
	OS string `json:"os"`
	// RunningKernel is `uname -r`.
	RunningKernel string `json:"running_kernel"`
	// BootLoader is how DefaultKernel/FallbackKernel were read: "kernelstub"
	// (Pop!_OS systemd-boot: the EFI copies, identified by content), "grub"
	// (the /boot/vmlinuz and /boot/vmlinuz.old symlinks), or "" (unknown).
	BootLoader     string `json:"boot_loader"`
	DefaultKernel  string `json:"default_kernel"`
	FallbackKernel string `json:"fallback_kernel"`
	// NvidiaModule reports, per kernel named above, whether an NVIDIA kernel
	// module is installed for it. Present only when an NVIDIA driver package
	// is installed on this node.
	NvidiaModule map[string]bool `json:"nvidia_module,omitempty"`
	// Platform maps each installed platform package to its version; Held is
	// the subset `apt-mark showhold` lists. The set is the one the host
	// updates runbook holds (PlatformPackagePattern).
	Platform map[string]string `json:"platform,omitempty"`
	Held     []string          `json:"held,omitempty"`
	// TailscaleState is `tailscale status --json` .BackendState ("Running"
	// when healthy); TailscaleOnline is .Self.Online — false while the
	// control-plane poll is failing even though data paths still work, the
	// silent state it hit once.
	TailscaleState  string `json:"tailscale_state,omitempty"`
	TailscaleOnline *bool  `json:"tailscale_online,omitempty"`
	// NonlocalBind is net.ipv4.ip_nonlocal_bind.
	NonlocalBind *bool `json:"ip_nonlocal_bind,omitempty"`
	// BootedAt is when the kernel booted (RFC 3339, from /proc/stat btime).
	// With CollectedAt it says whether a reading was taken while the boot
	// was still bringing services up — a tailscaled in "NoState" seconds
	// after boot is starting, not stalled.
	BootedAt string `json:"booted_at,omitempty"`
	// BootPartition is the ESP and initramfs facts (bootpartition.go).
	BootPartition *BootPartition `json:"boot_partition,omitempty"`
	// Telemetry is the host-software telemetry facts (hosttelemetry.go).
	Telemetry *HostTelemetry `json:"telemetry,omitempty"`
}

// PlatformPackagePattern selects the packages the host updates runbook
// (docs/operating/runbooks/host-updates.md) holds. Keep the two identical:
// tests/test_host_facts_pattern_parity.py compares them.
var PlatformPackagePattern = regexp.MustCompile(`^(linux-(generic|image-generic|headers-generic|system76)|linux-image-rpi.*|raspberrypi-kernel|nvidia-(driver|dkms|utils|kernel-common|kernel-source)-[0-9]+|system76-driver-nvidia|nvidia-container-toolkit(-base)?|libnvidia-container(1|-tools)|docker-ce(-cli)?|docker-(compose|buildx)-plugin|containerd\.io|tailscale)$`)

var nvidiaDriverPkg = regexp.MustCompile(`^nvidia-driver-[0-9]+$`)

// hostFactsInterval bounds how often the facts are recollected.
const hostFactsInterval = 5 * time.Minute

// hostFactsRecheckInterval is the shorter life of a reading that says
// tailscale is not connected. Such a reading is often taken while a boot is
// still bringing tailscaled up (BackendState "NoState"); kept for the full
// five minutes it made `noo cluster verify` fail "tailnet control" on host2
// for five minutes after a clean reboot, and an operator
// restarted a tailscaled that was already fine. A real stall still shows,
// just from a reading at most a minute old.
const hostFactsRecheckInterval = time.Minute

// factsTTL is how long a collection may be served from the cache.
func factsTTL(f *HostFacts) time.Duration {
	if f == nil {
		return 0
	}
	if (f.TailscaleState != "" && f.TailscaleState != "Running") ||
		(f.TailscaleOnline != nil && !*f.TailscaleOnline) {
		return hostFactsRecheckInterval
	}
	return hostFactsInterval
}

// factsCache holds the last collection; the heartbeat reads it every beat.
type factsCache struct {
	mu   sync.Mutex
	at   time.Time
	last *HostFacts
}

var hostFactsCache factsCache

// currentHostFacts returns the cached facts, recollecting when stale. On a
// non-Linux host only the OS is reported.
func (e *Engine) currentHostFacts(ctx context.Context) *HostFacts {
	if runtime.GOOS != "linux" {
		f := &HostFacts{CollectedAt: nowUTC().Format(time.RFC3339), OS: runtime.GOOS}
		if runtime.GOOS == "darwin" {
			f.Telemetry = collectDarwinTelemetry(ctx, "/", e.Runner)
		}
		return f
	}
	hostFactsCache.mu.Lock()
	defer hostFactsCache.mu.Unlock()
	if hostFactsCache.last != nil && time.Since(hostFactsCache.at) < factsTTL(hostFactsCache.last) {
		return hostFactsCache.last
	}
	f := CollectHostFacts(ctx, "/", e.Runner)
	hostFactsCache.last, hostFactsCache.at = f, time.Now()
	return f
}

// CollectHostFacts reads the facts from the filesystem under root (so tests
// can point it at a fake tree) and from commands run through r.
func CollectHostFacts(ctx context.Context, root string, r Runner) *HostFacts {
	f := &HostFacts{CollectedAt: nowUTC().Format(time.RFC3339), OS: "linux"}
	f.RunningKernel = strings.TrimSpace(readFile(root, "proc/sys/kernel/osrelease"))
	f.BootedAt = bootTime(readFile(root, "proc/stat"))

	f.BootLoader, f.DefaultKernel, f.FallbackKernel = bootEntries(root)
	f.BootPartition = collectBootPartition(root, f.BootLoader, f.DefaultKernel, f.FallbackKernel)

	f.Telemetry = collectHostTelemetry(ctx, root, r)

	if r != nil {
		f.Platform = platformPackages(ctx, r)
		f.Held = heldPackages(ctx, r)
		f.TailscaleState, f.TailscaleOnline = tailscaleState(ctx, r)
	}
	if hasNvidiaDriver(f.Platform) || exists(root, "proc/driver/nvidia") {
		f.NvidiaModule = map[string]bool{}
		for _, k := range []string{f.RunningKernel, f.DefaultKernel, f.FallbackKernel} {
			if k != "" {
				f.NvidiaModule[k] = nvidiaModuleFor(root, k)
			}
		}
	}
	if v := strings.TrimSpace(readFile(root, "proc/sys/net/ipv4/ip_nonlocal_bind")); v != "" {
		b := v == "1"
		f.NonlocalBind = &b
	}
	return f
}

// bootEntries names the kernel the next boot runs and the fallback entry.
//
// Pop!_OS (kernelstub + systemd-boot) boots COPIES in the EFI partition —
// vmlinuz.efi and vmlinuz-previous.efi — and those copies are what
// `kernelstub -k` rewrites; the /boot/vmlinuz symlinks still name whatever
// the package manager installed last. Once the two disagreed
// (symlink 7.1.5, EFI copy 7.0.11 after the operator's kernelstub), so the
// EFI copies are identified by content against /boot/vmlinuz-<version>.
// Elsewhere (GRUB) the default entry is the newest kernel, which is what
// /boot/vmlinuz points at, and /boot/vmlinuz.old is the fallback.
func bootEntries(root string) (loader, def, fallback string) {
	efiDirs, _ := filepath.Glob(filepath.Join(root, "boot/efi/EFI/host8-*"))
	for _, d := range efiDirs {
		cur := filepath.Join(d, "vmlinuz.efi")
		if !isFile(cur) {
			continue
		}
		byHash := kernelsByHash(root)
		return "kernelstub", byHash[hashFile(cur)], byHash[hashFile(filepath.Join(d, "vmlinuz-previous.efi"))]
	}
	if t, err := os.Readlink(filepath.Join(root, "boot/vmlinuz")); err == nil {
		def = strings.TrimPrefix(filepath.Base(t), "vmlinuz-")
		if t2, err := os.Readlink(filepath.Join(root, "boot/vmlinuz.old")); err == nil {
			fallback = strings.TrimPrefix(filepath.Base(t2), "vmlinuz-")
		}
		return "grub", def, fallback
	}
	return "", "", ""
}

// kernelsByHash maps the sha256 of every /boot/vmlinuz-<version> to its
// version. Cached by (path, size, mtime): these are 10–20 MB files.
func kernelsByHash(root string) map[string]string {
	out := map[string]string{}
	imgs, _ := filepath.Glob(filepath.Join(root, "boot/vmlinuz-*"))
	for _, p := range imgs {
		if h := hashFile(p); h != "" {
			out[h] = strings.TrimPrefix(filepath.Base(p), "vmlinuz-")
		}
	}
	return out
}

type hashKey struct {
	path  string
	size  int64
	mtime int64
}

var (
	hashMu    sync.Mutex
	hashCache = map[hashKey]string{}
)

func hashFile(p string) string {
	st, err := os.Stat(p)
	if err != nil || !st.Mode().IsRegular() {
		return ""
	}
	k := hashKey{p, st.Size(), st.ModTime().UnixNano()}
	hashMu.Lock()
	if h, ok := hashCache[k]; ok {
		hashMu.Unlock()
		return h
	}
	hashMu.Unlock()
	fh, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer fh.Close()
	h := sha256.New()
	if _, err := io.Copy(h, fh); err != nil {
		return ""
	}
	sum := hex.EncodeToString(h.Sum(nil))
	hashMu.Lock()
	hashCache[k] = sum
	hashMu.Unlock()
	return sum
}

// nvidiaModuleFor reports whether an NVIDIA kernel module is installed for
// kernel k, in any of the places DKMS and the distro packages put it.
//
// Ubuntu's prebuilt packages (linux-modules-nvidia-<ver>-<kernel>) install
// under the VERSIONED directory kernel/nvidia-<ver>/, not kernel/nvidia/.
// The exact name missed it, so every prebuilt-driver box reported "the next
// boot has no NVIDIA module" for a kernel whose module was installed —
// a GPU host, with linux-modules-nvidia-580-7.0.0-34-generic
// present. The glob covers both spellings.
func nvidiaModuleFor(root, k string) bool {
	for _, dir := range []string{"updates/dkms", "kernel/drivers/video", "extra", "updates", "kernel/nvidia*"} {
		matches, _ := filepath.Glob(filepath.Join(root, "lib/modules", k, dir, "nvidia.ko*"))
		if len(matches) > 0 {
			return true
		}
	}
	return false
}

func hasNvidiaDriver(platform map[string]string) bool {
	for p := range platform {
		if nvidiaDriverPkg.MatchString(p) {
			return true
		}
	}
	return false
}

func platformPackages(ctx context.Context, r Runner) map[string]string {
	rc, out := r.Capture(ctx, "", "dpkg-query", "-W", "-f=${Package}\t${Version}\n")
	if rc != 0 {
		return nil
	}
	pk := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		name, ver, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if ok && PlatformPackagePattern.MatchString(name) {
			pk[name] = ver
		}
	}
	if len(pk) == 0 {
		return nil
	}
	return pk
}

func heldPackages(ctx context.Context, r Runner) []string {
	rc, out := r.Capture(ctx, "", "apt-mark", "showhold")
	if rc != 0 {
		return nil
	}
	var held []string
	for _, line := range strings.Split(out, "\n") {
		if s := strings.TrimSpace(line); s != "" {
			held = append(held, s)
		}
	}
	sort.Strings(held)
	return held
}

// bootTime reads the `btime <unix seconds>` line of /proc/stat as RFC 3339;
// "" when it is absent or unreadable.
func bootTime(procStat string) string {
	for _, line := range strings.Split(procStat, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "btime" {
			secs, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil || secs <= 0 {
				return ""
			}
			return time.Unix(secs, 0).UTC().Format(time.RFC3339)
		}
	}
	return ""
}

func tailscaleState(ctx context.Context, r Runner) (string, *bool) {
	rc, out := r.Capture(ctx, "", "tailscale", "status", "--json")
	if rc != 0 || strings.TrimSpace(out) == "" {
		return "", nil
	}
	var st struct {
		BackendState string
		Self         *struct{ Online bool }
	}
	if json.Unmarshal([]byte(out), &st) != nil {
		return "", nil
	}
	if st.Self == nil {
		return st.BackendState, nil
	}
	online := st.Self.Online
	return st.BackendState, &online
}

func readFile(root, rel string) string {
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		return ""
	}
	return string(b)
}

func exists(root, rel string) bool {
	_, err := os.Stat(filepath.Join(root, rel))
	return err == nil
}

func isFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}
