// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// write creates root/rel with content, making parents.
func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The host8 controller after a kernel-hang recovery: the
// package symlink names 7.1.5 (the kernel that hung), kernelstub's EFI copy
// is 7.0.11 (what actually boots), the previous EFI copy is 6.18.7 — which
// has no NVIDIA module. Every fact the recovery needed, from a fake tree.
func popOSAfterRecovery(t *testing.T) (string, *fakeRunner) {
	root := t.TempDir()
	write(t, root, "proc/sys/kernel/osrelease", "7.0.11-76070011-generic\n")
	write(t, root, "proc/sys/net/ipv4/ip_nonlocal_bind", "1\n")
	write(t, root, "boot/vmlinuz-7.1.5-76070105-generic", "kernel 7.1.5")
	write(t, root, "boot/vmlinuz-7.0.11-76070011-generic", "kernel 7.0.11")
	write(t, root, "boot/vmlinuz-6.18.7-76061807-generic", "kernel 6.18.7")
	if err := os.Symlink("vmlinuz-7.1.5-76070105-generic", filepath.Join(root, "boot/vmlinuz")); err != nil {
		t.Fatal(err)
	}
	efi := "boot/efi/EFI/host8-0123abcd"
	write(t, root, efi+"/vmlinuz.efi", "kernel 7.0.11")
	write(t, root, efi+"/vmlinuz-previous.efi", "kernel 6.18.7")
	write(t, root, "lib/modules/7.0.11-76070011-generic/updates/dkms/nvidia.ko.zst", "m")
	write(t, root, "lib/modules/7.1.5-76070105-generic/updates/dkms/nvidia.ko.zst", "m")
	write(t, root, "lib/modules/6.18.7-76061807-generic/kernel/fs/ext4.ko", "m")
	r := &fakeRunner{stdout: map[string]string{
		"dpkg-query": "linux-system76\t7.1.5\nnvidia-driver-580\t580.173.02\ndocker-ce\t5:29.8.1\n" +
			"tailscale\t1.102.4\nvim\t2:9.1\nlibc6\t2.39\n",
		"apt-mark showhold": "tailscale\nlinux-system76\nnvidia-driver-580\n",
		"tailscale status":  `{"BackendState":"Running","Self":{"Online":true}}`,
	}}
	return root, r
}

func TestKernelstubEntriesAreIdentifiedByContentNotBySymlink(t *testing.T) {
	root, r := popOSAfterRecovery(t)
	f := CollectHostFacts(context.Background(), root, r)
	if f.BootLoader != "kernelstub" {
		t.Fatalf("loader = %q", f.BootLoader)
	}
	if f.RunningKernel != "7.0.11-76070011-generic" {
		t.Fatalf("running = %q", f.RunningKernel)
	}
	if f.DefaultKernel != "7.0.11-76070011-generic" {
		t.Fatalf("default = %q — the /boot/vmlinuz symlink (7.1.5) is not what boots", f.DefaultKernel)
	}
	if f.FallbackKernel != "6.18.7-76061807-generic" {
		t.Fatalf("fallback = %q", f.FallbackKernel)
	}
}

func TestTheFallbackWithNoNvidiaModuleIsReported(t *testing.T) {
	root, r := popOSAfterRecovery(t)
	f := CollectHostFacts(context.Background(), root, r)
	if !f.NvidiaModule["7.0.11-76070011-generic"] {
		t.Fatal("the default kernel has its module")
	}
	if got, ok := f.NvidiaModule["6.18.7-76061807-generic"]; !ok || got {
		t.Fatalf("fallback module = %v (present=%v); want reported false", got, ok)
	}
}

func TestPlatformPackagesHoldsAndTailscaleAreRead(t *testing.T) {
	root, r := popOSAfterRecovery(t)
	f := CollectHostFacts(context.Background(), root, r)
	if _, ok := f.Platform["vim"]; ok {
		t.Fatal("an everyday package leaked into the platform set")
	}
	for _, p := range []string{"linux-system76", "nvidia-driver-580", "docker-ce", "tailscale"} {
		if _, ok := f.Platform[p]; !ok {
			t.Fatalf("%s missing from platform %v", p, f.Platform)
		}
	}
	if len(f.Held) != 3 || f.Held[0] != "linux-system76" {
		t.Fatalf("held = %v (sorted, three)", f.Held)
	}
	if f.TailscaleState != "Running" || f.TailscaleOnline == nil || !*f.TailscaleOnline {
		t.Fatalf("tailscale = %q %v", f.TailscaleState, f.TailscaleOnline)
	}
	if f.NonlocalBind == nil || !*f.NonlocalBind {
		t.Fatal("ip_nonlocal_bind=1 not read")
	}
}

// The silent state: data paths up, control poll failing — BackendState can
// still say Running while Self.Online is false.
func TestAnOfflineControlPlaneIsReportedEvenWhileRunning(t *testing.T) {
	root, r := popOSAfterRecovery(t)
	r.stdout["tailscale status"] = `{"BackendState":"Running","Self":{"Online":false}}`
	f := CollectHostFacts(context.Background(), root, r)
	if f.TailscaleOnline == nil || *f.TailscaleOnline {
		t.Fatal("offline control plane read as online")
	}
}

func TestGrubHostsReadTheSymlinks(t *testing.T) {
	root := t.TempDir()
	write(t, root, "proc/sys/kernel/osrelease", "6.8.0-45-generic\n")
	write(t, root, "boot/vmlinuz-6.8.0-45-generic", "a")
	write(t, root, "boot/vmlinuz-6.8.0-47-generic", "b")
	_ = os.Symlink("vmlinuz-6.8.0-47-generic", filepath.Join(root, "boot/vmlinuz"))
	_ = os.Symlink("vmlinuz-6.8.0-45-generic", filepath.Join(root, "boot/vmlinuz.old"))
	f := CollectHostFacts(context.Background(), root, &fakeRunner{})
	if f.BootLoader != "grub" || f.DefaultKernel != "6.8.0-47-generic" || f.FallbackKernel != "6.8.0-45-generic" {
		t.Fatalf("grub facts = %+v", f)
	}
	if f.NvidiaModule != nil {
		t.Fatal("no NVIDIA driver installed: the module map must be absent, not all-false")
	}
}

// Nothing readable is "could not tell" — empty, never a guess.
func TestAnUnknownBootLayoutClaimsNothing(t *testing.T) {
	root := t.TempDir()
	write(t, root, "proc/sys/kernel/osrelease", "6.1.0-rpi\n")
	f := CollectHostFacts(context.Background(), root, &fakeRunner{rc: map[string]int{"dpkg-query": 1, "apt-mark": 1, "tailscale": 1}})
	if f.BootLoader != "" || f.DefaultKernel != "" || f.FallbackKernel != "" {
		t.Fatalf("guessed boot entries: %+v", f)
	}
	if f.Platform != nil || f.Held != nil || f.TailscaleOnline != nil {
		t.Fatalf("failed commands must leave fields empty: %+v", f)
	}
}

// The prebuilt path: Ubuntu's linux-modules-nvidia-<ver>-<kernel> package
// ships the module under kernel/nvidia-<ver>/, which the exact-name glob
// missed. host2 read as "no module for the next boot" with the module
// installed.
func TestPrebuiltNvidiaModuleUnderVersionedDirIsFound(t *testing.T) {
	root := t.TempDir()
	write(t, root, "lib/modules/7.0.0-34-generic/kernel/nvidia-580/nvidia.ko.zst", "m")
	if !nvidiaModuleFor(root, "7.0.0-34-generic") {
		t.Fatal("a prebuilt module under kernel/nvidia-580/ was not found")
	}
	if nvidiaModuleFor(root, "7.0.0-35-generic") {
		t.Fatal("a kernel with no module must still read as missing")
	}
}
