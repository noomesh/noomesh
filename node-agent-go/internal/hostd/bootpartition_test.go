// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostd

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func fakeESP(t *testing.T, total, free uint64) {
	t.Helper()
	old := statfsBytes
	statfsBytes = func(p string) (uint64, uint64, bool) {
		if strings.HasSuffix(p, "boot/efi") {
			return total, free, true
		}
		return 0, 0, false
	}
	t.Cleanup(func() { statfsBytes = old })
}

const (
	k705 = "7.0.11-76070011-generic"
	k715 = "7.1.5-76070105-generic"
)

// The incident layout: ESP full, 7.1.5's initramfs is outsized and its ESP
// copy is truncated, its DKMS modules are uncompressed while 7.0.11's are not.
func incidentTree(t *testing.T) string {
	root, _ := popOSAfterRecovery(t)
	efi := "boot/efi/EFI/host8-0123abcd"
	// Make 7.1.5 the kernelstub default (its EFI copy), 7.0.11 the previous.
	write(t, root, efi+"/vmlinuz.efi", "kernel 7.1.5")
	write(t, root, efi+"/vmlinuz-previous.efi", "kernel 7.0.11")
	write(t, root, "boot/initrd.img-"+k715, strings.Repeat("x", 3150))
	write(t, root, "boot/initrd.img-"+k705, strings.Repeat("y", 1400))
	write(t, root, efi+"/initrd.img", strings.Repeat("x", 2000)) // truncated
	write(t, root, efi+"/initrd.img-previous", strings.Repeat("y", 1400))
	write(t, root, "lib/modules/"+k715+"/updates/dkms/nvidia.ko", "m")
	return root
}

func TestBootPartitionReadsTheEspAndATruncatedNextBootInitrd(t *testing.T) {
	fakeESP(t, 511, 0)
	root := incidentTree(t)
	f := CollectHostFacts(context.Background(), root, &fakeRunner{})
	bp := f.BootPartition
	if bp == nil || bp.Mount != "/boot/efi" || bp.TotalBytes != 511 || bp.FreeBytes == nil || *bp.FreeBytes != 0 || bp.UsedBytes == nil || *bp.UsedBytes != 511 {
		t.Fatalf("esp = %+v (a full ESP must read as full)", bp)
	}
	if f.DefaultKernel != k715 {
		t.Fatalf("default = %q", f.DefaultKernel)
	}
	if bp.InitrdBytes[k715] != 3150 || bp.InitrdBytes[k705] != 1400 {
		t.Fatalf("initrd sizes = %v", bp.InitrdBytes)
	}
	if bp.ESPInitrdBytes[k715] != 2000 || bp.ESPInitrdBytes[k705] != 1400 {
		t.Fatalf("esp copies = %v (default <- initrd.img, fallback <- initrd.img-previous)", bp.ESPInitrdBytes)
	}
}

func TestUncompressedDkmsModulesAreFlaggedPerKernel(t *testing.T) {
	fakeESP(t, 511, 300)
	f := CollectHostFacts(context.Background(), incidentTree(t), &fakeRunner{})
	c := f.BootPartition.DKMSCompressed
	if c[k715] || !c[k705] {
		t.Fatalf("dkms_compressed = %v; want 7.1.5 false, 7.0.11 true", c)
	}
}

// Unreadable is absent, never zero: no statfs, no ESP dir, no initrds.
func TestUnreadableBootPartitionClaimsNothing(t *testing.T) {
	root := t.TempDir()
	write(t, root, "proc/sys/kernel/osrelease", "6.1.0-rpi\n")
	f := CollectHostFacts(context.Background(), root, &fakeRunner{})
	bp := f.BootPartition
	if bp == nil {
		t.Fatal("the object itself must be present so verify can tell 'not read' from 'older agent'")
	}
	if bp.Mount != "" || bp.TotalBytes != 0 || bp.InitrdBytes != nil || bp.ESPInitrdBytes != nil || bp.DKMSCompressed != nil {
		t.Fatalf("guessed boot partition facts: %+v", bp)
	}
}

// A full ESP must serialise free_bytes:0, not drop it (omitempty made verify
// say "unknown free space" about a 100%-full ESP).
func TestAFullEspReportsZeroFreeNotAbsent(t *testing.T) {
	fakeESP(t, 511, 0)
	f := CollectHostFacts(context.Background(), incidentTree(t), &fakeRunner{})
	b, _ := json.Marshal(f.BootPartition)
	if !strings.Contains(string(b), `"free_bytes":0`) {
		t.Fatalf("json = %s", b)
	}
	fakeNoESP := func() { statfsBytes = func(string) (uint64, uint64, bool) { return 0, 0, false } }
	fakeNoESP()
	f = CollectHostFacts(context.Background(), incidentTree(t), &fakeRunner{})
	b, _ = json.Marshal(f.BootPartition)
	if strings.Contains(string(b), "free_bytes") {
		t.Fatalf("unread ESP must not claim free space: %s", b)
	}
}

func TestEntriesAndTheEffectiveDefault(t *testing.T) {
	fakeESP(t, 511, 0)
	root := incidentTree(t)
	efi := "boot/efi/EFI/host8-0123abcd"
	write(t, root, "boot/efi/loader/entries/host8-current.conf",
		"title Pop!_OS\nlinux /EFI/host8-0123abcd/vmlinuz.efi\ninitrd /EFI/host8-0123abcd/initrd.img\n")
	write(t, root, "boot/efi/loader/entries/host8-oldkern.conf",
		"title Pop!_OS\nlinux /EFI/host8-0123abcd/vmlinuz-previous.efi\ninitrd /EFI/host8-0123abcd/initrd.img-previous\n")
	write(t, root, "boot/efi/loader/loader.conf", "default host8-current\ntimeout 3\n")
	_ = efi
	bp := CollectHostFacts(context.Background(), root, &fakeRunner{}).BootPartition
	if bp.DefaultEntry != "host8-current.conf" || bp.DefaultSource != "loader.conf" {
		t.Fatalf("default = %q from %q", bp.DefaultEntry, bp.DefaultSource)
	}
	by := map[string]BootEntry{}
	for _, e := range bp.Entries {
		by[e.Name] = e
	}
	if cur := by["host8-current.conf"]; cur.Kernel != k715 || cur.Intact {
		t.Fatalf("current = %+v (truncated copy is not intact)", cur)
	}
	if old := by["host8-oldkern.conf"]; old.Kernel != k705 || !old.Intact {
		t.Fatalf("oldkern = %+v", old)
	}

	// The EFI variable overrides loader.conf: 4 attr bytes + UTF-16LE.
	v := []byte{7, 0, 0, 0}
	for _, r := range "host8-oldkern.conf" {
		v = append(v, byte(r), 0)
	}
	v = append(v, 0, 0)
	write(t, root, "sys/firmware/efi/efivars/LoaderEntryDefault-"+loaderVendorGUID, string(v))
	bp = CollectHostFacts(context.Background(), root, &fakeRunner{}).BootPartition
	if bp.DefaultEntry != "host8-oldkern.conf" || bp.DefaultSource != "efi-var" {
		t.Fatalf("default = %q from %q; the EFI var must beat loader.conf", bp.DefaultEntry, bp.DefaultSource)
	}
}
