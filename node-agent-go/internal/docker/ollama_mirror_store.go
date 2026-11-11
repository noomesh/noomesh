// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// The docker package is unix-only already (ollama_store.go reads
// syscall.Stat_t), so this file carries no build tag of its own.

package docker

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// writeManifestNative writes a staged manifest into a NATIVE ollama's store:
// <modelsDir>/manifests/registry.ollama.ai/<ns>/<name>/<tag>.
//
// The agent may run as root (a Mac LaunchDaemon) while the store belongs to
// the operator's user, so the walk is done with directory file descriptors,
// never by path:
//   - every component from / down to modelsDir is opened in turn; a symlink
//     on the way is followed only if root owns it (a system link such as
//     macOS's /var), and every directory must be owned by root or by the
//     store's owner and must not be writable by others without the sticky
//     bit;
//   - modelsDir itself must be a real directory (never a symlink); its owner
//     is the store's owner;
//   - below it, manifests/, registry.ollama.ai/, <ns>/ and <name>/ are
//     opened with O_NOFOLLOW, or created (0755) and handed to the store's
//     owner, and each must then be owned by it;
//   - the manifest goes to an O_CREAT|O_EXCL|O_NOFOLLOW temp file in that
//     directory, is chowned to the owner, made 0644, fsynced, and renamed
//     over <tag> (rename replaces the entry; it follows nothing). An
//     existing <tag> that is a symlink or not a regular file is refused.
//
// Every path component comes from the validated tag (parseOllamaRef), never
// from a manifest. Its undo puts back what <tag> held before (kept in
// memory), or removes it.
func writeManifestNative(modelsDir, ns, name, tag string, body []byte) (*manifestWrite, error) {
	dfd, uid, gid, err := openManifestDir(modelsDir, ns, name)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dfd)
	old, hadOld, err := readRegularAt(dfd, tag)
	if err != nil {
		return nil, err
	}
	if err := replaceAt(dfd, tag, body, uid, gid); err != nil {
		return nil, err
	}
	undo := func() error {
		dfd2, uid2, gid2, err := openManifestDir(modelsDir, ns, name)
		if err != nil {
			return err
		}
		defer unix.Close(dfd2)
		if hadOld {
			return replaceAt(dfd2, tag, old, uid2, gid2)
		}
		return unix.Unlinkat(dfd2, tag, 0)
	}
	return &manifestWrite{undo: undo, commit: func() {}}, nil
}

// openManifestDir returns an fd for <modelsDir>/manifests/registry.ollama.ai/
// <ns>/<name>, creating what is missing, and the store owner's uid and gid.
func openManifestDir(modelsDir, ns, name string) (int, int, int, error) {
	clean := filepath.Clean(modelsDir)
	if !filepath.IsAbs(clean) || clean == "/" {
		return -1, 0, 0, fmt.Errorf("ollama's model store %q is not an absolute directory", modelsDir)
	}
	var st unix.Stat_t
	if err := unix.Lstat(clean, &st); err != nil {
		return -1, 0, 0, fmt.Errorf("ollama's model store %s: %w", clean, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return -1, 0, 0, fmt.Errorf("ollama's model store %s is a symlink or not a directory — refusing to write through it", clean)
	}
	uid, gid := int(st.Uid), int(st.Gid)

	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, 0, 0, fmt.Errorf("open /: %w", err)
	}
	comps := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	for i, c := range comps {
		last := i == len(comps)-1
		nfd, err := openAncestor(fd, c, last, uid, filepath.Join(append([]string{"/"}, comps[:i+1]...)...))
		unix.Close(fd)
		if err != nil {
			return -1, 0, 0, err
		}
		fd = nfd
	}
	for _, c := range []string{"manifests", "registry.ollama.ai", ns, name} {
		nfd, err := openOrMakeOwnedDir(fd, c, uid, gid)
		unix.Close(fd)
		if err != nil {
			return -1, 0, 0, fmt.Errorf("%s: %w", filepath.Join(clean, "manifests"), err)
		}
		fd = nfd
	}
	return fd, uid, gid, nil
}

// openAncestor opens one component of the store's own path. last is the
// store directory itself, which is never followed as a link.
func openAncestor(dirfd int, comp string, last bool, owner int, shown string) (int, error) {
	var lst unix.Stat_t
	if err := unix.Fstatat(dirfd, comp, &lst, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return -1, fmt.Errorf("%s: %w", shown, err)
	}
	flags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC
	if lst.Mode&unix.S_IFMT == unix.S_IFLNK {
		if last || lst.Uid != 0 {
			return -1, fmt.Errorf("%s is a symlink (owned by uid %d) — only root-owned system links above the store are followed; refusing", shown, lst.Uid)
		}
	} else {
		flags |= unix.O_NOFOLLOW
	}
	nfd, err := unix.Openat(dirfd, comp, flags, 0)
	if err != nil {
		return -1, fmt.Errorf("%s: %w", shown, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(nfd, &st); err != nil {
		unix.Close(nfd)
		return -1, fmt.Errorf("%s: %w", shown, err)
	}
	if int(st.Uid) != 0 && int(st.Uid) != owner {
		unix.Close(nfd)
		return -1, fmt.Errorf("%s is owned by uid %d, neither root nor the store's owner (uid %d) — refusing to write below it", shown, st.Uid, owner)
	}
	if st.Mode&0o002 != 0 && st.Mode&unix.S_ISVTX == 0 {
		unix.Close(nfd)
		return -1, fmt.Errorf("%s is writable by anyone (mode %o, no sticky bit) — refusing to write below it", shown, st.Mode&0o7777)
	}
	return nfd, nil
}

// openOrMakeOwnedDir opens dirfd/comp without following a link, creating it
// (0755, handed to uid:gid) when absent. It must end up a directory owned by
// uid that others cannot write.
func openOrMakeOwnedDir(dirfd int, comp string, uid, gid int) (int, error) {
	flags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	nfd, err := unix.Openat(dirfd, comp, flags, 0)
	if errors.Is(err, unix.ENOENT) {
		if merr := unix.Mkdirat(dirfd, comp, 0o755); merr != nil && !errors.Is(merr, unix.EEXIST) {
			return -1, fmt.Errorf("create %s: %w", comp, merr)
		}
		if cerr := unix.Fchownat(dirfd, comp, uid, gid, unix.AT_SYMLINK_NOFOLLOW); cerr != nil {
			return -1, fmt.Errorf("hand %s to uid %d: %w", comp, uid, cerr)
		}
		nfd, err = unix.Openat(dirfd, comp, flags, 0)
	}
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return -1, fmt.Errorf("%s is a symlink or not a directory — refusing to write through it", comp)
		}
		return -1, fmt.Errorf("%s: %w", comp, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(nfd, &st); err != nil {
		unix.Close(nfd)
		return -1, fmt.Errorf("%s: %w", comp, err)
	}
	if int(st.Uid) != uid {
		unix.Close(nfd)
		return -1, fmt.Errorf("%s is owned by uid %d, not the store's owner (uid %d) — refusing", comp, st.Uid, uid)
	}
	if st.Mode&0o022 != 0 {
		unix.Close(nfd)
		return -1, fmt.Errorf("%s is writable by group or others (mode %o) — refusing", comp, st.Mode&0o7777)
	}
	return nfd, nil
}

// readRegularAt reads dirfd/name if it exists. A symlink or anything but a
// regular file there is refused, not replaced.
func readRegularAt(dirfd int, name string) ([]byte, bool, error) {
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, false, nil
	}
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, false, fmt.Errorf("the existing manifest %s is a symlink — refusing to replace it", name)
		}
		return nil, false, fmt.Errorf("the existing manifest %s: %w", name, err)
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if !st.Mode().IsRegular() {
		return nil, false, fmt.Errorf("the existing manifest %s is not a regular file — refusing to replace it", name)
	}
	body, err := io.ReadAll(io.LimitReader(f, mirrorMaxManifestBytes+1))
	if err != nil {
		return nil, false, err
	}
	if len(body) > mirrorMaxManifestBytes {
		return nil, false, fmt.Errorf("the existing manifest %s is over %d bytes — refusing to replace it", name, mirrorMaxManifestBytes)
	}
	return body, true, nil
}

// replaceAt writes body to a fresh temp file in dirfd, hands it to uid:gid,
// and renames it over name. The temp is removed on any failure.
func replaceAt(dirfd int, name string, body []byte, uid, gid int) (err error) {
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := ".noo-" + name + "-" + hex.EncodeToString(rnd[:]) + ".tmp"
	fd, err := unix.Openat(dirfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create the manifest temp file: %w", err)
	}
	f := os.NewFile(uintptr(fd), tmp)
	defer func() {
		if err != nil {
			_ = unix.Unlinkat(dirfd, tmp, 0)
		}
	}()
	if _, err = f.Write(body); err == nil {
		if err = f.Chown(uid, gid); err == nil {
			if err = f.Chmod(0o644); err == nil {
				err = f.Sync()
			}
		}
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("write the manifest: %w", err)
	}
	if err = unix.Renameat(dirfd, tmp, dirfd, name); err != nil {
		return fmt.Errorf("rename the manifest into place: %w", err)
	}
	_ = unix.Fsync(dirfd)
	return nil
}

// freeBytes is the space available to the agent under path.
func freeBytes(path string) (uint64, error) {
	var s unix.Statfs_t
	if err := unix.Statfs(path, &s); err != nil {
		return 0, err
	}
	return uint64(s.Bavail) * uint64(s.Bsize), nil //nolint:unconvert // field types differ by platform
}
