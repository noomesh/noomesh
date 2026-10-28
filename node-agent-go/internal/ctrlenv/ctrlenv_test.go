package ctrlenv

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestResolverDefaultsAndTrim(t *testing.T) {
	for _, k := range []string{"CONTROLLER_URL", "NOO_TLS_CA", "NOO_TLS_CERT", "NOO_TLS_KEY", "NOO_PKI_DIR"} {
		t.Setenv(k, "")
	}
	if got := ControllerURL(); got != DefaultControllerURL {
		t.Fatalf("unset ControllerURL = %q, want default", got)
	}
	t.Setenv("CONTROLLER_URL", "  https://c:1/ \n")
	t.Setenv("NOO_TLS_CA", " /ca ")
	t.Setenv("NOO_TLS_CERT", "/crt\n")
	t.Setenv("NOO_TLS_KEY", "\t/key")
	t.Setenv("NOO_PKI_DIR", " /pki ")
	if got := ControllerURL(); got != "https://c:1/" {
		t.Fatalf("ControllerURL = %q", got)
	}
	if TLSCA() != "/ca" || TLSCert() != "/crt" || TLSKey() != "/key" || PKIDir() != "/pki" {
		t.Fatalf("not trimmed: %q %q %q %q", TLSCA(), TLSCert(), TLSKey(), PKIDir())
	}
}

// TestNoOtherFileReadsControllerEnv is the ratchet: only this package may
// read the controller/PKI environment names. It scans every non-test .go file
// in the module and must find some, so an empty scan cannot pass.
func TestNoOtherFileReadsControllerEnv(t *testing.T) {
	root := filepath.Join("..", "..")
	read := regexp.MustCompile(`(?:os\.(?:Getenv|LookupEnv)|syscall\.Getenv)\(\s*"(CONTROLLER_URL|NOO_TLS_CA|NOO_TLS_CERT|NOO_TLS_KEY|NOO_PKI_DIR)"`)
	scanned := 0
	var offenders []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		scanned++
		if filepath.Base(filepath.Dir(p)) == "ctrlenv" {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, m := range read.FindAllStringSubmatch(string(b), -1) {
			offenders = append(offenders, p+" reads "+m[1])
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 10 {
		t.Fatalf("scan found only %d non-test .go files; the walk is broken", scanned)
	}
	if len(offenders) > 0 {
		t.Fatalf("read these names through internal/ctrlenv instead:\n%s", strings.Join(offenders, "\n"))
	}
}
