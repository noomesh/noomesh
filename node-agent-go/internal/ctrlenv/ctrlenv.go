// Package ctrlenv is the ONE reader of the environment names that say where
// the controller is and which PKI files this agent presents to it:
// CONTROLLER_URL, NOO_TLS_CA, NOO_TLS_CERT, NOO_TLS_KEY and NOO_PKI_DIR.
//
// Before this package existed config.Load, the docker manifest probes, the
// NATS TLS builder, the healthcheck, hostd and the backend-leaf reporter each
// read these names themselves, with two different defaults for the controller
// URL (the heartbeat dialled https://gateway:8080 while the manifest lookups
// treated an unset variable as "no controller"). Every site now calls the
// functions below; TestNoOtherFileReadsControllerEnv fails if a file outside
// this package reads one of the names again.
//
// Values are whitespace-trimmed. The TLS paths and PKI dir have no default
// (empty means "not configured"); the controller URL has exactly one.
package ctrlenv

import (
	"os"
	"strings"
)

// DefaultControllerURL is the single default for CONTROLLER_URL: the
// in-network gateway name used by the compose-era layout.
const DefaultControllerURL = "https://gateway:8080"

func get(name string) string { return strings.TrimSpace(os.Getenv(name)) }

// ControllerURL is CONTROLLER_URL (trimmed), or DefaultControllerURL when
// unset or blank. It may carry a trailing slash; callers that join paths
// trim it with strings.TrimRight.
func ControllerURL() string {
	if v := get("CONTROLLER_URL"); v != "" {
		return v
	}
	return DefaultControllerURL
}

// TLSCA is NOO_TLS_CA: the cluster CA bundle path ("" when unset).
func TLSCA() string { return get("NOO_TLS_CA") }

// TLSCert is NOO_TLS_CERT: this node's client/server certificate path.
func TLSCert() string { return get("NOO_TLS_CERT") }

// TLSKey is NOO_TLS_KEY: this node's private key path.
func TLSKey() string { return get("NOO_TLS_KEY") }

// PKIDir is NOO_PKI_DIR: the project PKI directory ("" when unset).
func PKIDir() string { return get("NOO_PKI_DIR") }
