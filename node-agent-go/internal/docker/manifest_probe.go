// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// A manifest probe that keeps the reason. fetchArtifactManifest (backends.go)
// collapses every failure to nil, which is right for its best-effort callers
// and wrong for the import path: "the store does not have it" and "the
// controller did not answer in time" call for different remedies.
//
// Kept in its own file, beside rather than inside fetchArtifactManifest, so
// it can change independently of that function's timeout and retry policy.
package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/auth"
	nodeconfig "github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/ctrlenv"
)

// ErrArtifactAbsent is the store's own answer that it does not hold the
// artifact (404), or that this gateway predates the kind (400) — either way
// a definite "not available from the controller", as opposed to a timeout
// or a transport failure, where nothing is known.
var ErrArtifactAbsent = errors.New("the controller store does not have it")

// ErrArtifactKindUnknown is a gateway's 400 for a kind it does not serve (it
// predates the kind). It is ALSO ErrArtifactAbsent, so every caller that
// treats a 400 as "not there" keeps doing so; a caller that can say "upgrade
// the controller" checks for it first.
var ErrArtifactKindUnknown = fmt.Errorf("%w: the controller's gateway predates this artifact kind", ErrArtifactAbsent)

// ErrArtifactHashing is the gateway's 202: it has the file and is computing
// its sha256 in the background. Ask again after RetryAfter. Never "absent".
var ErrArtifactHashing = errors.New("the controller is still hashing it")

// ErrArtifactManifestTimeout marks a manifest that did not arrive in time —
// one request, or the whole wait for a hash. Never "absent".
var ErrArtifactManifestTimeout = errors.New("timed out waiting for the controller's manifest")

// hashingError carries the 202's Retry-After; errors.Is matches ErrArtifactHashing.
type hashingError struct{ retryAfter time.Duration }

func (h *hashingError) Error() string {
	return fmt.Sprintf("%v (retry after %s)", ErrArtifactHashing, h.retryAfter)
}
func (h *hashingError) Is(target error) bool { return target == ErrArtifactHashing }

// Waiting out a hash: the per-request budget covers an older gateway that
// still hashes inside the request (13.5 s for 3.3 GB on NFS, 2026-10-10;
// 15 s was not enough once the round trip was added), and the overall
// budget bounds the 202 loop (a 15 GB file at ~100 MB/s is ~2.5 min).
const (
	awaitManifestRequestTimeout = 60 * time.Second
	awaitManifestBudget         = 10 * time.Minute
	maxManifestRetryAfter       = 15 * time.Second
)

// probeManifestTimeout bounds one probe. The gateway hashes a file on
// first request; a probe that times out reports "timed out", never absent.
const probeManifestTimeout = 15 * time.Second

// lookupArtifactManifest is a manifest request with the reason kept: nil
// error and a manifest, ErrArtifactAbsent when the gateway answered that it
// has no such artifact, or another error (timeout, TLS, auth, a 5xx) when
// the question went unanswered. Treating the last kind as "absent" is how a
// slow digest on a big file used to read as "the store does not have it".
func lookupArtifactManifest(ctx context.Context, kind, name string) (*artifactManifest, error) {
	return lookupArtifactManifestWithin(ctx, kind, name, probeManifestTimeout)
}

// awaitArtifactManifest is lookupArtifactManifest for a caller that can wait
// (a model_file job, an import): it follows the gateway's 202 "hashing"
// answers until the manifest is ready or awaitManifestBudget runs out.
func awaitArtifactManifest(ctx context.Context, kind, name string) (*artifactManifest, error) {
	return awaitManifest(ctx, awaitManifestBudget, func(ctx context.Context) (*artifactManifest, error) {
		return lookupArtifactManifestWithin(ctx, kind, name, awaitManifestRequestTimeout)
	})
}

// awaitManifest is the loop, with the request injected so it is tested.
// Generic over the answer's type: the flat kinds decode an artifactManifest,
// the `hf` kind a preseed.HFManifest.
func awaitManifest[T any](ctx context.Context, budget time.Duration, ask func(context.Context) (T, error)) (T, error) {
	var zero T
	deadline := time.Now().Add(budget)
	for {
		m, err := ask(ctx)
		var h *hashingError
		if !errors.As(err, &h) {
			return m, err
		}
		if time.Now().Add(h.retryAfter).After(deadline) {
			return zero, fmt.Errorf("%w: the controller was still hashing the file after %s", ErrArtifactManifestTimeout, budget)
		}
		select {
		case <-ctx.Done():
			return zero, fmt.Errorf("%w: %w", ErrArtifactManifestTimeout, ctx.Err())
		case <-time.After(h.retryAfter):
		}
	}
}

func lookupArtifactManifestWithin(ctx context.Context, kind, name string, timeout time.Duration) (*artifactManifest, error) {
	body, err := manifestRoundTrip(ctx, kind, name, timeout)
	if err != nil {
		return nil, err
	}
	return decodeArtifactManifest(body)
}

// manifestRoundTrip asks the gateway for one manifest and returns the 200
// body, or the classified failure (see doArtifactRequest).
func manifestRoundTrip(ctx context.Context, kind, name string, timeout time.Duration) ([]byte, error) {
	controller := strings.TrimRight(ctrlenv.ControllerURL(), "/")
	// One resolver, one default: ctrlenv.ControllerURL() is never empty, the
	// heartbeat and this lookup always agree on where the controller is.
	reqURL := fmt.Sprintf("%s/api/artifacts/manifest/%s/%s", controller, kind, url.PathEscape(name))
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build manifest request: %w", err)
	}
	if secret := nodeconfig.Load().ClusterSecret; secret != "" {
		nodeID := os.Getenv("NODE_ID")
		if err := auth.SetClusterAuth(req, nodeID, secret); err != nil {
			return nil, fmt.Errorf("sign manifest request: %w", err)
		}
	}
	transport, err := nodeconfig.Load().HTTPTransport()
	if err != nil {
		return nil, fmt.Errorf("TLS transport: %w", err)
	}
	// A transport for one request: close its connection when done, or the
	// controller holds it (2026-11-02 EMFILE, see config.HTTPTransport).
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Timeout: timeout, Transport: transport}
	return doArtifactRequest(httpClient, req)
}

// doArtifactManifest runs the request and classifies the answer. Split out
// so the classification is testable against an httptest server.
func doArtifactManifest(httpClient *http.Client, req *http.Request) (*artifactManifest, error) {
	body, err := doArtifactRequest(httpClient, req)
	if err != nil {
		return nil, err
	}
	return decodeArtifactManifest(body)
}

// ErrArtifactRefused is the gateway's 409: it HAS the artifact and refuses
// to vouch for it (an `hf` blob whose bytes do not match its HF oid). The
// message carries the gateway's reason. Never "absent", never retried into
// a fallback.
var ErrArtifactRefused = errors.New("the controller refused to vouch for it")

// doArtifactRequest runs the request and returns a 200's body, or the
// classified failure: ErrArtifactKindUnknown / ErrArtifactAbsent (400/404),
// a hashingError (202), ErrArtifactRefused (409), a timeout, or an error
// naming the status and the gateway's own message.
func doArtifactRequest(httpClient *http.Client, req *http.Request) ([]byte, error) {
	resp, err := httpClient.Do(req)
	if err != nil {
		var ne interface{ Timeout() bool }
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
			return nil, fmt.Errorf("manifest request %w: %w", ErrArtifactManifestTimeout, err)
		}
		return nil, fmt.Errorf("manifest request failed: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusBadRequest:
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if strings.Contains(string(msg), "unknown artifact kind") {
			return nil, ErrArtifactKindUnknown
		}
		return nil, ErrArtifactAbsent
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrArtifactAbsent
	case resp.StatusCode == http.StatusAccepted:
		wait := 5 * time.Second
		if v, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && v > 0 {
			wait = time.Duration(v) * time.Second
		}
		return nil, &hashingError{retryAfter: min(wait, maxManifestRetryAfter)}
	case resp.StatusCode == http.StatusConflict:
		return nil, fmt.Errorf("%w: %s", ErrArtifactRefused, gatewayErrorText(resp.Body))
	case resp.StatusCode != http.StatusOK:
		if msg := gatewayErrorText(resp.Body); msg != "" {
			return nil, fmt.Errorf("manifest request answered HTTP %d: %s", resp.StatusCode, msg)
		}
		return nil, fmt.Errorf("manifest request answered HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	return body, nil
}

// gatewayErrorText is the gateway's `{"error": "..."}` message, or the
// body's first bytes when it is not that shape.
func gatewayErrorText(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 2048))
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(b, &e) == nil && e.Error != "" {
		return e.Error
	}
	return strings.TrimSpace(string(b))
}

// decodeArtifactManifest reads a flat kind's manifest (one sha256).
func decodeArtifactManifest(body []byte) (*artifactManifest, error) {
	var m artifactManifest
	if json.Unmarshal(body, &m) != nil || len(m.SHA256) != 64 {
		return nil, fmt.Errorf("manifest response carried no usable sha256")
	}
	m.SHA256 = strings.ToLower(m.SHA256)
	return &m, nil
}
