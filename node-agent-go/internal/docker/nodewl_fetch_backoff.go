package docker

import (
	"net/url"
	"regexp"
	"sync"
	"time"
)

// fetchBackoff spaces out node-workload image fetches that failed: an
// unreachable rail is tried again after 30 s, then 1, 2 and 4 min, then every
// 5 min, not on every reconcile pass. A success clears the artifact.
type fetchBackoff struct {
	mu sync.Mutex
	m  map[string]fetchFail
}

type fetchFail struct {
	why   string
	next  time.Time
	delay time.Duration
}

const (
	fetchBackoffFirst = 30 * time.Second
	fetchBackoffMax   = 5 * time.Minute
)

// blocked: the last failure's reason and how long until the next try, or
// ("", 0) when a fetch may run now.
func (b *fetchBackoff) blocked(artifact string, now time.Time) (string, time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	f, ok := b.m[artifact]
	if !ok || !now.Before(f.next) {
		return "", 0
	}
	return f.why, f.next.Sub(now)
}

func (b *fetchBackoff) failed(artifact, why string, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.m == nil {
		b.m = map[string]fetchFail{}
	}
	d := fetchBackoffFirst
	if f, ok := b.m[artifact]; ok {
		d = f.delay * 2
		if d > fetchBackoffMax {
			d = fetchBackoffMax
		}
	}
	b.m[artifact] = fetchFail{why: why, next: now.Add(d), delay: d}
}

func (b *fetchBackoff) ok(artifact string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.m, artifact)
}

var urlInText = regexp.MustCompile(`[a-z][a-z0-9+.-]*://[^\s"']+`)

// scrubURLs keeps only scheme, host, port and path of every URL in s: no
// user info, query string or fragment (a signed URL or a token in a query
// must never reach a log line or a heartbeat).
func scrubURLs(s string) string {
	return urlInText.ReplaceAllStringFunc(s, func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return "[url]"
		}
		return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}).String()
	})
}
