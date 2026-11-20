//
// Copyright 2024 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package http

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

const (
	HTTPCollector = "HTTPCollector"

	// maxResponseSize caps a single HTTP response body at 512 MB to
	// guard against unexpectedly large payloads.
	maxResponseSize = 512 * 1024 * 1024
)

type httpCollector struct {
	urls     []string
	poll     bool
	interval time.Duration
	client   *http.Client

	// mu guards seen, which deduplicates documents by their content hash
	// (document ref) so repeated polls of the same endpoint do not emit
	// identical documents more than once.
	mu   sync.Mutex
	seen map[string]struct{}
}

type Opt func(*httpCollector)

// WithHTTPClient overrides the HTTP client used to fetch documents,
// e.g. to attach custom transports or authentication headers.
func WithHTTPClient(client *http.Client) Opt {
	return func(h *httpCollector) {
		if client != nil {
			h.client = client
		}
	}
}

// NewHTTPCollector returns a collector that fetches documents from the
// given HTTP(S) URLs. When poll is true the URLs are re-fetched every
// interval; identical documents are only emitted once.
func NewHTTPCollector(ctx context.Context, urls []string, poll bool, interval time.Duration, opts ...Opt) *httpCollector {
	h := &httpCollector{
		urls:     urls,
		poll:     poll,
		interval: interval,
		client:   &http.Client{Timeout: 5 * time.Minute},
		seen:     map[string]struct{}{},
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// RetrieveArtifacts collects the documents from the collector. It emits each collected
// document through the channel to be collected and processed by the upstream processor.
// The function should block until all the artifacts are collected and return a nil error
// or return an error from the collector crashing. This function can keep running and check
// for new artifacts as they are being uploaded by polling on an interval or run once and
// grab all the artifacts and end.
func (h *httpCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	if len(h.urls) == 0 {
		return fmt.Errorf("no URLs provided for %s", HTTPCollector)
	}

	logger := logging.FromContext(ctx)

	for {
		for _, url := range h.urls {
			if ctx.Err() != nil {
				return ctx.Err() // nolint:wrapcheck
			}
			blob, err := h.fetch(ctx, url)
			if err != nil {
				// A single failing endpoint should not abort collection of the
				// remaining URLs; log and continue.
				logger.Warnw("failed to fetch document", "url", url, "error", err)
				continue
			}

			docRef := events.GetDocRef(blob)
			if h.isDuplicate(docRef) {
				logger.Debugw("skipping duplicate document", "url", url, "documentRef", docRef)
				continue
			}

			doc := &processor.Document{
				Blob:   blob,
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				SourceInformation: processor.SourceInformation{
					Collector:   string(HTTPCollector),
					Source:      url,
					DocumentRef: docRef,
				},
			}

			select {
			case docChannel <- doc:
			case <-ctx.Done():
				return ctx.Err() // nolint:wrapcheck
			}
		}

		if !h.poll {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err() // nolint:wrapcheck
		case <-time.After(h.interval):
		}
	}

	return nil
}

// Type returns the collector type
func (h *httpCollector) Type() string {
	return HTTPCollector
}

func (h *httpCollector) fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request for %s: %w", url, err)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error fetching %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d fetching %s", resp.StatusCode, url)
	}

	blob, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("error reading response body from %s: %w", url, err)
	}
	return blob, nil
}

// isDuplicate reports whether docRef has already been emitted and records
// it if not, ensuring each unique document is emitted exactly once.
func (h *httpCollector) isDuplicate(docRef string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.seen[docRef]; ok {
		return true
	}
	h.seen[docRef] = struct{}{}
	return false
}
