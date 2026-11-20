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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"
)

func sbomServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for _, name := range []string{"sbom-spdx.json", "sbom-cyclonedx.json", "sbom-cyclonedx.xml"} {
		blob, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatalf("failed to read testdata %s: %v", name, err)
		}
		mux.HandleFunc("/"+name, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(blob)
		})
	}
	mux.HandleFunc("/not-found", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func wantDoc(t *testing.T, name, source string) *processor.Document {
	t.Helper()
	blob, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("failed to read testdata %s: %v", name, err)
	}
	return &processor.Document{
		Blob:   blob,
		Type:   processor.DocumentUnknown,
		Format: processor.FormatUnknown,
		SourceInformation: processor.SourceInformation{
			Collector:   string(HTTPCollector),
			Source:      source,
			DocumentRef: events.GetDocRef(blob),
		},
	}
}

func collectDocs(t *testing.T, ctx context.Context, h *httpCollector) ([]*processor.Document, error) {
	t.Helper()
	docChannel := make(chan *processor.Document, collector.BufferChannelSize)
	errChan := make(chan error, 1)
	go func() {
		errChan <- h.RetrieveArtifacts(ctx, docChannel)
	}()
	var docs []*processor.Document
	for {
		select {
		case d := <-docChannel:
			docs = append(docs, d)
		case err := <-errChan:
			return docs, err
		}
	}
}

func Test_httpCollector_RetrieveArtifacts_SBOM(t *testing.T) {
	server := sbomServer(t)
	tests := []struct {
		name     string
		testdata string
	}{{
		name:     "SPDX JSON SBOM",
		testdata: "sbom-spdx.json",
	}, {
		name:     "CycloneDX JSON SBOM",
		testdata: "sbom-cyclonedx.json",
	}, {
		name:     "CycloneDX XML SBOM",
		testdata: "sbom-cyclonedx.xml",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := server.URL + "/" + tt.testdata
			h := NewHTTPCollector(context.Background(), []string{url}, false, time.Second)

			collector.DeregisterDocumentCollector(HTTPCollector)
			if err := collector.RegisterDocumentCollector(h, HTTPCollector); err != nil {
				t.Fatalf("failed to register collector: %v", err)
			}
			defer collector.DeregisterDocumentCollector(HTTPCollector)

			docs, err := collectDocs(t, context.Background(), h)
			if err != nil {
				t.Fatalf("RetrieveArtifacts() error = %v", err)
			}
			want := []*processor.Document{wantDoc(t, tt.testdata, url)}
			if !reflect.DeepEqual(docs, want) {
				t.Errorf("RetrieveArtifacts() = %+v, want %+v", docs, want)
			}
			if h.Type() != HTTPCollector {
				t.Errorf("Type() = %v, want %v", h.Type(), HTTPCollector)
			}
		})
	}
}

func Test_httpCollector_RetrieveArtifacts_Dedup(t *testing.T) {
	server := sbomServer(t)
	url := server.URL + "/sbom-spdx.json"

	// Poll rapidly and cancel shortly after; the same document is served on
	// every poll but must only be emitted once.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	h := NewHTTPCollector(ctx, []string{url}, true, 10*time.Millisecond)

	docs, err := collectDocs(t, ctx, h)
	if err == nil {
		t.Fatal("expected context cancellation error from polling collector")
	}
	want := []*processor.Document{wantDoc(t, "sbom-spdx.json", url)}
	if !reflect.DeepEqual(docs, want) {
		t.Errorf("RetrieveArtifacts() emitted %d docs, want exactly 1 deduplicated doc: %+v", len(docs), docs)
	}
}

func Test_httpCollector_RetrieveArtifacts_Errors(t *testing.T) {
	server := sbomServer(t)
	tests := []struct {
		name     string
		urls     []string
		wantDocs int
		wantErr  bool
	}{{
		name:     "no URLs configured",
		urls:     nil,
		wantDocs: 0,
		wantErr:  true,
	}, {
		name:     "failing endpoint is skipped",
		urls:     []string{server.URL + "/not-found", server.URL + "/sbom-cyclonedx.json"},
		wantDocs: 1,
		wantErr:  false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHTTPCollector(context.Background(), tt.urls, false, time.Second)
			docs, err := collectDocs(t, context.Background(), h)
			if (err != nil) != tt.wantErr {
				t.Fatalf("RetrieveArtifacts() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(docs) != tt.wantDocs {
				t.Errorf("RetrieveArtifacts() emitted %d docs, want %d", len(docs), tt.wantDocs)
			}
		})
	}
}
