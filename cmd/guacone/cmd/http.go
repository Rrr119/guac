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

package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/cli"
	csub_client "github.com/guacsec/guac/pkg/collectsub/client"
	"github.com/guacsec/guac/pkg/handler/collector"
	guachttp "github.com/guacsec/guac/pkg/handler/collector/http"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor"
	"github.com/guacsec/guac/pkg/ingestor/key"
	"github.com/guacsec/guac/pkg/ingestor/key/inmemory"
	"github.com/guacsec/guac/pkg/ingestor/verifier"
	"github.com/guacsec/guac/pkg/ingestor/verifier/sigstore_verifier"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/guacsec/guac/pkg/metrics"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type httpOptions struct {
	// path to the pem file
	keyPath string
	// ID related to the key being stored
	keyID string
	// URLs of documents to collect
	urls []string
	// gql endpoint
	graphqlEndpoint string
	headerFile      string
	// csub client options for identifier strings
	csubClientOptions       csub_client.CsubClientOptions
	queryVulnOnIngestion    bool
	queryLicenseOnIngestion bool
	queryEOLOnIngestion     bool
	queryDepsDevOnIngestion bool
	enableOtel              bool
}

var httpCmd = &cobra.Command{
	Use:   "http [flags] url...",
	Short: "fetch documents from HTTP(S) URLs and create a GUAC graph, this command talks directly to the graphQL endpoint",
	Run: func(cmd *cobra.Command, args []string) {
		opts, err := validateHTTPFlags(
			viper.GetString("verifier-key-path"),
			viper.GetString("verifier-key-id"),
			viper.GetString("gql-addr"),
			viper.GetString("header-file"),
			viper.GetString("csub-addr"),
			viper.GetBool("csub-tls"),
			viper.GetBool("csub-tls-skip-verify"),
			viper.GetBool("add-vuln-on-ingest"),
			viper.GetBool("add-license-on-ingest"),
			viper.GetBool("add-eol-on-ingest"),
			viper.GetBool("add-depsdev-on-ingest"),
			viper.GetBool("enable-otel"),
			args)
		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)
		transport := cli.HTTPHeaderTransport(ctx, opts.headerFile, http.DefaultTransport)

		if opts.enableOtel {
			shutdown, err := metrics.SetupOTelSDK(ctx)
			if err != nil {
				logger.Fatalf("Error setting up Otel: %v", err)
			}
			defer func() {
				if err := shutdown(ctx); err != nil {
					logger.Errorf("Error on Otel shutdown: %v", err)
				}
			}()
		}

		// Register Keystore
		inmemory := inmemory.NewInmemoryProvider()
		err = key.RegisterKeyProvider(inmemory, inmemory.Type())
		if err != nil {
			logger.Fatalf("unable to register key provider: %v", err)
		}

		if opts.keyPath != "" && opts.keyID != "" {
			keyRaw, err := os.ReadFile(opts.keyPath)
			if err != nil {
				logger.Fatalf("error: %v", err)
			}
			err = key.Store(ctx, opts.keyID, keyRaw, inmemory.Type())
			if err != nil {
				logger.Fatalf("error: %v", err)
			}
		}

		// Register Verifier
		sigstoreAndKeyVerifier := sigstore_verifier.NewSigstoreAndKeyVerifier()
		err = verifier.RegisterVerifier(sigstoreAndKeyVerifier, sigstoreAndKeyVerifier.Type())
		if err != nil {
			logger.Fatalf("unable to register key provider: %v", err)
		}

		// Register collector
		httpCollector := guachttp.NewHTTPCollector(ctx, opts.urls, false, time.Second,
			guachttp.WithHTTPClient(&http.Client{Transport: transport, Timeout: 5 * time.Minute}))
		err = collector.RegisterDocumentCollector(httpCollector, guachttp.HTTPCollector)
		if err != nil {
			logger.Fatalf("unable to register http collector: %v", err)
		}

		// initialize collectsub client
		csubClient, err := csub_client.NewClient(opts.csubClientOptions)
		if err != nil {
			logger.Infof("collectsub client initialization failed, this ingestion will not pull in any additional data through the collectsub service: %v", err)
			csubClient = nil
		} else {
			defer csubClient.Close()
		}

		totalNum := 0
		totalSuccess := 0
		var urlsWithErrors []string

		gotErr := false

		emit := func(d *processor.Document) error {
			totalNum += 1
			if _, err := ingestor.Ingest(
				ctx,
				d,
				opts.graphqlEndpoint,
				transport,
				csubClient,
				opts.queryVulnOnIngestion,
				opts.queryLicenseOnIngestion,
				opts.queryEOLOnIngestion,
				opts.queryDepsDevOnIngestion,
			); err != nil {
				gotErr = true
				urlsWithErrors = append(urlsWithErrors, d.SourceInformation.Source)
				return fmt.Errorf("unable to ingest document: %w", err)
			}
			totalSuccess += 1
			return nil
		}

		// Collect
		errHandler := func(err error) bool {
			if err == nil {
				logger.Info("collector ended gracefully")
				return true
			}
			logger.Errorf("collector ended with error: %v", err)
			return false
		}

		if err := collector.Collect(ctx, emit, errHandler); err != nil {
			logger.Errorf("collector exited with error: %v", err)
		}

		if gotErr {
			logger.Errorf("completed ingestion with error, %v of %v were successful - the following URLs did not ingest successfully:  %v",
				totalSuccess, totalNum, strings.Join(urlsWithErrors, " "))
		} else {
			logger.Infof("completed ingesting %v documents of %v", totalSuccess, totalNum)
		}
	},
}

func validateHTTPFlags(keyPath, keyID, graphqlEndpoint, headerFile, csubAddr string,
	csubTls, csubTlsSkipVerify bool,
	queryVulnIngestion bool,
	queryLicenseIngestion bool,
	queryEOLIngestion bool,
	queryDepsDevOnIngestion bool,
	enableOtel bool,
	args []string,
) (httpOptions, error) {
	var opts httpOptions
	opts.graphqlEndpoint = graphqlEndpoint
	opts.headerFile = headerFile
	opts.enableOtel = enableOtel

	if keyPath != "" {
		if strings.HasSuffix(keyPath, "pem") {
			opts.keyPath = keyPath
		} else {
			return opts, errors.New("key must be passed in as a pem file")
		}
	}
	if keyPath != "" {
		opts.keyID = keyID
	}

	if len(args) == 0 {
		return opts, fmt.Errorf("expected at least one positional argument for url")
	}
	for _, url := range args {
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			return opts, fmt.Errorf("url %q must start with http:// or https://", url)
		}
	}

	csubOpts, err := csub_client.ValidateCsubClientFlags(csubAddr, csubTls, csubTlsSkipVerify)
	if err != nil {
		return opts, fmt.Errorf("unable to validate csub client flags: %w", err)
	}
	opts.csubClientOptions = csubOpts
	opts.urls = args
	opts.queryVulnOnIngestion = queryVulnIngestion
	opts.queryLicenseOnIngestion = queryLicenseIngestion
	opts.queryEOLOnIngestion = queryEOLIngestion
	opts.queryDepsDevOnIngestion = queryDepsDevOnIngestion
	return opts, nil
}

func init() {
	set, err := cli.BuildFlags([]string{
		"verifier-key-path",
		"verifier-key-id",
		"enable-otel",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flag: %v", err)
		os.Exit(1)
	}
	httpCmd.Flags().AddFlagSet(set)
	if err := viper.BindPFlags(httpCmd.Flags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %v", err)
		os.Exit(1)
	}

	collectCmd.AddCommand(httpCmd)
}
