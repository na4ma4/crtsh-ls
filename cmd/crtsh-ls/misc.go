package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// CertificateRecord contains the fields used in the JSON response from crt.sh queries.
type CertificateRecord struct {
	IssuerCaID        int    `json:"issuer_ca_id"`
	IssuerName        string `json:"issuer_name"`
	NameValue         string `json:"name_value"`
	MinCertID         int    `json:"min_cert_id"`
	MinEntryTimestamp string `json:"min_entry_timestamp"`
	NotBefore         string `json:"not_before"`
	NotAfter          string `json:"not_after"`
}

var errStatusNotOK = errors.New("server returned error status code")

func getCertStream(ctx context.Context, domain string) (io.ReadCloser, error) {
	client := &http.Client{
		Timeout: viper.GetDuration("timeout"),
	}

	baseurl, err := url.Parse(viper.GetString("crtsh.base_uri"))
	if err != nil {
		logrus.Panicf("unable to parse crtsh.base_uri (%s): %s", viper.GetString("crtsh.base_uri"), err)
	}

	query := baseurl.Query()
	query.Add("output", "json")
	query.Add("q", domain)
	baseurl.RawQuery = query.Encode()

	logrus.Debugf("Requesting: %s", baseurl.String())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseurl.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error retrieving cert stream: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: server returned %d http status code (%s)", errStatusNotOK, resp.StatusCode, resp.Status)
	}

	return resp.Body, nil
}
