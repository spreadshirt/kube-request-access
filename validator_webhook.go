package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"os"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/utils/io"

	accessrequestsv1 "github.com/spreadshirt/kube-request-access/apis/accessrequests/v1"
	"github.com/spreadshirt/kube-request-access/webhooks"
)

type ValidatorWebhook struct {
	httpClient   *http.Client
	webhookURL   string
	expectedCert *x509.Certificate
}

func NewWebhookValidator(webhookURL string, certFile string) (Validator, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("could not read cert file: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("no cert data found")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not load cert: %w", err)
	}

	u, err := url.Parse(webhookURL)
	if err != nil {
		return nil, fmt.Errorf("invalid webhook url: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("webhook url must be https")
	}

	clientCerts := x509.NewCertPool()
	clientCerts.AddCert(cert)
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: clientCerts,
			},
		},
	}

	return &ValidatorWebhook{
		httpClient:   httpClient,
		webhookURL:   webhookURL,
		expectedCert: cert,
	}, nil
}

func (vh *ValidatorWebhook) ValidateAccessRequest(ctx context.Context, admissionRequest *admissionv1.AdmissionRequest, accessRequest *accessrequestsv1.AccessRequest) (*webhooks.ValidationResult, error) {
	return vh.sendRequest(ctx, webhooks.ValidateAccessRequestData{
		Request:       admissionRequest,
		AccessRequest: accessRequest,
	})
}

func (vh *ValidatorWebhook) sendRequest(ctx context.Context, data interface{}) (*webhooks.ValidationResult, error) {
	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	err := enc.Encode(data)
	if err != nil {
		return nil, fmt.Errorf("encode json: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", vh.webhookURL, buf)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", UserAgent)

	resp, err := vh.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.TLS == nil {
		return nil, fmt.Errorf("not a tls connection, but required")
	}
	if len(resp.TLS.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates sent")
	}

	if !resp.TLS.PeerCertificates[0].Equal(vh.expectedCert) {
		return nil, fmt.Errorf("certificate does not match expected cert")
	}

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAtMost(resp.Body, 10*1024)
		return nil, fmt.Errorf("expected status code %d, but got %d: %s", http.StatusOK, resp.StatusCode, data)
	}

	var validationResult webhooks.ValidationResult
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&validationResult)
	if err != nil {
		return nil, fmt.Errorf("could not parse validation result: %w", err)
	}

	return &validationResult, nil
}