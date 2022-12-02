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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/io"

	accessrequestsv1 "github.com/spreadshirt/kube-request-access/apis/accessrequests/v1"
	"github.com/spreadshirt/kube-request-access/webhooks"
)

const UserAgent = "kube-request-access"

type AuditWebhook struct {
	httpClient   *http.Client
	webhookURL   string
	expectedCert *x509.Certificate
}

func NewWebhookAuditer(webhookURL string, certFile string) (Auditer, error) {
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
				// ClientAuth: tls.RequireAndVerifyClientCert,
				RootCAs: clientCerts,
			},
		},
	}

	return &AuditWebhook{
		httpClient:   httpClient,
		webhookURL:   webhookURL,
		expectedCert: cert,
	}, nil
}

var _ Auditer = &AuditWebhook{}

func (aw *AuditWebhook) AuditExec(ctx context.Context, request *admissionv1.AdmissionRequest, isAllowed bool, execOptions *corev1.PodExecOptions, isAdmin bool) error {
	return aw.sendRequest(ctx, webhooks.AuditTypeExec, &webhooks.AuditExecData{
		Request:     request,
		IsAllowed:   isAllowed,
		ExecOptions: execOptions,
		IsAdmin:     isAdmin,
	})
}

func (aw *AuditWebhook) AuditCreated(ctx context.Context, request *admissionv1.AdmissionRequest, accessRequest accessrequestsv1.AccessRequest) error {
	return aw.sendRequest(ctx, webhooks.AuditTypeCreated, &webhooks.AuditCreateData{
		Request:       request,
		AccessRequest: accessRequest,
	})
}

func (aw *AuditWebhook) sendRequest(ctx context.Context, auditType string, data interface{}) error {
	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	err := enc.Encode(data)
	if err != nil {
		return fmt.Errorf("encode json: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", aw.webhookURL+"?type="+auditType, buf)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", UserAgent)

	resp, err := aw.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.TLS == nil {
		return fmt.Errorf("not a tls connection, but required")
	}
	if len(resp.TLS.PeerCertificates) == 0 {
		return fmt.Errorf("no certificates sent")
	}

	if !resp.TLS.PeerCertificates[0].Equal(aw.expectedCert) {
		return fmt.Errorf("certificate does not match expected cert")
	}

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAtMost(resp.Body, 10*1024)
		return fmt.Errorf("expected status code %d, but got %d: %s", http.StatusOK, resp.StatusCode, data)
	}

	return nil
}