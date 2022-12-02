package main

import (
	"context"

	admissionv1 "k8s.io/api/admission/v1"

	accessrequestsv1 "github.com/spreadshirt/kube-request-access/apis/accessrequests/v1"
	"github.com/spreadshirt/kube-request-access/webhooks"
)

type Validator interface {
	ValidateAccessRequest(ctx context.Context, admissionRequest *admissionv1.AdmissionRequest, accessRequest *accessrequestsv1.AccessRequest) (*webhooks.ValidationResult, error)
}

type NopValidator struct{}

var _ Validator = NopValidator{}

func (nv NopValidator) ValidateAccessRequest(ctx context.Context, admissionRequest *admissionv1.AdmissionRequest, accessRequest *accessrequestsv1.AccessRequest) (*webhooks.ValidationResult, error) {
	return &webhooks.ValidationResult{
		Status: webhooks.Valid,
	}, nil
}
