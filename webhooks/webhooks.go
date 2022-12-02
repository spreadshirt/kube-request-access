// Package webhooks contains types to make developing extensions easier.
package webhooks

import (
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"

	accessrequestsv1 "github.com/spreadshirt/kube-request-access/apis/accessrequests/v1"
)

const (
	// AuditTypeExec marks that an Auditer supports the AuditExec method.
	AuditTypeExec = "audit-exec"
	// AuditTypeCreated marks that an Auditer supports the AuditCreated method.
	AuditTypeCreated = "audit-created"
	// AuditTypeGranted marks that an Auditer supports the AuditGranted method.
	AuditTypeGranted = "audit-granted"
)

type AuditExecData struct {
	Request     *admissionv1.AdmissionRequest `json:"request"`
	IsAllowed   bool                          `json:"isAllowed"`
	ExecOptions *corev1.PodExecOptions        `json:"execOptions"`
	IsAdmin     bool                          `json:"isAdmin"`
}

type AuditCreateData struct {
	Request       *admissionv1.AdmissionRequest  `json:"request"`
	AccessRequest accessrequestsv1.AccessRequest `json:"accessRequest"`
}

type AuditGrantData struct {
	Request       *admissionv1.AdmissionRequest   `json:"request"`
	AccessRequest *accessrequestsv1.AccessRequest `json:"accessRequest"`
	AccessGrant   *accessrequestsv1.AccessGrant   `json:"accessGrant"`
}