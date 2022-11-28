package main

import (
	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"

	accessrequestsv1 "github.com/spreadshirt/kube-request-access/apis/accessrequests/v1"
)

// Auditer audits actions that are performed through the Kubernetes API.
//
// Auditer will be called when certain events happen and will fail the
// containing request if an error is returned.
type Auditer interface {
	// AuditExec is called when a `PodExec` has been allowed or denied.
	AuditExec(request *admissionv1.AdmissionRequest, isAllowed bool, execOptions *corev1.PodExecOptions, isAdmin bool) error

	// AuditCreated is called when a new AccessRequest has been created.
	//
	// This can be used to notify the team responsible to review and grant the requests, for example.
	AuditCreated(request *admissionv1.AdmissionRequest, accessRequest accessrequestsv1.AccessRequest) error
}

const (
	// AuditTypeExec marks that an Auditer supports the AuditExec method.
	AuditTypeExec = "audit-exec"
	// AuditTypeCreated marks that an Auditer supports the AuditCreated method.
	AuditTypeCreated = "audit-created"
)

var _ Auditer = &AuditLogger{}

type AuditLogger struct {
	// TODO: should use https://pkg.go.dev/k8s.io/klog/v2 instead?  (standard for Kubernetes things)
	logger *logrus.Logger
}

func (al *AuditLogger) SupportedAuditTypes() []string {
	return []string{
		AuditTypeExec,
	}
}

func (al *AuditLogger) AuditExec(request *admissionv1.AdmissionRequest, isAllowed bool, execOptions *corev1.PodExecOptions, isAdmin bool) error {
	decision := "denied"
	if isAllowed {
		decision = "allowed"
	}
	al.logger.WithFields(logrus.Fields{
		"is-admin":  isAdmin,
		"user-info": logrus.Fields{},
	}).Infof("%s is %s to run %s on %s", request.UserInfo.Username, decision, execOptions.Command, request.Name)
	return nil
}

func (al *AuditLogger) AuditCreated(request *admissionv1.AdmissionRequest, accessRequest accessrequestsv1.AccessRequest) error {
	al.logger.WithFields(logrus.Fields{
		"user-info": logrus.Fields{
			"uid":      request.UserInfo.UID,
			"username": request.UserInfo.Username,
		},
	}).Infof("%s has created a request to run %s on %s", request.UserInfo.Username, accessRequest.Spec.ExecOptions.Command, accessRequest.Spec.ForObject.Name)
	return nil
}
