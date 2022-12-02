package main

import (
	"fmt"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

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

var _ Auditer = &AuditLogger{}

type AuditLogger struct {
	logger klog.Logger
}

func (al *AuditLogger) AuditExec(request *admissionv1.AdmissionRequest, isAllowed bool, execOptions *corev1.PodExecOptions, isAdmin bool) error {
	decision := "denied"
	if isAllowed {
		decision = "allowed"
	}
	al.logger.Info(fmt.Sprintf("%s is %s to run %s on %s", request.UserInfo.Username, decision, execOptions.Command, request.Name),
		"is-admin", isAdmin,
		"user-info", request.UserInfo,
	)
	return nil
}

func (al *AuditLogger) AuditCreated(request *admissionv1.AdmissionRequest, accessRequest accessrequestsv1.AccessRequest) error {
	al.logger.Info(fmt.Sprintf("%s has created a request to run %s on %s", request.UserInfo.Username, accessRequest.Spec.ExecOptions.Command, accessRequest.Spec.ForObject.Name),
		"user-info", request.UserInfo,
	)
	return nil
}
