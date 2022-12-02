package main

import (
	"context"
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
	AuditExec(ctx context.Context, request *admissionv1.AdmissionRequest, isAllowed bool, execOptions *corev1.PodExecOptions, isAdmin bool) error

	// AuditCreated is called when a new AccessRequest has been created.
	//
	// This can be used to notify the team responsible to review and grant the requests, for example.
	AuditCreated(ctx context.Context, request *admissionv1.AdmissionRequest, accessRequest accessrequestsv1.AccessRequest) error

	// AuditGranted is called when a request has been granted.
	AuditGranted(ctx context.Context, request *admissionv1.AdmissionRequest, accessGrant *accessrequestsv1.AccessGrant, accessRequest *accessrequestsv1.AccessRequest) error
}

var _ Auditer = &AuditLogger{}

type AuditLogger struct {
	logger klog.Logger
}

func (al *AuditLogger) AuditExec(_ context.Context, request *admissionv1.AdmissionRequest, isAllowed bool, execOptions *corev1.PodExecOptions, isAdmin bool) error {
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

func (al *AuditLogger) AuditCreated(_ context.Context, request *admissionv1.AdmissionRequest, accessRequest accessrequestsv1.AccessRequest) error {
	al.logger.Info(fmt.Sprintf("%s has created a request to run %s on %s", request.UserInfo.Username, accessRequest.Spec.ExecOptions.Command, accessRequest.Spec.ForObject.Name),
		"requested-by", accessRequest.Spec.UserInfo.Username,
	)
	return nil
}

func (al *AuditLogger) AuditGranted(_ context.Context, request *admissionv1.AdmissionRequest, accessGrant *accessrequestsv1.AccessGrant, accessRequest *accessrequestsv1.AccessRequest) error {
	al.logger.Info(fmt.Sprintf("%s has granted %s by %s", accessGrant.Spec.GrantedBy.Username, accessRequest.Name, accessRequest.Spec.UserInfo.Username),
		"requested-by", accessRequest.Spec.UserInfo.Username,
		"granted-by", accessGrant.Spec.GrantedBy.Username,
	)
	return nil
}