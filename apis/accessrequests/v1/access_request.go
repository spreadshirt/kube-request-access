package v1

import (
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AccessRequest is a request to a particular API.
type AccessRequest struct {
	metav1.TypeMeta `json:",inline"`

	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec AccessRequestSpec `json:"spec"`
}

// AccessRequestSpec specifies what is being requested access to.
type AccessRequestSpec struct {
	UserInfo    *authenticationv1.UserInfo `json:"userInfo"`
	ExecOptions *corev1.PodExecOptions     `json:"execOptions"`
}