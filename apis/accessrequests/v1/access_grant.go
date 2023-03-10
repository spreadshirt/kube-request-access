package v1

import (
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AccessGrant is a request to a particular API.
type AccessGrant struct {
	metav1.TypeMeta `json:",inline"`

	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec AccessGrantSpec `json:"spec"`

	Status string `json:"status"`
}

const AccessGrantGranted = "granted"
const AccessGrantDenied = "denied"

// AccessGrantSpec specifies what is being requested access to.
type AccessGrantSpec struct {
	GrantedBy *authenticationv1.UserInfo `json:"grantedBy"`
	GrantFor  string                     `json:"grantFor"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AccessGrantList is a list of AccessGrant resources
type AccessGrantList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []AccessGrant `json:"items"`
}