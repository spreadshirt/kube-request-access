// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	v1 "github.com/spreadshirt/kube-request-access/apis/generated/clientset/versioned/typed/accessrequests/v1"
	rest "k8s.io/client-go/rest"
	testing "k8s.io/client-go/testing"
)

type FakeAccessrequestsV1 struct {
	*testing.Fake
}

func (c *FakeAccessrequestsV1) AccessGrants(namespace string) v1.AccessGrantInterface {
	return &FakeAccessGrants{c, namespace}
}

func (c *FakeAccessrequestsV1) AccessRequests(namespace string) v1.AccessRequestInterface {
	return &FakeAccessRequests{c, namespace}
}

// RESTClient returns a RESTClient that is used to communicate
// with API server by this client implementation.
func (c *FakeAccessrequestsV1) RESTClient() rest.Interface {
	var ret *rest.RESTClient
	return ret
}
