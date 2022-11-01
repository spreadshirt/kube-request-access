package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"git.spreadomat.net/go/logging"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/clientcmd"

	accessrequestsv1 "git.spreadomat.net/deleng/kubectl-audit/apis/accessrequests/v1"
	accessrequestsclientv1 "git.spreadomat.net/deleng/kubectl-audit/apis/generated/clientset/versioned/typed/accessrequests/v1"
)

var scheme = runtime.NewScheme()
var codecs = serializer.NewCodecFactory(scheme)

func init() {
	addToScheme(scheme)
}

func addToScheme(scheme *runtime.Scheme) {
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(admissionv1.AddToScheme(scheme))
	utilruntime.Must(admissionregistrationv1.AddToScheme(scheme))

	// crds
	utilruntime.Must(accessrequestsv1.AddToScheme(scheme))
}

var accessRequestsClient *accessrequestsclientv1.AccessrequestsV1Client

func main() {
	app := cli.App{
		Name:  "kubectl-audit",
		Usage: "Run audited commands using kubectl",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "addr",
				Value: "localhost:8443",
				Usage: "Address to listen on",
			},
			&cli.StringFlag{
				Name:  "cert-file",
				Value: "dev/localhost.crt",
				Usage: "HTTPS cert file",
			},
			&cli.StringFlag{
				Name:  "key-file",
				Value: "dev/localhost.key",
				Usage: "HTTPS key file",
			}, &cli.BoolFlag{
				Name:  "verbose",
				Value: false,
				Usage: "Enable debug logging",
			},
		},
		Action: runServer,
	}
	err := app.Run(os.Args)
	if err != nil {
		logrus.Fatal(err)
	}
}

func runServer(c *cli.Context) error {
	if c.Bool("verbose") {
		logrus.SetLevel(logrus.DebugLevel)
	}

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	// if you want to change the loading rules (which files in which order), you can do so here

	configOverrides := &clientcmd.ConfigOverrides{}
	// if you want to change override values or bind them to flags, there are methods to help you

	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
	config, err := kubeConfig.ClientConfig()
	if err != nil {
		return fmt.Errorf("could not find kubernetes client config: %w", err)
	}

	accessRequestsClient, err = accessrequestsclientv1.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("could not create accessrequests client: %w", err)
	}

	router := mux.NewRouter()
	router.HandleFunc("/", handleAdmission)

	accessLogger := logging.NewAccessLogger(nil, nil, nil)
	router.Use(
		accessLogger.Middleware,
	)

	logrus.Infof("Listening on https://%s", c.String("addr"))
	err = http.ListenAndServeTLS(c.String("addr"), c.String("cert-file"), c.String("key-file"), router)
	if err != nil {
		return err
	}
	return nil
}

func handleAdmission(w http.ResponseWriter, req *http.Request) {
	logger := logging.LogForRequest(req)

	var body []byte
	if req.Body != nil {
		if data, err := io.ReadAll(req.Body); err == nil {
			body = data
		}
	}

	// verify the content type is accurate
	contentType := req.Header.Get("Content-Type")
	if contentType != "application/json" {
		logger.Errorf("contentType=%s, expect application/json", contentType)
		return
	}
	deserializer := codecs.UniversalDeserializer()
	obj, gvk, err := deserializer.Decode(body, nil, nil)
	if err != nil {
		msg := fmt.Sprintf("Request could not be decoded: %v", err)
		logger.Error(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	var responseObj runtime.Object
	switch *gvk {
	case admissionv1.SchemeGroupVersion.WithKind("AdmissionReview"):
		requestedAdmissionReview, ok := obj.(*admissionv1.AdmissionReview)
		if !ok {
			logger.Errorf("Expected v1.AdmissionReview but got: %T", obj)
			return
		}
		responseAdmissionReview := &admissionv1.AdmissionReview{}
		responseAdmissionReview.SetGroupVersionKind(*gvk)
		responseAdmissionReview.Response = handle(req.Context(), logger, requestedAdmissionReview)
		responseAdmissionReview.Response.UID = requestedAdmissionReview.Request.UID
		responseObj = responseAdmissionReview
	default:
		msg := fmt.Sprintf("Unsupported group version kind: %v", gvk)
		logger.Error(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	// klog.V(2).Info(fmt.Sprintf("sending response: %v", responseObj))
	respBytes, err := json.Marshal(responseObj)
	if err != nil {
		logger.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(respBytes); err != nil {
		logger.Error(err)
	}
}

var admissionReviewExample = `
{
  "kind": "AdmissionReview",
  "apiVersion": "admission.k8s.io/v1",
  "request": {
    "uid": "5cf446fc-5745-47a1-aecd-f4231a676bd6",
    "kind": {
      "group": "",
      "version": "v1",
      "kind": "PodExecOptions"
    },
    "resource": {
      "group": "",
      "version": "v1",
      "resource": "pods"
    },
    "subResource": "exec",
    "requestKind": {
      "group": "",
      "version": "v1",
      "kind": "PodExecOptions"
    },
    "requestResource": {
      "group": "",
      "version": "v1",
      "resource": "pods"
    },
    "requestSubResource": "exec",
    "name": "nginx-deployment-6595874d85-2bhgt",
    "namespace": "default",
    "operation": "CONNECT",
    "userInfo": {
      "username": "system:admin",
      "groups": [
        "system:masters",
        "system:authenticated"
      ]
    },
    "object": {
      "kind": "PodExecOptions",
      "apiVersion": "v1",
      "stdin": true,
      "stdout": true,
      "tty": true,
      "container": "nginx",
      "command": [
        "/bin/sh"
      ]
    },
    "oldObject": null,
    "dryRun": false,
    "options": null
  }
}
`

func handle(ctx context.Context, logger *logrus.Entry, admissionReview *admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
	if logrus.GetLevel() == logrus.DebugLevel {
		buf := new(bytes.Buffer)
		enc := json.NewEncoder(buf)
		_ = enc.Encode(admissionReview)
		logger.WithField("admission-review", buf.String()).Debug("got admission review")
	}

	deserializer := codecs.UniversalDeserializer()
	obj, gvk, err := deserializer.Decode(admissionReview.Request.Object.Raw, nil, nil)
	if err != nil {
		msg := fmt.Sprintf("Request could not be decoded: %v", err)
		logger.Error(msg)
		return &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Status:  "Failure",
				Message: msg,
				Code:    http.StatusInternalServerError,
			},
		}
	}

	switch *gvk {
	case accessrequestsv1.SchemeGroupVersion.WithKind("AccessRequest"):
		accessRequest, ok := obj.(*accessrequestsv1.AccessRequest)
		if !ok {
			msg := fmt.Sprintf("expected v1.AccessRequest but got: %T", obj)
			return &admissionv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status:  "Failure",
					Message: msg,
					Code:    http.StatusInternalServerError,
				},
			}
		}

		if admissionReview.Request.UserInfo.Username != accessRequest.Spec.UserInfo.Username {
			return &admissionv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status: "Failure",
					Message: fmt.Sprintf("you can only request access for yourself (requested for %q, but authenticated as %q)",
						accessRequest.Spec.UserInfo.Username,
						admissionReview.Request.UserInfo.Username),
					Code: http.StatusForbidden,
				},
				UID: admissionReview.Request.UID,
			}
		}

		if accessRequest.Spec.ExecOptions.Stdin || accessRequest.Spec.ExecOptions.TTY {
			return &admissionv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status:  "Failure",
					Message: "stdin (-i, --stdin) and tty (-t, --tty) access are currently not allowed",
					Code:    http.StatusForbidden,
				},
				UID: admissionReview.Request.UID,
			}
		}

		// TODO: consider rejecting multiple requests for the same command

		return &admissionv1.AdmissionResponse{
			Allowed: true,
			UID:     admissionReview.Request.UID,
		}
	case corev1.SchemeGroupVersion.WithKind("PodExecOptions"):
		podExecOptions, ok := obj.(*corev1.PodExecOptions)
		if !ok {
			msg := fmt.Sprintf("expected PodExecOptions but got: %T", obj)
			return &admissionv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status:  "Failure",
					Message: msg,
					Code:    http.StatusInternalServerError,
				},
			}
		}

		if podExecOptions.Stdin || podExecOptions.TTY {
			return &admissionv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status:  "Failure",
					Message: "stdin (-i, --stdin) and tty (-t, --tty) access are currently not allowed",
					Code:    http.StatusForbidden,
				},
				UID: admissionReview.Request.UID,
			}
		}

		accessRequests, err := accessRequestsClient.AccessRequests(admissionReview.Request.Namespace).List(ctx, metav1.ListOptions{
			LabelSelector: fmt.Sprintf("username = %s", admissionReview.Request.UserInfo.Username),
		})
		if err != nil {
			return &admissionv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status:  "Failure",
					Message: fmt.Sprintf("could not list accessrequests: %s", err),
					Code:    http.StatusInternalServerError,
				},
				UID: admissionReview.Request.UID,
			}
		}

		currentUser := admissionReview.Request.UserInfo
		logger.Debug("found %d/%v accessrequests for %q", len(accessRequests.Items), accessRequests.GetRemainingItemCount(), currentUser.Username)

		var match *accessrequestsv1.AccessRequest
		for _, accessRequest := range accessRequests.Items {
			logger.Debugf("uid %v %q %q", accessRequest.Spec.UserInfo.Username == currentUser.Username, accessRequest.Spec.UserInfo.Username, currentUser.Username)
			logger.Debugf("resource %v %q %q", accessRequest.Spec.ForObject.Resource == admissionReview.Request.Resource, accessRequest.Spec.ForObject.Resource, admissionReview.Request.Resource)
			logger.Debugf("subresource %v %q %q", accessRequest.Spec.ForObject.SubResource == admissionReview.Request.SubResource, accessRequest.Spec.ForObject.SubResource, admissionReview.Request.SubResource)
			logger.Debugf("name %v %q %q", accessRequest.Spec.ForObject.Name == admissionReview.Request.Name, accessRequest.Spec.ForObject.Name, admissionReview.Request.Name)
			logger.Debugf("namespace %v %q %q", accessRequest.Spec.ForObject.Namespace == admissionReview.Request.Namespace, accessRequest.Spec.ForObject.Namespace, admissionReview.Request.Namespace)
			logger.Debugf("execOptions %v %q %q", equality.Semantic.DeepEqual(accessRequest.Spec.ExecOptions, podExecOptions), accessRequest.Spec.ExecOptions, podExecOptions)

			logger.Debugf("%q %q", accessRequest.Spec.ExecOptions.Command, podExecOptions.Command)

			if accessRequest.Spec.UserInfo.Username == currentUser.Username &&
				accessRequest.Spec.ForObject.Resource == admissionReview.Request.Resource &&
				accessRequest.Spec.ForObject.SubResource == admissionReview.Request.SubResource &&
				accessRequest.Spec.ForObject.Name == admissionReview.Request.Name &&
				accessRequest.Spec.ForObject.Namespace == admissionReview.Request.Namespace &&
				equality.Semantic.DeepEqual(accessRequest.Spec.ExecOptions, podExecOptions) {
				match = &accessRequest
				break
			}
		}

		if match == nil {
			logger.Error("no match")
			return &admissionv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status: metav1.StatusFailure,
					Reason: metav1.StatusReasonForbidden,
					Code:   http.StatusForbidden,
				},
			}
		}

		accessGrants, err := accessRequestsClient.AccessGrants(admissionReview.Request.Namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return &admissionv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status:  "Failure",
					Message: fmt.Sprintf("could not list accessgrants: %s", err),
					Code:    http.StatusInternalServerError,
				},
				UID: admissionReview.Request.UID,
			}
		}

		var grantMatch *accessrequestsv1.AccessGrant
		for _, accessGrant := range accessGrants.Items {
			logger.Debugf("for %q %q", accessGrant.Spec.GrantFor, match.Name)
			logger.Debugf("status %q", accessGrant.Status)
			if accessGrant.Spec.GrantFor == match.Name &&
				accessGrant.Status == accessrequestsv1.AccessGrantGranted {
				grantMatch = &accessGrant
				break
			}
		}

		if grantMatch == nil {
			logger.Error("no grant match")
			return &admissionv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status: metav1.StatusFailure,
					Reason: metav1.StatusReasonForbidden,
					Code:   http.StatusForbidden,
				},
			}
		}

		// "burn" request and grant after use
		deleteOptions := metav1.DeleteOptions{}
		if admissionReview.Request.DryRun != nil && *admissionReview.Request.DryRun {
			deleteOptions.DryRun = []string{"All"}
		}
		err = accessRequestsClient.AccessGrants(admissionReview.Request.Namespace).Delete(ctx, grantMatch.Name, deleteOptions)
		if err != nil {
			logger.WithError(err).Error("could not delete grant")
			return &admissionv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status: metav1.StatusFailure,
					Reason: metav1.StatusReasonInternalError,
					Code:   http.StatusForbidden,
				},
			}
		}

		err = accessRequestsClient.AccessRequests(admissionReview.Request.Namespace).Delete(ctx, match.Name, deleteOptions)
		if err != nil {
			logger.WithError(err).Error("could not delete request")
			return &admissionv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status: metav1.StatusFailure,
					Reason: metav1.StatusReasonInternalError,
					Code:   http.StatusForbidden,
				},
			}
		}

		logger.Info("audit")
		return &admissionv1.AdmissionResponse{
			Allowed: true,
			UID:     admissionReview.Request.UID,
		}
	default:
		logger.WithError(fmt.Errorf("unhandled object of type %q", gvk.Group+"/"+gvk.Kind)).Error("unhandled object")
		return &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Status:  metav1.StatusFailure,
				Message: "unhandled object",
				Code:    http.StatusInternalServerError,
			},
		}
	}
}
