package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	accessrequestsv1 "github.com/spreadshirt/kube-request-access/apis/accessrequests/v1"
	accessrequestsclientv1 "github.com/spreadshirt/kube-request-access/apis/generated/clientset/versioned/typed/accessrequests/v1"
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

var kubernetesClient *kubernetes.Clientset
var accessRequestsClient *accessrequestsclientv1.AccessrequestsV1Client

// MaxValidFor is the maximum validity of an access request.
const MaxValidFor = 12 * time.Hour

// GrantedRoleName is the role that is temporarily given to users when their
// access request was granted.
//
// If no role name is set then it a role is already assumed to exist, created
// by some other system.
var GrantedRoleName = ""

// AlwaysAllowedGroupName can be set to always allow users with the given
// group.  They won't need to request or grant and will always be allowed.
//
// Additionally they won't have the regular restrictions applied, like exec
// with stdin or tty set for interactive commands.
var AlwaysAllowedGroupName = ""

func main() {
	app := cli.App{
		Name:  "kube-request-access",
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
			},
			&cli.BoolFlag{
				Name:  "verbose",
				Value: false,
				Usage: "Enable debug logging",
			},
			&cli.StringFlag{
				Name:  "granted-role-name",
				Value: "",
				Usage: "Name of the role that is given to a user temporarily when a request is granted",
			},
			&cli.StringFlag{
				Name:  "always-allowed-group-name",
				Value: "",
				Usage: "Name of the group whose members will be allowed to execute commands without a request and grant",
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

	GrantedRoleName = c.String("granted-role-name")
	AlwaysAllowedGroupName = c.String("always-allowed-group-name")

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	// if you want to change the loading rules (which files in which order), you can do so here

	configOverrides := &clientcmd.ConfigOverrides{}
	// if you want to change override values or bind them to flags, there are methods to help you

	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
	config, err := kubeConfig.ClientConfig()
	if err != nil {
		return fmt.Errorf("could not find kubernetes client config: %w", err)
	}

	kubernetesClient, err = kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("could not create kubernetes client: %w", err)
	}

	accessRequestsClient, err = accessrequestsclientv1.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("could not create accessrequests client: %w", err)
	}

	router := mux.NewRouter()
	router.HandleFunc("/", handleAdmission)

	// TODO: log requests somehow™, maybe https://pkg.go.dev/github.com/gorilla/handlers#CustomLoggingHandler?

	logrus.Infof("Listening on https://%s", c.String("addr"))
	err = http.ListenAndServeTLS(c.String("addr"), c.String("cert-file"), c.String("key-file"), router)
	if err != nil {
		return err
	}
	return nil
}

func handleAdmission(w http.ResponseWriter, req *http.Request) {
	var body []byte
	if req.Body != nil {
		if data, err := io.ReadAll(req.Body); err == nil {
			body = data
		}
	}

	// verify the content type is accurate
	contentType := req.Header.Get("Content-Type")
	if contentType != "application/json" {
		logrus.Errorf("contentType=%s, expect application/json", contentType)
		return
	}
	deserializer := codecs.UniversalDeserializer()
	obj, gvk, err := deserializer.Decode(body, nil, nil)
	if err != nil {
		msg := fmt.Sprintf("Request could not be decoded: %v", err)
		logrus.Error(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	var responseObj runtime.Object
	switch *gvk {
	case admissionv1.SchemeGroupVersion.WithKind("AdmissionReview"):
		requestedAdmissionReview, ok := obj.(*admissionv1.AdmissionReview)
		if !ok {
			logrus.Errorf("Expected v1.AdmissionReview but got: %T", obj)
			return
		}
		responseAdmissionReview := &admissionv1.AdmissionReview{}
		responseAdmissionReview.SetGroupVersionKind(*gvk)
		allowed, msg, code, err := handle(req.Context(), requestedAdmissionReview)
		if err != nil {
			logrus.WithError(err).Error("error handling admission review")
			responseAdmissionReview.Response = &admissionv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status:  metav1.StatusFailure,
					Message: msg,
					Code:    code,
				},
			}
		} else {
			status := metav1.StatusFailure
			if allowed {
				status = metav1.StatusSuccess
			}
			responseAdmissionReview.Response = &admissionv1.AdmissionResponse{
				Allowed: allowed,
				Result: &metav1.Status{
					Status:  status,
					Message: msg,
					Code:    code,
				},
			}
		}
		responseAdmissionReview.Response.UID = requestedAdmissionReview.Request.UID
		responseObj = responseAdmissionReview
	default:
		msg := fmt.Sprintf("Unsupported group version kind: %v", gvk)
		logrus.Error(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	// klog.V(2).Info(fmt.Sprintf("sending response: %v", responseObj))
	respBytes, err := json.Marshal(responseObj)
	if err != nil {
		logrus.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(respBytes); err != nil {
		logrus.Error(err)
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

func handle(ctx context.Context, admissionReview *admissionv1.AdmissionReview) (allowed bool, response string, code int32, err error) {
	if logrus.GetLevel() == logrus.DebugLevel {
		buf := new(bytes.Buffer)
		enc := json.NewEncoder(buf)
		_ = enc.Encode(admissionReview)
		logrus.WithField("admission-review", buf.String()).Debug("got admission review")
	}

	deserializer := codecs.UniversalDeserializer()
	obj, gvk, err := deserializer.Decode(admissionReview.Request.Object.Raw, nil, nil)
	if err != nil {
		err = fmt.Errorf("Request could not be decoded: %w", err)
		return false, "", http.StatusInternalServerError, err
	}

	switch *gvk {
	case accessrequestsv1.SchemeGroupVersion.WithKind("AccessRequest"):
		accessRequest, ok := obj.(*accessrequestsv1.AccessRequest)
		if !ok {
			err := fmt.Errorf("expected v1.AccessRequest but got: %T", obj)
			return false, "", http.StatusInternalServerError, err
		}

		if admissionReview.Request.UserInfo.Username != accessRequest.Spec.UserInfo.Username {
			msg := fmt.Sprintf("you can only request access for yourself (requested for %q, but authenticated as %q)",
				accessRequest.Spec.UserInfo.Username,
				admissionReview.Request.UserInfo.Username)
			return false, msg, http.StatusForbidden, nil
		}

		if accessRequest.Spec.ValidFor != "" {
			validFor, err := time.ParseDuration(accessRequest.Spec.ValidFor)
			if err != nil {
				err = fmt.Errorf("invalid validFor duration: %w", err)
				return false, err.Error(), http.StatusBadRequest, nil
			}

			if validFor > MaxValidFor {
				msg := "requests can be valid for at most 24 hours (24h)"
				return false, msg, http.StatusBadRequest, nil
			}
		}

		if accessRequest.Spec.ExecOptions.Stdin || accessRequest.Spec.ExecOptions.TTY {
			msg := "stdin (-i, --stdin) and tty (-t, --tty) access are currently not allowed"
			return false, msg, http.StatusForbidden, err
		}

		// TODO: consider rejecting multiple requests for the same command

		return true, "", http.StatusOK, nil
	case accessrequestsv1.SchemeGroupVersion.WithKind("AccessGrant"):
		// NOTE: we return the error to the user here, because they are expected to be admins and are allowed this information

		accessGrant, ok := obj.(*accessrequestsv1.AccessGrant)
		if !ok {
			err := fmt.Errorf("expected v1.AccessRequest but got: %T", obj)
			return false, err.Error(), http.StatusInternalServerError, err

		}

		accessRequest, err := accessRequestsClient.AccessRequests(admissionReview.Request.Namespace).Get(ctx, accessGrant.Spec.GrantFor, metav1.GetOptions{})
		if err != nil {
			err = fmt.Errorf("could not find matching access request: %w", err)
			return false, err.Error(), http.StatusBadRequest, err
		}

		if GrantedRoleName != "" {
			roleBinding, err := kubernetesClient.RbacV1().RoleBindings(admissionReview.Request.Namespace).Create(ctx, &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: fmt.Sprintf("developer-exec-tmp-%s-", accessRequest.Spec.UserInfo.Username),
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "spreadgroup.com/v1",
							Kind:       "AccessRequest",
							UID:        accessRequest.UID,
							Name:       accessRequest.Name,
						},
					},
				},
				RoleRef: rbacv1.RoleRef{
					Kind: "Role",
					Name: GrantedRoleName,
				},
				Subjects: []rbacv1.Subject{
					{
						Kind: "User",
						Name: accessRequest.Spec.UserInfo.Username,
					},
				},
			}, metav1.CreateOptions{})
			if err != nil {
				err = fmt.Errorf("could not create role binding: %s", err)
				return false, err.Error(), http.StatusInternalServerError, err
			}

			logrus.Debugf("created rolebinding %q (with role %q) to account %q", roleBinding.Name, GrantedRoleName, accessRequest.Spec.UserInfo.Username)
		}

		return true, "", http.StatusOK, nil
	case corev1.SchemeGroupVersion.WithKind("PodExecOptions"):
		podExecOptions, ok := obj.(*corev1.PodExecOptions)
		if !ok {
			err := fmt.Errorf("expected PodExecOptions but got: %T", obj)
			return false, "", http.StatusInternalServerError, err
		}

		if AlwaysAllowedGroupName != "" {
			isAlwaysAllowed := false
			for _, group := range admissionReview.Request.UserInfo.Groups {
				if group == AlwaysAllowedGroupName {
					isAlwaysAllowed = true
					break
				}
			}

			if isAlwaysAllowed {
				logrus.Info("admin audit", podExecOptions)
				return true, "", http.StatusOK, nil
			}
		}

		if podExecOptions.Stdin || podExecOptions.TTY {
			return false, "stdin (-i, --stdin) and tty (-t, --tty) access are currently not allowed", http.StatusForbidden, nil
		}

		accessRequests, err := accessRequestsClient.AccessRequests(admissionReview.Request.Namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			err = fmt.Errorf("could not list accessrequests: %w", err)
			return false, "", http.StatusInternalServerError, err
		}

		currentUser := admissionReview.Request.UserInfo
		logrus.Debugf("found %d/%v accessrequests for %q", len(accessRequests.Items), accessRequests.GetRemainingItemCount(), currentUser.Username)

		var match *accessrequestsv1.AccessRequest
		for _, accessRequest := range accessRequests.Items {
			logrus.Debugf("uid %v %q %q", accessRequest.Spec.UserInfo.Username == currentUser.Username, accessRequest.Spec.UserInfo.Username, currentUser.Username)
			logrus.Debugf("resource %v %q %q", accessRequest.Spec.ForObject.Resource == admissionReview.Request.Resource, accessRequest.Spec.ForObject.Resource, admissionReview.Request.Resource)
			logrus.Debugf("subresource %v %q %q", accessRequest.Spec.ForObject.SubResource == admissionReview.Request.SubResource, accessRequest.Spec.ForObject.SubResource, admissionReview.Request.SubResource)
			logrus.Debugf("name %v %q %q", accessRequest.Spec.ForObject.Name == admissionReview.Request.Name, accessRequest.Spec.ForObject.Name, admissionReview.Request.Name)
			logrus.Debugf("namespace %v %q %q", accessRequest.Spec.ForObject.Namespace == admissionReview.Request.Namespace, accessRequest.Spec.ForObject.Namespace, admissionReview.Request.Namespace)
			logrus.Debugf("execOptions %v %q %q", equality.Semantic.DeepEqual(accessRequest.Spec.ExecOptions, podExecOptions), accessRequest.Spec.ExecOptions, podExecOptions)

			logrus.Debugf("%q %q", accessRequest.Spec.ExecOptions.Command, podExecOptions.Command)

			// allow any command if no command was specified in request
			if len(accessRequest.Spec.ExecOptions.Command) == 0 {
				podExecOptions.Command = nil
			}

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
			logrus.Error("no match")
			return false, "", http.StatusForbidden, nil
		}

		accessGrants, err := accessRequestsClient.AccessGrants(admissionReview.Request.Namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			err = fmt.Errorf("could not list accessgrants: %w", err)
			return false, "", http.StatusInternalServerError, err
		}

		var grantMatch *accessrequestsv1.AccessGrant
		for _, accessGrant := range accessGrants.Items {
			logrus.Debugf("for %q %q", accessGrant.Spec.GrantFor, match.Name)
			logrus.Debugf("status %q", accessGrant.Status)
			if accessGrant.Spec.GrantFor == match.Name &&
				accessGrant.Status == accessrequestsv1.AccessGrantGranted {
				grantMatch = &accessGrant
				break
			}
		}

		if grantMatch == nil {
			logrus.Error("no grant match")
			return false, "", http.StatusForbidden, nil
		}

		var validUntil time.Time
		if match.Spec.ValidFor != "" {
			validFor, err := time.ParseDuration(match.Spec.ValidFor)
			if err != nil {
				// should have been caught earlier in AccessRequest validation, error out
				err = fmt.Errorf("invalid validFor duration: %w", err)
				return false, err.Error(), http.StatusInternalServerError, err
			}

			validUntil = grantMatch.CreationTimestamp.Time.Add(validFor)
		} else {
			// fake so the validity check does not error out
			validUntil = time.Now().Add(1 * time.Minute)
		}

		hasExpired := validUntil.Before(time.Now())

		if match.Spec.ValidFor == "" || hasExpired {
			// "burn" request after use (grant and rolebinding are deleted because they are owned by the access request)
			deleteOptions := metav1.DeleteOptions{}
			if admissionReview.Request.DryRun != nil && *admissionReview.Request.DryRun {
				deleteOptions.DryRun = []string{"All"}
			}

			err = accessRequestsClient.AccessRequests(admissionReview.Request.Namespace).Delete(ctx, match.Name, deleteOptions)
			if err != nil {
				err = fmt.Errorf("could not delete request: %w", err)
				return false, "", http.StatusInternalServerError, err
			}
		}

		if hasExpired {
			msg := "access request has expired"
			err := fmt.Errorf("%s: %s is after %s", msg, validUntil, time.Now())
			return false, msg, http.StatusForbidden, err
		}

		logrus.Info("audit", podExecOptions) // TODO: which format do we want?
		return true, "", http.StatusOK, nil
	default:
		err := fmt.Errorf("unhandled object of type %q", gvk.Group+"/"+gvk.Kind)
		return false, "unhandled object", http.StatusInternalServerError, err
	}
}
