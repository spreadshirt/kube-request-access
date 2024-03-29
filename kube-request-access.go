package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/spf13/cobra"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	accessrequestsv1 "github.com/spreadshirt/kube-request-access/apis/accessrequests/v1"
	accessrequestsclientv1 "github.com/spreadshirt/kube-request-access/apis/generated/clientset/versioned/typed/accessrequests/v1"
	"github.com/spreadshirt/kube-request-access/webhooks"
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

type admissionConfig struct {
	addr     string
	certFile string
	keyFile  string
	verbose  bool

	cleanupInterval time.Duration
	deleteAfter     time.Duration

	grantedRoleName         string
	alwaysAllowedGroupNames []string
	alwaysAllowedUserNames  []string
	usernamePrefix          string

	auditWebhookURL      string
	auditWebhookCABundle string

	extendedValidationWebhookURL      string
	extendedValidationWebhookCABundle string
}

func main() {
	cfg := &admissionConfig{}

	cmd := &cobra.Command{
		Use:   "kube-request-access",
		Short: "Run audited commands using kubectl",
		RunE:  cfg.run,
	}

	cmd.Flags().StringVarP(&cfg.addr, "address", "a", "localhost:8443", "Address to listen on")
	cmd.Flags().StringVarP(&cfg.certFile, "cert-file", "c", "dev/localhost.crt", "HTTPS cert file")
	cmd.Flags().StringVarP(&cfg.keyFile, "key-file", "k", "dev/localhost.key", "HTTPS key file")

	cmd.Flags().DurationVarP(&cfg.cleanupInterval, "cleanup-interval", "", 5*time.Minute, "The interval with which remaining objects are cleaned up")
	cmd.Flags().DurationVarP(&cfg.deleteAfter, "delete-after", "", 48*time.Hour, "The interval after which unused access requests are deleted")

	cmd.Flags().StringVar(&cfg.grantedRoleName, "granted-role-name", "", "Name of the role that is given to a user temporarily when a request is granted")
	cmd.Flags().StringSliceVar(&cfg.alwaysAllowedGroupNames, "always-allowed-group-name", nil, "Name of a group whose members will be allowed to execute commands without a request and grant")
	cmd.Flags().StringSliceVar(&cfg.alwaysAllowedUserNames, "always-allowed-user-name", nil, "User name of a user who will be allowed to execute commands without a request and grant")
	cmd.Flags().StringVar(&cfg.usernamePrefix, "username-prefix", "", "Prefix for usernames to use when verifying and granting access (optional)")

	cmd.Flags().StringVar(&cfg.auditWebhookURL, "audit-webhook-url", "", "URL of the audit webhook to be used")
	cmd.Flags().StringVar(&cfg.auditWebhookCABundle, "audit-webhook-ca-bundle", "", "Path to the cert file of the audit webhook")

	cmd.Flags().StringVar(&cfg.extendedValidationWebhookURL, "extended-validation-webhook-url", "", "URL of the extended validation webhook to be used")
	cmd.Flags().StringVar(&cfg.extendedValidationWebhookCABundle, "extended-validation-webhook-ca-bundle", "", "Path to the cert file of the extended validation webhook")

	// add -v from klog
	klogFlags := flag.NewFlagSet("", flag.ContinueOnError)
	klog.InitFlags(klogFlags)
	cmd.Flags().AddGoFlag(klogFlags.Lookup("v"))

	klog.CopyStandardLogTo("WARNING")

	err := cmd.Execute()
	if err != nil {
		klog.Fatal(err)
	}
}

// DefaultMaxValidFor is the default maximum validity of an access request.
const DefaultMaxValidFor = 12 * time.Hour

type admissionHandler struct {
	kubernetesClient     *kubernetes.Clientset
	accessRequestsClient *accessrequestsclientv1.AccessrequestsV1Client

	// MaxValidFor is the maximum validity of an access request.
	MaxValidFor time.Duration

	// GrantedRoleName is the role that is temporarily given to users when their
	// access request was granted.
	//
	// If no role name is set then it a role is already assumed to exist, created
	// by some other system.
	GrantedRoleName string

	// AlwaysAllowedGroupNames can be set to always allow users with the given
	// groups.  They won't need to request or grant and will always be allowed.
	//
	// Additionally they won't have the regular restrictions applied, like exec
	// with stdin or tty set for interactive commands.
	AlwaysAllowedGroupNames map[string]bool

	// AlwaysAllowedUserNames can be set to always allow users with a given
	// user name.  They won't need to request or grant and will always be allowed.
	//
	// Additionally they won't have the regular restrictions applied, like exec
	// with stdin or tty set for interactive commands.
	AlwaysAllowedUserNames map[string]bool

	// UsernamePrefix can be set to work with systems that add a prefix to the
	// usernames in Kubernetes.
	UsernamePrefix string

	// auditer receives audit events for processing.
	//
	// It defaults to AuditLogger which just logs the info it receives.
	auditer Auditer

	// extendedValidator can be used to do custom validation.
	//
	// It defaults to NopValidator which does nothing.
	extendedValidator Validator
}

func (cfg *admissionConfig) run(_ *cobra.Command, _ []string) error {
	config, err := clientcmd.BuildConfigFromFlags("", findKubeConfig())
	if err != nil {
		return fmt.Errorf("could not find kubernetes client config: %w", err)
	}

	kubernetesClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("could not create kubernetes client: %w", err)
	}

	accessRequestsClient, err := accessrequestsclientv1.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("could not create accessrequests client: %w", err)
	}

	var auditer Auditer
	auditer = &AuditLogger{
		logger: klog.LoggerWithName(klog.Background(), "auditer"),
	}
	if cfg.auditWebhookURL != "" {
		auditer, err = NewWebhookAuditer(cfg.auditWebhookURL, cfg.auditWebhookCABundle)
		if err != nil {
			return fmt.Errorf("could not create webhook auditer: %w", err)
		}
	}

	var validator Validator
	validator = &NopValidator{}
	if cfg.extendedValidationWebhookURL != "" {
		validator, err = NewWebhookValidator(cfg.extendedValidationWebhookURL, cfg.extendedValidationWebhookCABundle)
		if err != nil {
			return fmt.Errorf("could not create webhook validator: %w", err)
		}
	}

	handler := &admissionHandler{
		kubernetesClient:     kubernetesClient,
		accessRequestsClient: accessRequestsClient,

		MaxValidFor:     DefaultMaxValidFor,
		GrantedRoleName: cfg.grantedRoleName,
		UsernamePrefix:  cfg.usernamePrefix,

		auditer:           auditer,
		extendedValidator: validator,
	}

	go handler.cleanup(cfg.cleanupInterval, cfg.deleteAfter)

	if len(cfg.alwaysAllowedGroupNames) > 0 {
		handler.AlwaysAllowedGroupNames = make(map[string]bool, len(cfg.alwaysAllowedGroupNames))
		for _, alwaysAllowedGroup := range cfg.alwaysAllowedGroupNames {
			handler.AlwaysAllowedGroupNames[alwaysAllowedGroup] = true
		}
	}

	if len(cfg.alwaysAllowedUserNames) > 0 {
		handler.AlwaysAllowedUserNames = make(map[string]bool, len(cfg.alwaysAllowedUserNames))
		for _, alwaysAllowedUser := range cfg.alwaysAllowedUserNames {
			handler.AlwaysAllowedUserNames[alwaysAllowedUser] = true
		}
	}

	router := mux.NewRouter()
	router.HandleFunc("/ready", func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("ok"))
	})
	router.Handle("/", handlers.CustomLoggingHandler(os.Stderr, http.HandlerFunc(handler.handleAdmission), logFormatter))

	klog.Infof("Listening on https://%s", cfg.addr)
	err = http.ListenAndServeTLS(cfg.addr, cfg.certFile, cfg.keyFile, router)
	if err != nil {
		return err
	}
	return nil
}

// findKubeConfig returns the path to .kube/config if it exists, or an empty string.
func findKubeConfig() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	f, err := os.Open(path.Join(homeDir, ".kube/config"))
	if err != nil {
		return ""
	}
	f.Close()

	return f.Name()
}

func logFormatter(_ io.Writer, params handlers.LogFormatterParams) {
	klog.InfoS(fmt.Sprintf("%s %s %d", params.Request.Method, params.Request.URL.Path, params.StatusCode),
		"response.size", params.Size,
		"status.code", params.StatusCode,
		"request.url", params.URL.String(),
	)
}

// cleanup deletes access requests (and thus associated objects) after a while.
//
// - access requests with a `validFor` duration will be deleted after it has expired (grant creation date + `validFor`)
// - access requests without `validFor` will be deleted after `deleteAfter` has passed
func (ah *admissionHandler) cleanup(interval time.Duration, deleteAfter time.Duration) {
	for {
		time.Sleep(interval)

		requests, err := ah.accessRequestsClient.AccessRequests("default").List(context.Background(), metav1.ListOptions{})
		if err != nil {
			klog.ErrorS(err, "could not list access requests")
			continue
		}

		grants, err := ah.accessRequestsClient.AccessGrants("default").List(context.Background(), metav1.ListOptions{})
		if err != nil {
			klog.ErrorS(err, "could not list access grants")
			continue
		}

		for _, request := range requests.Items {
			// handle single-use access requests first (no need to look up their grant first for lifetime)
			if request.Spec.ValidFor == "" {
				if request.CreationTimestamp.Time.Add(deleteAfter).Before(time.Now()) {
					err = ah.accessRequestsClient.AccessRequests(request.Namespace).Delete(context.Background(), request.Name, metav1.DeleteOptions{})
					if err != nil {
						klog.ErrorS(err, "could not delete access request", "access-request", request.Name)
						continue
					}

					klog.InfoS("deleted unused access request", "access-request", request.Name, "deleted-after", deleteAfter.String())
				}

				continue
			}

			dur, err := time.ParseDuration(request.Spec.ValidFor)
			if err != nil {
				klog.ErrorS(err, "invalid duration", "access-request", request.Name)
				continue
			}

			if request.CreationTimestamp.Time.Add(dur + 1*time.Minute).Before(time.Now()) {
				// not expired yet, skip
				continue
			}

			var grantMatch *accessrequestsv1.AccessGrant
			for _, grant := range grants.Items {
				if grant.Spec.GrantFor == request.Name &&
					grant.Status == accessrequestsv1.AccessGrantGranted {
					grantMatch = &grant
					break
				}
			}

			if grantMatch == nil {
				// access has not been granted yet, leave it alone
				continue
			}

			if grantMatch.CreationTimestamp.Time.Add(dur + 1*time.Minute).Before(time.Now()) {
				// not expired yet, skip
				continue
			}

			err = ah.accessRequestsClient.AccessRequests(request.Namespace).Delete(context.Background(), request.Name, metav1.DeleteOptions{})
			if err != nil {
				klog.ErrorS(err, "could not delete access request", "access-request", request.Name)
				continue
			}

			klog.InfoS("deleted expired access request", "access-request", request.Name)
		}
	}
}

func (ah *admissionHandler) handleAdmission(w http.ResponseWriter, req *http.Request) {
	var body []byte
	if req.Body != nil {
		if data, err := io.ReadAll(req.Body); err == nil {
			body = data
		}
	}

	// verify the content type is accurate
	contentType := req.Header.Get("Content-Type")
	if contentType != "application/json" {
		msg := fmt.Sprintf("contentType=%s, expect application/json", contentType)
		klog.Error(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	deserializer := codecs.UniversalDeserializer()
	obj, gvk, err := deserializer.Decode(body, nil, nil)
	if err != nil {
		msg := fmt.Sprintf("Request could not be decoded: %v", err)
		klog.Error(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	var responseObj runtime.Object
	switch *gvk {
	case admissionv1.SchemeGroupVersion.WithKind("AdmissionReview"):
		requestedAdmissionReview, ok := obj.(*admissionv1.AdmissionReview)
		if !ok {
			klog.Errorf("Expected v1.AdmissionReview but got: %T", obj)
			return
		}
		responseAdmissionReview := &admissionv1.AdmissionReview{}
		responseAdmissionReview.SetGroupVersionKind(*gvk)
		allowed, msg, code, err := ah.handleReview(req.Context(), requestedAdmissionReview)
		if err != nil {
			klog.ErrorS(err, "error handling admission review")
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
		klog.Error(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	// klog.V(2).Info(fmt.Sprintf("sending response: %v", responseObj))
	respBytes, err := json.Marshal(responseObj)
	if err != nil {
		klog.ErrorS(err, "could not encode json")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(respBytes); err != nil {
		klog.ErrorS(err, "could not send response")
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

func (ah *admissionHandler) handleReview(ctx context.Context, admissionReview *admissionv1.AdmissionReview) (allowed bool, response string, code int32, err error) {
	if klog.V(3).Enabled() {
		buf := new(bytes.Buffer)
		enc := json.NewEncoder(buf)
		_ = enc.Encode(admissionReview)
		klog.InfoS("got admission review",
			"admission-review", buf.String(),
		)
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
		if ah.UsernamePrefix != "" {
			accessRequest.Spec.UserInfo.Username = ah.UsernamePrefix + accessRequest.Spec.UserInfo.Username
		}

		if !ah.isAlwaysAllowed(admissionReview.Request.UserInfo) && admissionReview.Request.UserInfo.Username != accessRequest.Spec.UserInfo.Username {
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

			if validFor > ah.MaxValidFor {
				msg := "requests can be valid for at most 24 hours (24h)"
				return false, msg, http.StatusBadRequest, nil
			}
		}

		if accessRequest.Spec.ExecOptions.Stdin || accessRequest.Spec.ExecOptions.TTY {
			msg := "stdin (-i, --stdin) and tty (-t, --tty) access are currently not allowed"
			return false, msg, http.StatusForbidden, err
		}

		validation, err := ah.extendedValidator.ValidateAccessRequest(ctx, admissionReview.Request, accessRequest)
		if err != nil {
			return false, "validator failed", http.StatusInternalServerError, err
		}
		if validation.Status != webhooks.Valid {
			return false, validation.Message, http.StatusBadRequest, nil
		}

		err = ah.auditer.AuditCreated(ctx, admissionReview.Request, *accessRequest)
		if err != nil {
			return false, "audit failed", http.StatusInternalServerError, err
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

		accessRequest, err := ah.accessRequestsClient.AccessRequests(admissionReview.Request.Namespace).Get(ctx, accessGrant.Spec.GrantFor, metav1.GetOptions{})
		if err != nil {
			err = fmt.Errorf("could not find matching access request: %w", err)
			return false, err.Error(), http.StatusBadRequest, err
		}
		if ah.UsernamePrefix != "" {
			accessRequest.Spec.UserInfo.Username = ah.UsernamePrefix + accessRequest.Spec.UserInfo.Username
		}

		if ah.GrantedRoleName != "" {
			roleBinding, err := ah.kubernetesClient.RbacV1().RoleBindings(admissionReview.Request.Namespace).Create(ctx, &rbacv1.RoleBinding{
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
					Name: ah.GrantedRoleName,
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

			klog.V(2).Infof("created rolebinding %q (with role %q) to account %q", roleBinding.Name, ah.GrantedRoleName, accessRequest.Spec.UserInfo.Username)
		}

		err = ah.auditer.AuditGranted(ctx, admissionReview.Request, accessGrant, accessRequest)
		if err != nil {
			return false, "audit failed", http.StatusInternalServerError, err
		}

		return true, "", http.StatusOK, nil
	case corev1.SchemeGroupVersion.WithKind("PodExecOptions"):
		podExecOptions, ok := obj.(*corev1.PodExecOptions)
		if !ok {
			err := fmt.Errorf("expected PodExecOptions but got: %T", obj)
			return false, "", http.StatusInternalServerError, err
		}

		if ah.isAlwaysAllowed(admissionReview.Request.UserInfo) {
			err = ah.auditer.AuditExec(ctx, admissionReview.Request, true, podExecOptions, true)
			if err != nil {
				return false, "audit failed", http.StatusInternalServerError, err
			}
			return true, "", http.StatusOK, nil
		}

		if podExecOptions.Stdin || podExecOptions.TTY {
			err = ah.auditer.AuditExec(ctx, admissionReview.Request, false, podExecOptions, false)
			if err != nil {
				return false, "audit failed", http.StatusInternalServerError, err
			}
			return false, "stdin (-i, --stdin) and tty (-t, --tty) access are currently not allowed", http.StatusForbidden, nil
		}

		accessRequests, err := ah.accessRequestsClient.AccessRequests(admissionReview.Request.Namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			err = fmt.Errorf("could not list accessrequests: %w", err)
			return false, "", http.StatusInternalServerError, err
		}

		currentUser := admissionReview.Request.UserInfo
		klog.V(2).Infof("found %d/%v accessrequests for %q", len(accessRequests.Items), accessRequests.GetRemainingItemCount(), currentUser.Username)

		var match *accessrequestsv1.AccessRequest
		for _, accessRequest := range accessRequests.Items {
			if ah.UsernamePrefix != "" {
				accessRequest.Spec.UserInfo.Username = ah.UsernamePrefix + accessRequest.Spec.UserInfo.Username
			}

			klog.V(3).Infof("uid %v %q %q", accessRequest.Spec.UserInfo.Username == currentUser.Username, accessRequest.Spec.UserInfo.Username, currentUser.Username)
			klog.V(3).Infof("resource %v %q %q", accessRequest.Spec.ForObject.Resource == admissionReview.Request.Resource, accessRequest.Spec.ForObject.Resource, admissionReview.Request.Resource)
			klog.V(3).Infof("subresource %v %q %q", accessRequest.Spec.ForObject.SubResource == admissionReview.Request.SubResource, accessRequest.Spec.ForObject.SubResource, admissionReview.Request.SubResource)
			klog.V(3).Infof("name %v %q %q", accessRequest.Spec.ForObject.Name == admissionReview.Request.Name, accessRequest.Spec.ForObject.Name, admissionReview.Request.Name)
			klog.V(3).Infof("namespace %v %q %q", accessRequest.Spec.ForObject.Namespace == admissionReview.Request.Namespace, accessRequest.Spec.ForObject.Namespace, admissionReview.Request.Namespace)
			klog.V(3).Infof("execOptions %v %q %q", equality.Semantic.DeepEqual(accessRequest.Spec.ExecOptions, podExecOptions), accessRequest.Spec.ExecOptions, podExecOptions)

			klog.V(3).Infof("%q %q", accessRequest.Spec.ExecOptions.Command, podExecOptions.Command)

			optionsToCompare := *podExecOptions
			// allow any command if no command was specified in request
			if len(accessRequest.Spec.ExecOptions.Command) == 0 {
				optionsToCompare.Command = nil
			}

			if accessRequest.Spec.UserInfo.Username == currentUser.Username &&
				accessRequest.Spec.ForObject.Resource == admissionReview.Request.Resource &&
				accessRequest.Spec.ForObject.SubResource == admissionReview.Request.SubResource &&
				accessRequest.Spec.ForObject.Name == admissionReview.Request.Name &&
				accessRequest.Spec.ForObject.Namespace == admissionReview.Request.Namespace &&
				equality.Semantic.DeepEqual(accessRequest.Spec.ExecOptions, &optionsToCompare) {
				match = &accessRequest
				break
			}
		}

		if match == nil {
			klog.Error("no match")
			err = ah.auditer.AuditExec(ctx, admissionReview.Request, false, podExecOptions, false)
			if err != nil {
				return false, "audit failed", http.StatusInternalServerError, err
			}
			return false, "", http.StatusForbidden, nil
		}

		accessGrants, err := ah.accessRequestsClient.AccessGrants(admissionReview.Request.Namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			err = fmt.Errorf("could not list accessgrants: %w", err)
			return false, "", http.StatusInternalServerError, err
		}

		var grantMatch *accessrequestsv1.AccessGrant
		for _, accessGrant := range accessGrants.Items {
			klog.V(3).Infof("for %q %q", accessGrant.Spec.GrantFor, match.Name)
			klog.V(3).Infof("status %q", accessGrant.Status)
			if accessGrant.Spec.GrantFor == match.Name &&
				accessGrant.Status == accessrequestsv1.AccessGrantGranted {
				grantMatch = &accessGrant
				break
			}
		}

		if grantMatch == nil {
			klog.Error("no grant match")
			err = ah.auditer.AuditExec(ctx, admissionReview.Request, false, podExecOptions, false)
			if err != nil {
				return false, "audit failed", http.StatusInternalServerError, err
			}
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

			err = ah.accessRequestsClient.AccessRequests(admissionReview.Request.Namespace).Delete(ctx, match.Name, deleteOptions)
			if err != nil {
				err = fmt.Errorf("could not delete request: %w", err)
				return false, "", http.StatusInternalServerError, err
			}
		}

		if hasExpired {
			err = ah.auditer.AuditExec(ctx, admissionReview.Request, false, podExecOptions, false)
			if err != nil {
				return false, "audit failed", http.StatusInternalServerError, err
			}
			msg := "access request has expired"
			err := fmt.Errorf("%s: %s is after %s", msg, validUntil, time.Now())
			return false, msg, http.StatusForbidden, err
		}

		err = ah.auditer.AuditExec(ctx, admissionReview.Request, true, podExecOptions, false)
		if err != nil {
			return false, "audit failed", http.StatusInternalServerError, err
		}
		return true, "", http.StatusOK, nil
	default:
		err := fmt.Errorf("unhandled object of type %q", gvk.Group+"/"+gvk.Kind)
		return false, "unhandled object", http.StatusInternalServerError, err
	}
}

func (ah *admissionHandler) isAlwaysAllowed(userInfo authenticationv1.UserInfo) bool {
	if len(ah.AlwaysAllowedGroupNames) < 1 && len(ah.AlwaysAllowedUserNames) < 1 {
		return false
	}

	for _, group := range userInfo.Groups {
		if ah.AlwaysAllowedGroupNames[group] {
			return true
		}
	}

	username := userInfo.Username
	if ah.UsernamePrefix != "" {
		// if the usernamePrefix is set, let's remove it
		username = strings.Replace(username, ah.UsernamePrefix, "", 1)
	}
	if _, found := ah.AlwaysAllowedUserNames[username]; found {
		return true
	}

	return false
}
