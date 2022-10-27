package main

import (
	"bytes"
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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
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
}

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

	router := mux.NewRouter()
	router.HandleFunc("/", handleAdmission)

	accessLogger := logging.NewAccessLogger(nil, nil, nil)
	router.Use(
		accessLogger.Middleware,
	)

	logrus.Infof("Listening on https://%s", c.String("addr"))
	err := http.ListenAndServeTLS(c.String("addr"), c.String("cert-file"), c.String("key-file"), router)
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
		responseAdmissionReview.Response = handle(logger, requestedAdmissionReview)
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

func handle(logger *logrus.Entry, admissionReview *admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
	if logrus.GetLevel() == logrus.DebugLevel {
		buf := new(bytes.Buffer)
		enc := json.NewEncoder(buf)
		_ = enc.Encode(admissionReview)
		logger.WithField("admission-review", buf.String()).Debug("got admission review")
	}

	// admissionReview.Request.UserInfo.Username

	return &admissionv1.AdmissionResponse{
		Allowed: true,
		UID:     admissionReview.Request.UID,
	}
}
