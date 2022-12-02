package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/spf13/cobra"
	"k8s.io/klog/v2"

	"github.com/spreadshirt/kube-request-access/webhooks"
)

type webhookServer struct {
	addr     string
	certFile string
	keyFile  string
	verbose  bool
}

func main() {
	srv := &webhookServer{}

	cmd := &cobra.Command{
		Use:   "webhook-validator",
		Short: "An example implementation of a working extended validation webhook",
		RunE:  srv.run,
	}

	cmd.Flags().StringVarP(&srv.addr, "address", "a", "localhost:10443", "Address to listen on")
	cmd.Flags().StringVarP(&srv.certFile, "cert-file", "c", "dev/localhost.crt", "HTTPS cert file")
	cmd.Flags().StringVarP(&srv.keyFile, "key-file", "k", "dev/localhost.key", "HTTPS key file")

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

func (ws *webhookServer) run(cmd *cobra.Command, _ []string) error {
	router := mux.NewRouter()
	router.Handle("/validate", handlers.CustomLoggingHandler(os.Stderr, http.HandlerFunc(ws.handleWebhook), logFormatter))

	klog.Infof("Listening on https://%s", ws.addr)
	err := http.ListenAndServeTLS(ws.addr, ws.certFile, ws.keyFile, router)

	if err != nil {
		return err
	}

	return nil
}

func (ws *webhookServer) handleWebhook(w http.ResponseWriter, req *http.Request) {
	dec := json.NewDecoder(req.Body)
	var validateData webhooks.ValidateAccessRequestData
	err := dec.Decode(&validateData)
	if err != nil {
		klog.ErrorS(err, "invalid validate data received")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if klog.V(3).Enabled() {
		klog.InfoS("validate info", "validate.info", fmt.Sprintf("%#v", validateData))
	}

	validationResult := webhooks.ValidationResult{
		Status:  webhooks.Valid,
		Message: "all is well",
	}
	klog.V(2).InfoS(fmt.Sprintf("validating %s as valid", validateData.Request.Name),
		"validate.result", validationResult,
	)
	enc := json.NewEncoder(w)
	err = enc.Encode(validationResult)
	if err != nil {
		klog.ErrorS(err, "could not encode validation result")
		return
	}
}

func logFormatter(_ io.Writer, params handlers.LogFormatterParams) {
	klog.InfoS(fmt.Sprintf("%s %s %d", params.Request.Method, params.Request.URL.Path, params.StatusCode),
		"response.size", params.Size,
		"status.code", params.StatusCode,
		"request.url", params.URL.String(),
	)
}
