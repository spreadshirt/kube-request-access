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
		Use:   "webhook-auditer",
		Short: "An example implementation of a working auditing webhook",
		RunE:  srv.run,
	}

	cmd.Flags().StringVarP(&srv.addr, "address", "a", "localhost:9443", "Address to listen on")
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
	router.Handle("/audit", handlers.CustomLoggingHandler(os.Stderr, http.HandlerFunc(ws.handleWebhook), logFormatter))

	klog.Infof("Listening on https://%s", ws.addr)
	err := http.ListenAndServeTLS(ws.addr, ws.certFile, ws.keyFile, router)

	if err != nil {
		return err
	}

	return nil
}

func (ws *webhookServer) handleWebhook(w http.ResponseWriter, req *http.Request) {
	dec := json.NewDecoder(req.Body)
	switch req.URL.Query().Get("type") {
	case webhooks.AuditTypeCreated:
		var createData webhooks.AuditCreateData
		err := dec.Decode(&createData)
		if err != nil {
			klog.ErrorS(err, "invalid create data received")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		if klog.V(3).Enabled() {
			klog.InfoS("create info", "create.info", fmt.Sprintf("%#v", createData))
		}

		klog.Infof("%s has requested access for command %s on %s",
			createData.Request.UserInfo.Username,
			createData.AccessRequest.Spec.ExecOptions.Command,
			createData.AccessRequest.Spec.ForObject.Name)
	case webhooks.AuditTypeExec:
		var execData webhooks.AuditExecData
		err := dec.Decode(&execData)
		if err != nil {
			klog.Error(err, "invalid create data received")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		if klog.V(3).Enabled() {
			klog.InfoS("create info", "create.info", fmt.Sprintf("%#v", execData))
		}

		klog.Infof("%s is running %s on %s", execData.Request.UserInfo.Username, execData.ExecOptions.Command, execData.Request.Name)
	default:
		http.Error(w, fmt.Sprintf("unknown audit type %q", req.URL.Query().Get("type")), http.StatusBadRequest)
	}
}

func logFormatter(_ io.Writer, params handlers.LogFormatterParams) {
	klog.InfoS(fmt.Sprintf("%s %s %d", params.Request.Method, params.Request.URL.Path, params.StatusCode),
		"response.size", params.Size,
		"status.code", params.StatusCode,
		"request.url", params.URL.String(),
	)
}
