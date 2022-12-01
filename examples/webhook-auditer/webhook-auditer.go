package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

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
	cmd.Flags().BoolVarP(&srv.verbose, "verbose", "v", false, "Enable debug logging")

	err := cmd.Execute()
	if err != nil {
		logrus.Fatal(err)
	}
}

func (ws *webhookServer) run(cmd *cobra.Command, _ []string) error {
	if ws.verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	router := mux.NewRouter()
	router.Handle("/audit", handlers.CustomLoggingHandler(logrus.StandardLogger().Out, http.HandlerFunc(ws.handleWebhook), logFormatter))

	logrus.Infof("Listening on https://%s", ws.addr)
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
			logrus.WithError(err).Error("invalid create data received")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		logrus.Infof("%s has requested access for command %s on %s",
			createData.Request.UserInfo.Username,
			createData.AccessRequest.Spec.ExecOptions.Command,
			createData.AccessRequest.Spec.ForObject.Name)
	case webhooks.AuditTypeExec:
		var execData webhooks.AuditExecData
		err := dec.Decode(&execData)
		if err != nil {
			logrus.WithError(err).Error("invalid create data received")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		logrus.Infof("%s is running %s on %s", execData.Request.UserInfo.Username, execData.ExecOptions.Command, execData.Request.Name)
	default:
		http.Error(w, fmt.Sprintf("unknown audit type %q", req.URL.Query().Get("type")), http.StatusBadRequest)
	}
}

func logFormatter(_ io.Writer, params handlers.LogFormatterParams) {
	logrus.WithFields(logrus.Fields{
		"response.size": params.Size,
		"status.code":   params.StatusCode,
		"request.url":   params.URL.String(),
	}).Infof("%s %s %d", params.Request.Method, params.Request.URL.Path, params.StatusCode)
}
