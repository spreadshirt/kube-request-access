package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/spreadshirt/kube-request-access/webhooks"
)

func main() {
	app := cli.App{
		Name:  "webhook-auditer-example",
		Usage: "An example implementation of a working auditing webhook",
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
		},
		Action: runWebhookServer,
	}
	err := app.Run(os.Args)
	if err != nil {
		logrus.Fatal(err)
	}
}

func runWebhookServer(c *cli.Context) error {
	if c.Bool("verbose") {
		logrus.SetLevel(logrus.DebugLevel)
	}

	router := mux.NewRouter()
	router.Handle("/audit", handlers.CustomLoggingHandler(logrus.StandardLogger().Out, http.HandlerFunc(handleWebhook), logFormatter))

	logrus.Infof("Listening on https://%s", c.String("addr"))
	err := http.ListenAndServeTLS(c.String("addr"), c.String("cert-file"), c.String("key-file"), router)
	if err != nil {
		return err
	}

	return nil
}

func handleWebhook(w http.ResponseWriter, req *http.Request) {
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
