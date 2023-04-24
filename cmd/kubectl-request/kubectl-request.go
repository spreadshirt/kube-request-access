package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/printers"
	"k8s.io/client-go/kubernetes"

	accessrequestsv1 "github.com/spreadshirt/kube-request-access/apis/accessrequests/v1"
	accessrequestsclientv1 "github.com/spreadshirt/kube-request-access/apis/generated/clientset/versioned/typed/accessrequests/v1"
)

// these variables are set by goreleaser, see https://goreleaser.com/customization/builds/.
var (
	version = "dev"
	commit  = "local"
	date    = "unknown"
)

func main() {
	// turning this off displays our subcommands first (instead of help and completion first)
	cobra.EnableCommandSorting = false

	// 	flags := pflag.NewFlagSet("kubectl-ns", pflag.ExitOnError)
	// pflag.CommandLine = flags

	cmd := &cobra.Command{
		Use:   "kubectl-request",
		Short: "Request and grant access to `kubectl exec` and friends",
		Example: `
	# request access
	kubectl request exec deployment/nginx ls -l /tmp

	# grant access
	kubectl request grant <name>
`,
		Args:    cobra.MinimumNArgs(1),
		Version: version, // set so that cobra adds the --version flag
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			updateInfo, err := IsUpdateAvailable(context.Background(), "v"+version)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not check for updates: %s\n", err)
				return
			}

			if updateInfo != nil {
				fmt.Fprintf(os.Stderr, "An update is available (%s -> %s), please download it from https://github.com/spreadshirt/kube-request-access/releases/latest!\n",
					updateInfo.CurrentVersion, updateInfo.LatestVersion)
			}
		},
	}

	cmd.SetVersionTemplate(
		fmt.Sprintf(`Version:    %s
Commit:     %s
Build date: %s
`,
			"v"+version, commit, date),
	)

	accessCommand := &accessCommand{
		execOptions: &execOptions{},
		customKeys:  map[string]string{},
	}
	accessCommand.genericOptions = genericclioptions.NewConfigFlags(true)
	accessCommand.genericOptions.AddFlags(cmd.PersistentFlags())

	requestExecCmd := &cobra.Command{
		Use:          "exec (POD | TYPE/NAME) [-c CONTAINER] [flags] -- [COMMAND] [args...] [options]",
		Short:        "Request access to execute a command in a container.",
		Args:         cobra.MinimumNArgs(1),
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			accessCommand.execOptions.Command = args[1:]
			if err := accessCommand.Request(c, args[:1]); err != nil {
				return err
			}
			return nil
		}}
	requestExecCmd.Flags().StringVarP(&accessCommand.execOptions.Container, "container", "c", "", `Container name. If omitted, use the kubectl.kubernetes.io/default-container annotation for selecting the
container to be attached or the first container in the pod will be chosen`)
	requestExecCmd.Flags().DurationVarP(&accessCommand.validFor, "valid-for", "d", 0, "Amount of the that the access is requested for (command will only be allowed once if not specified)")
	requestExecCmd.Flags().StringToStringVarP(&accessCommand.customKeys, "custom-key", "k", nil, "Custom key-value pairs to set")
	requestExecCmd.Flags().StringVarP(&accessCommand.onBehalfOf, "on-behalf-of", "", "", "Username to create the request on behalf of (only for admins)")
	cmd.AddCommand(requestExecCmd)

	grantCmd := &cobra.Command{
		Use:          "grant REQUEST",
		Short:        "Grant access to the given request",
		Args:         cobra.MinimumNArgs(1),
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			if err := accessCommand.Grant(c, args[0]); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.AddCommand(grantCmd)

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

type accessCommand struct {
	genericOptions *genericclioptions.ConfigFlags

	execOptions *execOptions
	validFor    time.Duration
	customKeys  map[string]string
	onBehalfOf  string
}

type execOptions struct {
	Container string
	Command   []string
}

func (ac *accessCommand) Request(cmd *cobra.Command, args []string) error {
	target := args[0]

	config, err := ac.genericOptions.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("could not get config: %w", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("could not get client: %w", err)
	}

	configLoader := ac.genericOptions.ToRawKubeConfigLoader()
	rawConfig, err := configLoader.RawConfig()
	if err != nil {
		return err
	}
	namespace, _, err := configLoader.Namespace()
	if err != nil {
		return err
	}

	var selectedPod *corev1.Pod

	// FIXME: find out how to do this officially (there must be a function for parsing names in Kubernetes?)
	var kind string
	var name string
	parts := strings.SplitN(target, "/", 2)
	if len(parts) == 0 {
		return fmt.Errorf("invalid reference %q: don't know how to resolve", target)
	}
	if len(parts) == 1 {
		kind = "pod"
		name = parts[0]
	} else {
		kind = parts[0]
		name = parts[1]
	}
	// TODO: singularize
	switch kind {
	case "pod", "pods":
		pod, err := client.CoreV1().Pods(namespace).Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("could not get pods: %w", err)
		}

		selectedPod = pod
	case "deployment", "deployments":
		// lookup first pod in deployment (like `kubectl exec` does)
		deployment, err := client.AppsV1().Deployments(namespace).Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("could not get deployment: %w", err)
		}

		appName := deployment.Labels["app"]

		pods, err := client.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{
			LabelSelector: fmt.Sprintf("app=%s", appName),
		})
		if err != nil {
			return fmt.Errorf("could not get pods: %w", err)
		}

		if len(pods.Items) == 0 {
			return fmt.Errorf("%q has no pods", target)
		}

		selectedPod = &pods.Items[0]
	default:
		return fmt.Errorf("unsupported kind %q", kind)

	}

	// default to first container if none is set (like `kubectl exec`)
	if ac.execOptions.Container == "" {
		if len(selectedPod.Spec.Containers) == 0 {
			return fmt.Errorf("no containers in pod %q", selectedPod.Name)
		}
		ac.execOptions.Container = selectedPod.Spec.Containers[0].Name
	}

	accessRequestsClient, err := accessrequestsclientv1.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("could not create accessrequests client: %w", err)
	}

	currentContext := rawConfig.CurrentContext
	if ac.genericOptions.Context != nil && *ac.genericOptions.Context != "" {
		currentContext = *ac.genericOptions.Context
	}
	if currentContext == "" {
		return fmt.Errorf("no context set")
	}
	userName := rawConfig.Contexts[currentContext].AuthInfo

	if ac.onBehalfOf != "" {
		userName = ac.onBehalfOf
	}

	accessRequest := &accessrequestsv1.AccessRequest{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("access-exec-%s-", userName),
			Labels: map[string]string{
				"username": userName,
			},
		},
		Spec: accessrequestsv1.AccessRequestSpec{
			UserInfo: &authenticationv1.UserInfo{
				Username: userName,
			},
			ForObject: accessrequestsv1.AccessRequestForObject{
				Resource: metav1.GroupVersionResource{
					Group:    "",
					Version:  "v1",
					Resource: "pods",
				},
				SubResource: "exec",
				Namespace:   namespace,
				Name:        selectedPod.Name,
			},
			ExecOptions: &corev1.PodExecOptions{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "PodExecOptions",
				},
				Stdout:    true,
				Stderr:    true,
				Stdin:     false,
				TTY:       false,
				Container: ac.execOptions.Container,
				Command:   ac.execOptions.Command,
			},
			CustomKeys: ac.customKeys,
		},
	}

	if ac.validFor != 0 {
		accessRequest.Spec.ValidFor = ac.validFor.Round(time.Minute).String()
	}

	accessRequest, err = accessRequestsClient.AccessRequests(namespace).Create(context.Background(), accessRequest, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("could not create access request: %w", err)
	}

	fmt.Println("created accessrequest", accessRequest.Name, "(please wait for an admin to grant the permission)")

	return nil
}

func (ac *accessCommand) Grant(cmd *cobra.Command, requestName string) error {
	config, err := ac.genericOptions.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("could not get config: %w", err)
	}

	configLoader := ac.genericOptions.ToRawKubeConfigLoader()
	rawConfig, err := configLoader.RawConfig()
	if err != nil {
		return err
	}
	namespace, _, err := configLoader.Namespace()
	if err != nil {
		return err
	}

	accessRequestsClient, err := accessrequestsclientv1.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("could not create accessrequests client: %w", err)
	}

	currentContext := rawConfig.CurrentContext
	if ac.genericOptions.Context != nil {
		currentContext = *ac.genericOptions.Context
	}
	userName := rawConfig.Contexts[currentContext].AuthInfo

	accessRequest, err := accessRequestsClient.AccessRequests(namespace).Get(context.Background(), requestName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("could not get accessrequest: %w", err)
	}

	// remove this field which contains no useful information for this and makes the output much longer than it needs to be
	accessRequest.ManagedFields = nil

	// TODO: get this set automatically by the client
	accessRequest.SetGroupVersionKind(schema.GroupVersionKind{Version: "v1", Group: "spreadgroup.com", Kind: "AccessRequest"})
	printer := &printers.YAMLPrinter{}
	err = printer.PrintObj(accessRequest, os.Stdout)
	if err != nil {
		return fmt.Errorf("could not print object: %w", err)
	}

	duration := "once"
	if accessRequest.Spec.ValidFor != "" {
		duration = fmt.Sprintf("for %s", accessRequest.Spec.ValidFor)
	}
	command := fmt.Sprintf("%q", accessRequest.Spec.ExecOptions.Command)
	if len(accessRequest.Spec.ExecOptions.Command) == 0 {
		command = "ANY command"
	}
	fmt.Println("---")
	fmt.Printf(`%q requested by %q

- requesting access to %q and container %q in namespace %q
- to run %s
- %s
`,
		accessRequest.Name, accessRequest.Spec.UserInfo.Username,
		accessRequest.Spec.ForObject.Name, accessRequest.Spec.ExecOptions.Container, accessRequest.Spec.ForObject.Namespace,
		command,
		duration,
	)
	fmt.Println()

	fmt.Print("Grant access to the request above ([yN])? ")
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return fmt.Errorf("no answer")
	}
	if scanner.Text() != "y" && scanner.Text() != "Y" {
		return fmt.Errorf("access not granted, exiting")
	}

	// blockOwnerDeletion := true
	accessGrant := &accessrequestsv1.AccessGrant{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grant-" + accessRequest.Name,
			Namespace: namespace,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "spreadgroup.com/v1",
					Kind:       "AccessRequest",
					UID:        accessRequest.UID,
					Name:       accessRequest.Name,
					// BlockOwnerDeletion: &blockOwnerDeletion,
				},
			},
		},
		Spec: accessrequestsv1.AccessGrantSpec{
			GrantFor: accessRequest.Name,
			GrantedBy: &authenticationv1.UserInfo{
				Username: userName,
			},
		},
		Status: accessrequestsv1.AccessGrantGranted,
	}
	accessGrant, err = accessRequestsClient.AccessGrants(namespace).Create(context.Background(), accessGrant, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("could not create access grant: %w", err)
	}

	fmt.Println("created grant", accessGrant.Name)

	return nil
}
