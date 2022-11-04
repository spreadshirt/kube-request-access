package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"

	accessrequestsv1 "git.spreadomat.net/deleng/kubectl-audit/apis/accessrequests/v1"
	accessrequestsclientv1 "git.spreadomat.net/deleng/kubectl-audit/apis/generated/clientset/versioned/typed/accessrequests/v1"
)

func main() {
	// turning this off displays our subcommands first (instead of help and completion first)
	cobra.EnableCommandSorting = false

	// 	flags := pflag.NewFlagSet("kubectl-ns", pflag.ExitOnError)
	// pflag.CommandLine = flags

	cmd := &cobra.Command{
		Use:   "access",
		Short: "Request and grant access to `kubectl exec` and friends",
		Example: `
	# request access
	kubectl access request exec deployment/api-core ls -l /tmp

	# grant access
	kubectl access grant <name>
`,
		Args: cobra.MinimumNArgs(1),
	}

	accessCommand := &accessCommand{
		execOptions: &execOptions{},
	}
	accessCommand.genericOptions = genericclioptions.NewConfigFlags(true)
	accessCommand.genericOptions.AddFlags(cmd.PersistentFlags())

	requestCmd := &cobra.Command{
		Use:   "request <cmd> [flags-and-args]",
		Short: "Request access to `kubectl <cmd>`",
		Args:  cobra.MinimumNArgs(1),
	}
	cmd.AddCommand(requestCmd)

	requestExecCmd := &cobra.Command{
		Use:          "exec (POD | TYPE/NAME) [-c CONTAINER] [flags] -- COMMAND [args...] [options]",
		Short:        "Request access to execute a command in a container.",
		Args:         cobra.MinimumNArgs(2),
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
	requestCmd.AddCommand(requestExecCmd)

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

type accessCommand struct {
	genericOptions *genericclioptions.ConfigFlags

	execOptions *execOptions
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

	var podName string

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

		podName = pod.Name
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

		podName = pods.Items[0].Name
	default:
		return fmt.Errorf("unsupported kind %q", kind)

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

	accessRequest := &accessrequestsv1.AccessRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("access-exec-%s-%s", userName, ac.execOptions.Command[0]),
		},
		Spec: accessrequestsv1.AccessRequestSpec{
			UserInfo: &authenticationv1.UserInfo{
				Username: userName,
			},
			ForObject: accessrequestsv1.AccessRequestForObject{
				Resource: metav1.GroupVersionResource{
					Group:    "",
					Resource: "pods",
				},
				SubResource: "exec",
				Namespace:   namespace,
				Name:        podName,
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
		},
	}
	accessRequest, err = accessRequestsClient.AccessRequests(namespace).Create(context.Background(), accessRequest, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("could not create access request: %w", err)
	}

	fmt.Println("created accessrequest", accessRequest.Name, "(please wait for an admin to grant the permission)")

	return nil
}

func Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func Validate() error {
	return nil
}

func Run() error {
	return nil
}