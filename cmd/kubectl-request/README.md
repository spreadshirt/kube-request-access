# kubectl-request

`kubectl-request` is a kubectl plugin that manages the `AccessRequest` and `AccessGrant` CRDs
which `kube-request-access` uses to grant access to `kubectl exec`.

## Installation

Download the [latest release](https://github.com/spreadshirt/kube-request-access/releases/latest) and put the
`kubectl-request` binary somewhere in your `PATH`.

After that you can use it as `kubectl request`.

## Usage

- request access using `kubectl request exec ...`
  - by default, access is requested to run the specified command once
  - you can also request access to run the given command multiple times for a duration using `--valid-for`
- wait for an admin to grant permissions (or deny them)
- run the command you requested access for using `kubectl exec` as usual

Here's the full `kubectl request --help` message for reference:

```
Request and grant access to `kubectl exec` and friends

Usage:
  kubectl-request [command]

Examples:

        # request access
        kubectl request exec deployment/nginx ls -l /tmp

        # grant access
        kubectl request grant <name>


Available Commands:
  exec        Request access to execute a command in a container.
  grant       Grant access to the given request
  help        Help about any command
  completion  generate the autocompletion script for the specified shell

Flags:
      --as string                      Username to impersonate for the operation. User could be a regular user or a service account in a namespace.
      --as-group stringArray           Group to impersonate for the operation, this flag can be repeated to specify multiple groups.
      --as-uid string                  UID to impersonate for the operation.
      --cache-dir string               Default cache directory (default "/home/luna/.kube/cache")
      --certificate-authority string   Path to a cert file for the certificate authority
      --client-certificate string      Path to a client certificate file for TLS
      --client-key string              Path to a client key file for TLS
      --cluster string                 The name of the kubeconfig cluster to use
      --context string                 The name of the kubeconfig context to use
  -h, --help                           help for kubectl-request
      --insecure-skip-tls-verify       If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure
      --kubeconfig string              Path to the kubeconfig file to use for CLI requests.
  -n, --namespace string               If present, the namespace scope for this CLI request
      --request-timeout string         The length of time to wait before giving up on a single server request. Non-zero values should contain a corresponding time unit (e.g. 1s, 2m, 3h). A value of zero means don't timeout requests. (default "0")
  -s, --server string                  The address and port of the Kubernetes API server
      --tls-server-name string         Server name to use for server certificate validation. If it is not provided, the hostname used to contact the server is used
      --token string                   Bearer token for authentication to the API server
      --user string                    The name of the kubeconfig user to use
  -v, --version                        version for kubectl-request

Use "kubectl-request [command] --help" for more information about a command.
```
