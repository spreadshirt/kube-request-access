# kubectl-audit

Let's make `kubectl exec` and friends auditable!

## Development

Run `./scripts/run` to get a full local development environment.  It sets up a local
k3d cluster if it does not exist yet and deploys everything necessary to run to it.

Then you can run `kubectl exec -it deployment/nginx -- /bin/sh` and similar commands
to check things locally.
