DEPLOYMENT_TAG:=$(shell git log -1 --pretty=format:%cd.%H --date=short)

all: kubectl-audit

kubectl-audit: Makefile *.go
	CGO_ENABLED=0 go build .
	
docker: kubectl-audit
	docker build -t registry.spreadgroup.com/sprd/kubectl-audit:local -t registry.spreadgroup.com/sprd/kubectl-audit:$(DEPLOYMENT_TAG) .
	
publish: docker
	docker push registry.spreadgroup.com/sprd/kubectl-audit:$(DEPLOYMENT_TAG)
