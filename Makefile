DEPLOYMENT_TAG:=$(shell git log -1 --pretty=format:%cd.%H --date=short)

all: kube-request-access local-config

kube-request-access: Makefile *.go
	CGO_ENABLED=0 go build .
	
local-config: dev/localhost.crt dev/localhost.key dev/validating-admission-webhook.yaml

dev/localhost.crt dev/localhost.key:
	openssl req -x509 -out dev/localhost.crt -keyout dev/localhost.key \
		-newkey rsa:2048 -nodes -sha256 \
		-subj '/CN=kube-request-access.default.svc' -extensions EXT -config <( \
		printf "[dn]\nCN=kube-request-access.default.svc\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:kube-request-access.default.svc,DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")

dev/validating-admission-webhook.yaml: dev/localhost.crt
	sed -i -E 's/^(\s+)caBundle: "(.*)"(\s+)# CA_BUNDLE/\1caBundle: "'$$(base64 --wrap=0 dev/localhost.crt)'"\3# CA_BUNDLE/' dev/validating-admission-webhook.yaml
	
generate-code: apis/accessrequests/v1/zz_generated.deepcopy.go

apis/accessrequests/v1/zz_generated.deepcopy.go: Makefile apis/accessrequests/v1/access_request.go apis/accessrequests/v1/access_grant.go
	# setup fake gopath so that the code generation can work
	mkdir -p  .go/src/github.com/spreadshirt
	ln -sf $$PWD .go/src/github.com/spreadshirt
	
	# generate the code!
	GOPATH=$$PWD/.go ./code-generator/generate-groups.sh deepcopy,client github.com/spreadshirt/kube-request-access/apis/generated github.com/spreadshirt/kube-request-access/apis accessrequests:v1 --go-header-file /dev/null

docker: kube-request-access
	docker build -t kube-request-access:local -t registry.spreadgroup.com/sprd/kube-request-access:$(DEPLOYMENT_TAG) .
	
publish: docker
	docker push registry.spreadgroup.com/sprd/kube-request-access:$(DEPLOYMENT_TAG)
