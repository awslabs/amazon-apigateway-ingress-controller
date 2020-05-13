GO111MODULE=on
# Image URL to use all building/pushing image targets
IMG ?= controller:latest

all: test manager

# Run tests
test: generate fmt vet manifests
	go test ./pkg/... ./cmd/... -coverprofile cover.out

# Build manager binary
manager: generate fmt vet
	go build -mod=vendor -o bin/manager github.com/awslabs/amazon-apigateway-ingress-controller/cmd/manager

# Run against the configured Kubernetes cluster in ~/.kube/config
run: generate fmt vet
	go run ./cmd/manager/main.go

# Install CRDs into a cluster
install: manifests
	kubectl apply -f config/crds

# Deploy controller in the configured Kubernetes cluster in ~/.kube/config
deploy: manifests
	kustomize build config/default | kubectl apply -f -

# Generate manifests e.g. CRD, RBAC etc.
manifests:
	go run vendor/sigs.k8s.io/controller-tools/cmd/controller-gen/main.go rbac

# Run go fmt against code
fmt:
	go fmt ./pkg/... ./cmd/...

# Run go vet against code
vet:
	go vet ./pkg/... ./cmd/...

# Generate code
generate:
ifndef GOPATH
	$(error GOPATH not defined, please define GOPATH. Run "go help gopath" to learn more about GOPATH)
endif
	go generate ./pkg/... ./cmd/...

# Build the docker image
docker-build: test
	docker build . -t ${IMG}
	@echo "updating kustomize image patch file for manager resource"
	sed -i '' -e 's@image: .*@image: '"${IMG}"'@' -e 's@iam.amazonaws.com/role: .*@iam.amazonaws.com/role: '"${IAMROLEARN}"'@' ./config/default/manager_image_patch.yaml

# Push the docker image
docker-push:
	docker push ${IMG}

iam:
ifndef INSTANCE_ROLE_ARNS
	$(error INSTANCE_ROLE_ARNS not defined, please provide a comma delimited list of ARNS for AssumeRole privileges)
endif
	aws cloudformation create-stack \
    --stack-name amazon-apigateway-ingress-controller-role \
    --capabilities CAPABILITY_NAMED_IAM \
    --template-body file://config/iam/role.yaml \
    --parameters \
      ParameterKey=InstanceRoleArns,ParameterValue="'${INSTANCE_ROLE_ARNS}'"
