module github.com/awslabs/amazon-apigateway-ingress-controller

go 1.14

require (
	github.com/aws/aws-sdk-go v1.34.18
	github.com/awslabs/goformation/v4 v4.8.0
	github.com/onsi/gomega v1.10.0
	go.uber.org/zap v1.15.0
	k8s.io/api v0.18.2
	k8s.io/apimachinery v0.18.2
	k8s.io/client-go v0.18.2
	sigs.k8s.io/controller-runtime v0.6.0
	sigs.k8s.io/controller-tools v0.3.0 // indirect
)
