# Amazon API Gateway Ingress Controller

## Getting Started

The default configuration assumes you are using kube2iam to manage pod permissions.
To set up a role for this controller use the following command

```sh
export INSTANCE_ROLE_ARNS=`comma delimited list of k8s worker instance ARNs`
make iam
```

To build and deploy the controller

```sh
export IMG=`some ecr repository`
export IAMROLEARN=`the iam role arn created above`

make docker-build
make docker-push
make deploy
```

[Example Ingress](./config/samples/extensions_v1beta1_ingress.yaml)
