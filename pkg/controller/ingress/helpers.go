package ingress

import (
	"fmt"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/labels"

	"github.com/aws/aws-sdk-go/service/cloudformation"
	cfn "github.com/awslabs/amazon-apigateway-ingress-controller/pkg/cloudformation"
	extensionsv1beta1 "k8s.io/api/extensions/v1beta1"
)

func getCustomDomainName(ingress *extensionsv1beta1.Ingress) string {
	return ingress.ObjectMeta.Annotations[IngressAnnotationCustomDomainName]
}

func getCertificateArn(ingress *extensionsv1beta1.Ingress) string {
	return ingress.ObjectMeta.Annotations[IngressAnnotationCertificateArn]
}

func getNodeSelector(ingress *extensionsv1beta1.Ingress) labels.Selector {
	s, err := labels.Parse(ingress.ObjectMeta.Annotations[IngressAnnotationNodeSelector])
	if err != nil {
		return DefaultNodeSelector
	}

	return s
}

func getStageName(ingress *extensionsv1beta1.Ingress) string {
	return ingress.ObjectMeta.Annotations[IngressAnnotationStageName]
}

func getArns(ingress *extensionsv1beta1.Ingress) []string {
	return strings.Split(ingress.ObjectMeta.Annotations[IngressAnnotationClientArns], ",")
}

func getNginxImage(ingress *extensionsv1beta1.Ingress) string {
	image, ok := ingress.ObjectMeta.Annotations[IngressAnnotationNginxImage]
	if ok {
		return image
	}

	return DefaultNginxImage
}

func getNginxServicePort(ingress *extensionsv1beta1.Ingress) int {
	port := ingress.ObjectMeta.Annotations[IngressAnnotationNginxServicePort]
	p, err := strconv.Atoi(port)
	if err != nil {
		return DefaultNginxServicePort
	}

	return p
}

func getNginxReplicas(ingress *extensionsv1beta1.Ingress) int {
	replicas := ingress.ObjectMeta.Annotations[IngressAnnotationNginxReplicas]
	r, err := strconv.Atoi(replicas)
	if err != nil {
		return DefaultNginxReplicas
	}

	return r
}

func shouldUpdate(stack *cloudformation.Stack, instance *extensionsv1beta1.Ingress) bool {
	if cfn.StackOutputMap(stack)[cfn.OutputKeyClientARNS] != strings.Join(getArns(instance), ",") {
		return true
	}

	return false
}

func createReverseProxyResourceName(name string) string {
	return fmt.Sprintf("%s-reverse-proxy", name)
}
