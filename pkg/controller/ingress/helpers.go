package ingress

import (
	"fmt"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/labels"

	"github.com/aws/aws-sdk-go/service/apigateway"
	"github.com/aws/aws-sdk-go/service/apigateway/apigatewayiface"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	cfn "github.com/awslabs/amazon-apigateway-ingress-controller/pkg/cloudformation"
	extensionsv1beta1 "k8s.io/api/extensions/v1beta1"
)

func getWAFScope(ingress *extensionsv1beta1.Ingress) string {
	//Defualt type will be REGIONAL
	var wafScope string = ingress.ObjectMeta.Annotations[IngressAnnotationWAFScope]
	if wafScope == "" {
		wafScope = "REGIONAL"
	}
	return wafScope
}

func getAPIEndpointType(ingress *extensionsv1beta1.Ingress) string {
	//Defualt type will be EDGE
	var endpointType string = ingress.ObjectMeta.Annotations[IngressAnnotationEndpointType]
	if endpointType == "" {
		endpointType = "EDGE"
	}
	return endpointType
}

func getWAFEnabled(ingress *extensionsv1beta1.Ingress) bool {
	var wafEnabledStr string = ingress.ObjectMeta.Annotations[IngressAnnotationWAFEnabled]
	var wafEnabled bool
	var err error
	if wafEnabledStr == "" {
		wafEnabled = false
	} else {
		wafEnabled, err = strconv.ParseBool(wafEnabledStr)
		if err != nil {
			wafEnabled = false
		}
	}
	return wafEnabled
}

func getWAFRulesJSON(ingress *extensionsv1beta1.Ingress) string {
	return ingress.ObjectMeta.Annotations[IngressAnnotationWAFRulesCFJson]
}

func getCustomDomainName(ingress *extensionsv1beta1.Ingress) string {
	return ingress.ObjectMeta.Annotations[IngressAnnotationCustomDomainName]
}

func getCertificateArn(ingress *extensionsv1beta1.Ingress) string {
	return ingress.ObjectMeta.Annotations[IngressAnnotationCertificateArn]
}

func getHostedZoneName(ingress *extensionsv1beta1.Ingress) string {
	return ingress.ObjectMeta.Annotations[IngressAnnotationHostedZoneName]
}

func getNodeSelector(ingress *extensionsv1beta1.Ingress) labels.Selector {
	s, err := labels.Parse(ingress.ObjectMeta.Annotations[IngressAnnotationNodeSelector])
	if err != nil {
		return DefaultNodeSelector
	}

	return s
}

func getRoute53AccountRole(ingress *extensionsv1beta1.Ingress) string {
	return ingress.ObjectMeta.Annotations[IngressAnnotationAssumeRoute53RoleArn]
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

func getCustomDomainCreatedHostname(mainStack *cloudformation.Stack) string {
	return cfn.StackOutputMap(mainStack)[cfn.OutputKeyCustomDomainHostName]
}

func getCustomDomainCreatedHostedZoneID(mainStack *cloudformation.Stack) string {
	return cfn.StackOutputMap(mainStack)[cfn.OutputKeyCustomDomainHostedZoneID]
}

func getNginxReplicas(ingress *extensionsv1beta1.Ingress) int {
	replicas := ingress.ObjectMeta.Annotations[IngressAnnotationNginxReplicas]
	r, err := strconv.Atoi(replicas)
	if err != nil {
		return DefaultNginxReplicas
	}

	return r
}

func shouldUpdateRoute53(mainStack *cloudformation.Stack, stack *cloudformation.Stack, instance *extensionsv1beta1.Ingress) bool {
	if cfn.StackOutputMap(stack)[cfn.OutputKeyHostedZone] != getHostedZoneName(instance) {
		return true
	}
	return false
}

func shouldUpdate(stack *cloudformation.Stack, instance *extensionsv1beta1.Ingress, apigw apigatewayiface.APIGatewayAPI) bool {
	if cfn.StackOutputMap(stack)[cfn.OutputKeyClientARNS] != strings.Join(getArns(instance), ",") {
		return true
	}

	if !(cfn.StackOutputMap(stack)[cfn.OutputKeyWAFEnabled] == "" && !getWAFEnabled(instance)) {
		if cfn.StackOutputMap(stack)[cfn.OutputKeyWAFEnabled] != fmt.Sprintf("%t", getWAFEnabled(instance)) {
			return true
		}
		if cfn.StackOutputMap(stack)[cfn.OutputKeyWAFScope] != getWAFScope(instance) {
			return true
		}
		if cfn.StackOutputMap(stack)[cfn.OutputKeyWAFRules] != getWAFRulesJSON(instance) {
			return true
		}
	}

	if cfn.StackOutputMap(stack)[cfn.OutputKeyAPIEndpointType] != getAPIEndpointType(instance) {
		return true
	}

	if !(cfn.StackOutputMap(stack)[cfn.OutputKeyWAFEnabled] == "" && !getWAFEnabled(instance)) {
		if cfn.StackOutputMap(stack)[cfn.OutputKeyWAFEnabled] != fmt.Sprintf("%t", getWAFEnabled(instance)) {
			return true
		}
		if cfn.StackOutputMap(stack)[cfn.OutputKeyWAFScope] != getWAFScope(instance) {
			return true
		}
		if cfn.StackOutputMap(stack)[cfn.OutputKeyWAFRules] != getWAFRulesJSON(instance) {
			return true
		}
	}

	if cfn.StackOutputMap(stack)[cfn.OutputKeyCertARN] != getCertificateArn(instance) {
		return true
	}

	if cfn.StackOutputMap(stack)[cfn.OutputKeyCustomDomain] != getCustomDomainName(instance) {
		return true
	}

	apiId := cfn.StackOutputMap(stack)[cfn.OutputKeyRestAPIID]
	var getResourceInput apigateway.GetResourcesInput
	var limit int64
	limit = 500
	method := "methods"
	embed := []*string{&method}
	getResourceInput.RestApiId = &apiId
	getResourceInput.Limit = &limit
	getResourceInput.Embed = embed
	apiResources, error := apigw.GetResources(&getResourceInput)

	if error != nil {
		return false
	}

	var items []*apigateway.Resource
	if apiResources != nil {
		items = apiResources.Items
	}

	if items != nil {
		for _, ingressRule := range instance.Spec.Rules {
			if ingressRule.HTTP == nil {
				continue
			}

			//To identity newly added paths
			for _, path := range ingressRule.HTTP.Paths {
				var needUpdates bool = true
				for _, apiItem := range items {
					if strings.Compare(path.Path, *apiItem.Path) == 0 {
						needUpdates = false
						break
					}
				}
				if needUpdates {
					return true
				}
			}

			//To identity removed paths
			for _, apiItem := range items {
				var needUpdates bool = true
				for _, path := range ingressRule.HTTP.Paths {
					if strings.HasPrefix(*apiItem.Path, path.Path) || strings.HasPrefix(path.Path, *apiItem.Path) {
						needUpdates = false
						break
					}
				}
				if needUpdates {
					return true
				}
			}

		}
	}

	return false
}

func createReverseProxyResourceName(name string) string {
	return fmt.Sprintf("%s-reverse-proxy", name)
}
