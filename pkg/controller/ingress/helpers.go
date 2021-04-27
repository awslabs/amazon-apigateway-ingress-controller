package ingress

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/aws/aws-sdk-go/service/apigateway"
	"github.com/aws/aws-sdk-go/service/apigateway/apigatewayiface"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	cfn "github.com/awslabs/amazon-apigateway-ingress-controller/pkg/cloudformation"
	extensionsv1beta1 "k8s.io/api/extensions/v1beta1"
)

func getS3BucketName(ingress *extensionsv1beta1.Ingress) string {
	return ingress.ObjectMeta.Annotations[IngressAnnotationCFS3BucketName]
}

func getLoggingLevel(ingress *extensionsv1beta1.Ingress) string {
	return ingress.ObjectMeta.Annotations[IngressAnnotationLoggingLevel]
}

func getS3ObjectKey(ingress *extensionsv1beta1.Ingress) string {
	return ingress.ObjectMeta.Annotations[IngressAnnotationCFS3ObjectKey]
}

func getRequestTimeout(ingress *extensionsv1beta1.Ingress) int {
	var requetTimeoutStr string = ingress.ObjectMeta.Annotations[IngressAnnotationRequestTimeout]
	requetTimeout, err := strconv.Atoi(requetTimeoutStr)
	if err != nil {
		requetTimeout = 29000
	}
	return requetTimeout
}

func getTLSPolicy(ingress *extensionsv1beta1.Ingress) string {
	var tlsPolicy string = ingress.ObjectMeta.Annotations[IngressAnnotationTLSPolicy]
	if tlsPolicy == "" || (tlsPolicy != "TLS_1_0" && tlsPolicy != "TLS_1_2") {
		tlsPolicy = "TLS_1_0"
	}
	return tlsPolicy
}

func getUsagePlans(ingress *extensionsv1beta1.Ingress) []cfn.UsagePlan {
	var usagePlansStr string = ingress.ObjectMeta.Annotations[IngressAnnotationAPIKeyBasedUsagePlans]
	if usagePlansStr == "" {
		return nil
	}
	var usagePlans []cfn.UsagePlan
	err := json.Unmarshal([]byte(usagePlansStr), &usagePlans)
	if err != nil {
		return nil
	}
	return usagePlans
}

func getAPIResources(ingress *extensionsv1beta1.Ingress) []cfn.APIResource {
	var apiResourcesStr string = ingress.ObjectMeta.Annotations[IngressAnnotationPublicResources]
	if apiResourcesStr == "" {
		return nil
	}
	var apiResources []cfn.APIResource
	err := json.Unmarshal([]byte(apiResourcesStr), &apiResources)
	if err != nil {
		return nil
	}
	return apiResources
}

func getAWSAPIConfigs(ingress *extensionsv1beta1.Ingress) []cfn.AWSAPIDefinition {
	var awsAPIConfigStr string = ingress.ObjectMeta.Annotations[IngressAnnotationAWSAPIConfigs]
	if awsAPIConfigStr == "" {
		return nil
	}
	var awsAPIConfigs []cfn.AWSAPIDefinition
	err := json.Unmarshal([]byte(awsAPIConfigStr), &awsAPIConfigs)
	if err != nil {
		return nil
	}
	return awsAPIConfigs
}

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

func getCacheSize(ingress *extensionsv1beta1.Ingress) string {
	return ingress.ObjectMeta.Annotations[IngressAnnotationGWCacheSize]
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

func getGWCacheEnabled(ingress *extensionsv1beta1.Ingress) bool {
	var cacheEnabledStr string = ingress.ObjectMeta.Annotations[IngressAnnotationGWCacheEnabled]
	var cacheEnabled bool
	var err error
	if cacheEnabledStr == "" {
		cacheEnabled = false
	} else {
		cacheEnabled, err = strconv.ParseBool(cacheEnabledStr)
		if err != nil {
			cacheEnabled = false
		}
	}
	return cacheEnabled
}

func getCompressionSize(ingress *extensionsv1beta1.Ingress) int {
	maxCompressSize := ingress.ObjectMeta.Annotations[IngressAnnotationMinimumCompressionSize]
	if maxCompressSize == "" {
		return 0
	} else {
		i, err := strconv.Atoi(maxCompressSize)
		if err == nil {
			return i
		}
	}
	return 0
}

func getWAFRulesJSON(ingress *extensionsv1beta1.Ingress) string {
	return ingress.ObjectMeta.Annotations[IngressAnnotationWAFRulesCFJson]
}

func getCustomDomainBasePath(ingress *extensionsv1beta1.Ingress) string {
	return ingress.ObjectMeta.Annotations[IngressAnnotationCustomDomainBasePath]
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
	arns := ingress.ObjectMeta.Annotations[IngressAnnotationClientArns]
	if arns == "" {
		return []string{}
	} else {
		return strings.Split(arns, ",")
	}
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
	if cfn.StackOutputMap(mainStack)[cfn.OutputKeyCustomDomainHostName] != cfn.StackOutputMap(stack)[cfn.OutputKeyCustomDomainHostName] {
		return true
	}
	if cfn.StackOutputMap(mainStack)[cfn.OutputKeyCustomDomain] != cfn.StackOutputMap(stack)[cfn.OutputKeyCustomDomain] {
		return true
	}
	return false
}

func shouldUpdateWAF(stack *cloudformation.Stack) bool {
	if cfn.StackOutputMap(stack)[cfn.OutputKeyWAFEnabled] != "" && cfn.StackOutputMap(stack)[fmt.Sprintf("%s%d", cfn.OutputKeyWAFAssociationCreated, 0)] == "" {
		return true
	}
	return false
}

func shouldUpdate(stack *cloudformation.Stack, instance *extensionsv1beta1.Ingress, apigw apigatewayiface.APIGatewayAPI, r *ReconcileIngress) bool {
	if cfn.StackOutputMap(stack)[cfn.OutputKeyClientARNS] != strings.Join(getArns(instance), ",") {
		r.log.Info("Client Arns not matching, Should Update",
			zap.String("Input", strings.Join(getArns(instance), ",")),
			zap.String("Output", cfn.StackOutputMap(stack)[cfn.OutputKeyClientARNS]))
		return true
	}

	if !(cfn.StackOutputMap(stack)[cfn.OutputKeyWAFEnabled] == "" && !getWAFEnabled(instance)) {
		if cfn.StackOutputMap(stack)[cfn.OutputKeyWAFEnabled] != fmt.Sprintf("%t", getWAFEnabled(instance)) {
			r.log.Info("WAF Enabled Status not matching, Should Update",
				zap.String("Input", fmt.Sprintf("%t", getWAFEnabled(instance))),
				zap.String("Output", cfn.StackOutputMap(stack)[cfn.OutputKeyWAFEnabled]))
			return true
		}
		if cfn.StackOutputMap(stack)[cfn.OutputKeyWAFScope] != getWAFScope(instance) {
			r.log.Info("WAF Scope not matching, Should Update",
				zap.String("Input", getWAFScope(instance)),
				zap.String("Output", cfn.StackOutputMap(stack)[cfn.OutputKeyWAFScope]))
			return true
		}
		if cfn.StackOutputMap(stack)[cfn.OutputKeyWAFRules] != getWAFRulesJSON(instance) {
			r.log.Info("WAF Rules not matching, Should Update",
				zap.String("Input", getWAFRulesJSON(instance)),
				zap.String("Output", cfn.StackOutputMap(stack)[cfn.OutputKeyWAFRules]))
			return true
		}
	}

	if cfn.StackOutputMap(stack)[cfn.OutputKeyWAFEnabled] != "" && cfn.StackOutputMap(stack)[fmt.Sprintf("%s%d", cfn.OutputKeyWAFAssociationCreated, 0)] == "" {
		r.log.Info("WAF Association Status not matching, Should Update",
			zap.String("OutputKeyWAFEnabled", cfn.StackOutputMap(stack)[cfn.OutputKeyWAFEnabled]),
			zap.String("OutputKeyWAFAssociationCreated", cfn.StackOutputMap(stack)[fmt.Sprintf("%s%d", cfn.OutputKeyWAFAssociationCreated, 0)]))
		return true
	}

	if cfn.StackOutputMap(stack)[cfn.OutputKeyAPIEndpointType] != getAPIEndpointType(instance) {
		r.log.Info("API EP type not matching, Should Update",
			zap.String("Input", getAPIEndpointType(instance)),
			zap.String("Output", cfn.StackOutputMap(stack)[cfn.OutputKeyAPIEndpointType]))
		return true
	}

	if cfn.StackOutputMap(stack)[cfn.OutputKeyCertARN] != getCertificateArn(instance) {
		r.log.Info("SSL Cert Arn not matching, Should Update",
			zap.String("Input", getCertificateArn(instance)),
			zap.String("Output", cfn.StackOutputMap(stack)[cfn.OutputKeyCertARN]))
		return true
	}

	if cfn.StackOutputMap(stack)[cfn.OutputKeyCustomDomain] != getCustomDomainName(instance) {
		r.log.Info("Custom Domain not matching, Should Update",
			zap.String("Input", getCustomDomainName(instance)),
			zap.String("Output", cfn.StackOutputMap(stack)[cfn.OutputKeyCustomDomain]))
		return true
	}

	if cfn.StackOutputMap(stack)[cfn.OutputLoggingLevel] != getLoggingLevel(instance) {
		r.log.Info("LoggingLevel not matching, Should Update",
			zap.String("Input", getLoggingLevel(instance)),
			zap.String("Output", cfn.StackOutputMap(stack)[cfn.OutputLoggingLevel]))
		return true
	}

	if cfn.StackOutputMap(stack)[cfn.OutputKeyCustomDomainBasePath] != getCustomDomainBasePath(instance) {
		r.log.Info("Custom Domain Base Path not matching, Should Update",
			zap.String("Input", getCustomDomainBasePath(instance)),
			zap.String("Output", cfn.StackOutputMap(stack)[cfn.OutputKeyCustomDomainBasePath]))
		return true
	}

	if cfn.StackOutputMap(stack)[cfn.OutputKeyRequestTimeout] != fmt.Sprintf("%d", getRequestTimeout(instance)) {
		r.log.Info("Request timeout not matching, Should Update",
			zap.String("Input", fmt.Sprintf("%d", getRequestTimeout(instance))),
			zap.String("Output", cfn.StackOutputMap(stack)[cfn.OutputKeyRequestTimeout]))
		return true
	}

	if getCustomDomainName(instance) != "" && cfn.StackOutputMap(stack)[cfn.OutputKeyTLSPolicy] != getTLSPolicy(instance) {
		r.log.Info("TLS policy not matching, Should Update",
			zap.String("Input", getTLSPolicy(instance)),
			zap.String("Output", cfn.StackOutputMap(stack)[cfn.OutputKeyTLSPolicy]))
		return true
	}

	outAWSAPIConfigsStr := cfn.StackOutputMap(stack)[cfn.OutputKeyAWSAPIConfigs]
	awsAPIConfigs := getAWSAPIConfigs(instance)
	awsAPIConfigBytes, _ := json.Marshal(awsAPIConfigs)
	awsAPIConfigsStr := string(awsAPIConfigBytes)
	if awsAPIConfigs != nil && outAWSAPIConfigsStr == "" {
		r.log.Info("AWS API Configs added, Should Update")
		return true
	} else if awsAPIConfigs == nil && outAWSAPIConfigsStr != "" {
		r.log.Info("AWS API Configs removed, Should Update")
		return true
	} else if awsAPIConfigs != nil && outAWSAPIConfigsStr != "" && outAWSAPIConfigsStr != awsAPIConfigsStr {
		r.log.Info("AWS API Configs changed, Should Update",
			zap.String("Input", awsAPIConfigsStr),
			zap.String("Output", outAWSAPIConfigsStr))
		return true
	}

	outUsagePlansStr := cfn.StackOutputMap(stack)[cfn.OutputKeyUsagePlans]
	usagePlans := getUsagePlans(instance)
	usagePlansBytes, _ := json.Marshal(usagePlans)
	usagePlansStr := string(usagePlansBytes)
	if usagePlans != nil && outUsagePlansStr == "" {
		r.log.Info("Usage plans added, Should Update")
		return true
	} else if usagePlans == nil && outUsagePlansStr != "" {
		r.log.Info("Usage plans removed, Should Update")
		return true
	} else if usagePlans != nil && outUsagePlansStr != "" && outUsagePlansStr != usagePlansStr {
		r.log.Info("Usage plans changed, Should Update",
			zap.String("Input", usagePlansStr),
			zap.String("Output", outUsagePlansStr))
		return true
	}

	outAPIResourcesStr := cfn.StackOutputMap(stack)[cfn.OutputKeyAPIResources]
	apiResources := getAPIResources(instance)
	apiResourcesBytes, _ := json.Marshal(apiResources)
	apiResourcesStr := string(apiResourcesBytes)
	if apiResources != nil && outAPIResourcesStr == "" {
		r.log.Info("API Resources added, Should Update")
		return true
	} else if apiResources == nil && outAPIResourcesStr != "" {
		r.log.Info("API Resources removed, Should Update")
		return true
	} else if apiResources != nil && outAPIResourcesStr != "" && outAPIResourcesStr != apiResourcesStr {
		r.log.Info("API Resources changed, Should Update",
			zap.String("Input", apiResourcesStr),
			zap.String("Output", outAPIResourcesStr))
		return true
	}

	if cfn.StackOutputMap(stack)[cfn.OutputMinimumCompressionSize] == "" && getCompressionSize(instance) == 0 {
		r.log.Debug("Minimum Compression Size not set. Should Update not triggered",
			zap.String("Input", fmt.Sprintf("%d", getCompressionSize(instance))),
			zap.String("Output", cfn.StackOutputMap(stack)[cfn.OutputMinimumCompressionSize]))
	} else if cfn.StackOutputMap(stack)[cfn.OutputMinimumCompressionSize] == "" && getCompressionSize(instance) > 0 {
		r.log.Info("Minimum Compression Size added, Should Update",
			zap.String("Input", fmt.Sprintf("%d", getCompressionSize(instance))),
			zap.String("Output", cfn.StackOutputMap(stack)[cfn.OutputMinimumCompressionSize]))
		return true
	} else if cfn.StackOutputMap(stack)[cfn.OutputMinimumCompressionSize] != "" && getCompressionSize(instance) == 0 {
		r.log.Info("Minimum Compression Size removed, Should Update",
			zap.String("Input", fmt.Sprintf("%d", getCompressionSize(instance))),
			zap.String("Output", cfn.StackOutputMap(stack)[cfn.OutputMinimumCompressionSize]))
		return true
	} else if cfn.StackOutputMap(stack)[cfn.OutputMinimumCompressionSize] != fmt.Sprintf("%d", getCompressionSize(instance)) {
		r.log.Info("Minimum Compression Size not matching, Should Update",
			zap.String("Input", fmt.Sprintf("%d", getCompressionSize(instance))),
			zap.String("Output", cfn.StackOutputMap(stack)[cfn.OutputMinimumCompressionSize]))
		return true
	}

	if awsAPIConfigs == nil && outAWSAPIConfigsStr == "" && apiResources == nil && outAPIResourcesStr == "" && checkProxyPaths(stack, instance, apigw) {
		r.log.Info("Rules are not matching, Should Update")
		return true
	} else {
		r.log.Debug("Rules are matching, Should Update not triggered.")
	}

	rulePaths, err := json.Marshal(instance.Spec.Rules[0].HTTP.Paths)
	var rulePathsStr string
	if err != nil {
		rulePathsStr = ""
	} else {
		rulePathsStr = string(rulePaths)
	}

	if ((awsAPIConfigs != nil || outAWSAPIConfigsStr != "") || (apiResources != nil || outAPIResourcesStr != "")) && rulePathsStr != cfn.StackOutputMap(stack)[cfn.OutputKeyIngressRules] {
		r.log.Info("Rules in Outputs are not matching, Should Update")
		return true
	} else {
		r.log.Debug("Rules in Outputs are matching, Should Update not triggered.")
	}

	if getGWCacheEnabled(instance) && cfn.StackOutputMap(stack)[cfn.OutputKeyCachingEnabled] != fmt.Sprintf("%t", getGWCacheEnabled(instance)) {
		r.log.Info("Cache Enabled Status not matching, Should Update",
			zap.String("Input", fmt.Sprintf("%t", getGWCacheEnabled(instance))),
			zap.String("Output", cfn.StackOutputMap(stack)[cfn.OutputKeyCachingEnabled]))
		return true
	} else if !getGWCacheEnabled(instance) && cfn.StackOutputMap(stack)[cfn.OutputKeyCachingEnabled] != "" {
		r.log.Info("Cache Enabled Status not matching, Should Update",
			zap.String("Input", fmt.Sprintf("%t", getGWCacheEnabled(instance))),
			zap.String("Output", cfn.StackOutputMap(stack)[cfn.OutputKeyCachingEnabled]))
		return true
	}

	if cfn.StackOutputMap(stack)[cfn.OutputKeyCacheClusterSize] != getCacheSize(instance) {
		r.log.Info("Cache Size not matching, Should Update",
			zap.String("Input", getCacheSize(instance)),
			zap.String("Output", cfn.StackOutputMap(stack)[cfn.OutputKeyCacheClusterSize]))
		return true
	}
	return false
}

func checkProxyPaths(stack *cloudformation.Stack, instance *extensionsv1beta1.Ingress, apigw apigatewayiface.APIGatewayAPI) bool {
	apiId := cfn.StackOutputMap(stack)[fmt.Sprintf("%s%d", cfn.OutputKeyRestAPIID, 0)]
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
				apiPath := strings.Replace(*apiItem.Path, "/{proxy+}", "", -1)
				for _, path := range ingressRule.HTTP.Paths {
					if strings.Compare(path.Path, apiPath) == 0 || strings.HasPrefix(path.Path, *apiItem.Path) {
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
