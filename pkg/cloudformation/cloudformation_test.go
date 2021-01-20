package cloudformation

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/awslabs/amazon-apigateway-ingress-controller/pkg/network"
	cfn "github.com/awslabs/goformation/v4/cloudformation"
	"github.com/awslabs/goformation/v4/cloudformation/apigateway"
	extensionsv1beta1 "k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func getUsagePlans() []UsagePlan {
	return []UsagePlan{
		{
			PlanName:    "Gold",
			Description: "20 requests for 1 min",
			APIKeys: []APIKey{
				{
					CustomerID:         "customer1",
					GenerateDistinctID: true,
					Name:               "cusKey1",
				},
				{
					CustomerID:         "customer2",
					GenerateDistinctID: true,
					Name:               "cusKey2",
				},
			},
			QuotaLimit:         100,
			QuotaPeriod:        "MONTH",
			ThrottleBurstLimit: 100,
			ThrottleRateLimit:  100,
			MethodThrottlingParameters: []MethodThrottlingParametersObject{
				{
					Path:       "/api/v1/foobar",
					BurstLimit: 100,
					RateLimit:  100,
				},
			},
		},
	}
}

func getUsagePlan() UsagePlan {
	return UsagePlan{
		PlanName:    "Gold",
		Description: "20 requests for 1 min",
		APIKeys: []APIKey{
			{
				CustomerID:         "customer1",
				GenerateDistinctID: true,
				Name:               "cusKey1",
			},
			{
				CustomerID:         "customer2",
				GenerateDistinctID: true,
				Name:               "cusKey2",
			},
		},
		QuotaLimit:                 100,
		QuotaPeriod:                "MONTH",
		ThrottleBurstLimit:         100,
		ThrottleRateLimit:          100,
		MethodThrottlingParameters: getMethodThrottlingParams(),
	}
}

func getMethodThrottlingParams() []MethodThrottlingParametersObject {
	return []MethodThrottlingParametersObject{
		MethodThrottlingParametersObject{
			Path:       "/api/v1/foobar",
			BurstLimit: 100,
			RateLimit:  100,
		},
	}
}

func getUsagePlanSilver() UsagePlan {
	return UsagePlan{
		PlanName:    "Silver",
		Description: "20 requests for 1 min",
		APIKeys: []APIKey{
			{
				CustomerID:         "customer1",
				GenerateDistinctID: true,
				Name:               "cusKey1",
			},
			{
				CustomerID:         "customer2",
				GenerateDistinctID: true,
				Name:               "cusKey2",
			},
		},
		QuotaLimit:                 100,
		QuotaPeriod:                "MONTH",
		ThrottleBurstLimit:         100,
		ThrottleRateLimit:          100,
		MethodThrottlingParameters: getMethodThrottlingParams(),
	}
}

func getSecondUsagePlans() []UsagePlan {
	return []UsagePlan{
		getUsagePlanSilver(),
		getSecondUsagePlan(),
	}
}

func getSecondUsagePlan() UsagePlan {
	return UsagePlan{
		PlanName:    "Gold",
		Description: "10 requests for 1 min",
		APIKeys: []APIKey{
			{
				CustomerID:         "customer1",
				GenerateDistinctID: true,
				Name:               "cusKey1",
			},
			{
				CustomerID:         "customer2",
				GenerateDistinctID: true,
				Name:               "cusKey2",
			},
		},
		QuotaLimit:                 100,
		QuotaPeriod:                "MONTH",
		ThrottleBurstLimit:         100,
		ThrottleRateLimit:          100,
		MethodThrottlingParameters: getMethodThrottlingParams(),
	}
}

func getUsagePlanBytes() string {
	usagePlan := getUsagePlans()
	usagePlanBytes, _ := json.Marshal(usagePlan)
	return string(usagePlanBytes)
}

func getSecondUsagePlanBytes() string {
	usagePlan := getSecondUsagePlans()
	usagePlanBytes, _ := json.Marshal(usagePlan)
	return string(usagePlanBytes)
}

func getAPIKeyMappingBuild(i int, k int, index int) *apigateway.UsagePlanKey {
	arr := buildUsagePlanAPIKeyMapping(getUsagePlan(), k, index)
	for k, key := range arr {
		if k == i {
			return key
		}
	}
	return nil
}

func getAPIKeyBuild(i int) *apigateway.ApiKey {
	arr := buildAPIKey(getUsagePlan(), 0)
	for k, key := range arr {
		if k == i {
			return key
		}
	}
	return nil
}

func getSecondAPIKeyMappingBuild(i int, k int, index int) *apigateway.UsagePlanKey {
	arr := buildUsagePlanAPIKeyMapping(getSecondUsagePlan(), k, index)
	for k, key := range arr {
		if k == i {
			return key
		}
	}
	return nil
}

func getSecondAPIKeyBuild(i int, index int) *apigateway.ApiKey {
	arr := buildAPIKey(getSecondUsagePlan(), index)
	for k, key := range arr {
		if k == i {
			return key
		}
	}
	return nil
}

func getAPIResources() []APIResource {
	return []APIResource{
		getAPIResource(),
	}
}

func getAPIResourcesWithLambda() []APIResource {
	return []APIResource{
		getAPIResource(),
		getLambdaAPIResource(),
	}
}

func getAuthDef() AWSAPIAuthorizer {
	return AWSAPIAuthorizer{
		IdentitySource:               "foo",
		AuthorizerType:               "REQUEST",
		AuthorizerAuthType:           "foo",
		AuthorizerName:               "foo",
		IdentityValidationExpression: "",
		AuthorizerUri:                "arn:bar",
	}
}

func getAuthDefPointer() *AWSAPIAuthorizer {
	return &AWSAPIAuthorizer{
		IdentitySource:               "foo",
		AuthorizerType:               "REQUEST",
		AuthorizerAuthType:           "foo",
		AuthorizerName:               "foo",
		IdentityValidationExpression: "",
		AuthorizerUri:                "arn:bar",
	}
}

func getCognitoAuthDefPointer() *AWSAPIAuthorizer {
	return &AWSAPIAuthorizer{
		IdentitySource:               "foo",
		AuthorizerType:               "COGNITO_USER_POOLS",
		AuthorizerAuthType:           "foo",
		AuthorizerName:               "foo",
		IdentityValidationExpression: "",
		AuthorizerResultTtlInSeconds: 3600,
		AuthorizerUri:                "arn:bar",
		ProviderARNs: []string{
			"arn:foo",
		},
	}
}

func getAuthDefs() []AWSAPIAuthorizer {
	return []AWSAPIAuthorizer{
		getAuthDef(),
		getAuthDefCognito(),
	}
}

func getAPIDef() AWSAPIDefinition {
	return AWSAPIDefinition{
		Name:                  "api0",
		Context:               "api0",
		AuthenticationEnabled: true,
		APIKeyEnabled:         true,
		Authorization_Enabled: true,
		Authorizers:           getAuthDefs(),
		UsagePlans:            getSecondUsagePlans(),
		APIs:                  getAPIResources(),
		BinaryMediaTypes:      []string{"foo/bar"},
	}
}

func getAPIDef22() AWSAPIDefinition {
	return AWSAPIDefinition{
		Name:                  "api1",
		Context:               "api1",
		AuthenticationEnabled: true,
		APIKeyEnabled:         true,
		Authorization_Enabled: true,
		Authorizers:           getAuthDefs(),
		APIs:                  getAPIResources(),
	}
}

func getAPIDefs() []AWSAPIDefinition {
	return []AWSAPIDefinition{
		getAPIDef(),
		getAPIDef22(),
	}
}

func getAWSAPIDefBytes() string {
	awsDefs := getAPIDefs()
	awsDefsBytes, _ := json.Marshal(awsDefs)
	return string(awsDefsBytes)
}

func getAuthDefCognito() AWSAPIAuthorizer {
	return AWSAPIAuthorizer{
		IdentitySource:               "foo",
		AuthorizerType:               "COGNITO_USER_POOLS",
		AuthorizerAuthType:           "foo",
		AuthorizerName:               "foo",
		IdentityValidationExpression: "",
		AuthorizerResultTtlInSeconds: 3600,
		AuthorizerUri:                "arn:bar",
		ProviderARNs: []string{
			"arn:foo",
		},
	}
}

func getAuthDefToken() AWSAPIAuthorizer {
	return AWSAPIAuthorizer{
		IdentitySource:               "foo",
		AuthorizerType:               "TOKEN",
		AuthorizerAuthType:           "foo",
		AuthorizerName:               "foo",
		IdentityValidationExpression: "",
		AuthorizerResultTtlInSeconds: 3600,
		AuthorizerUri:                "arn:bar",
		ProviderARNs: []string{
			"arn:foo",
		},
	}
}

func getAuthDefRequest() AWSAPIAuthorizer {
	return AWSAPIAuthorizer{
		IdentitySource:               "foo",
		AuthorizerType:               "TOKEN",
		AuthorizerAuthType:           "foo",
		AuthorizerName:               "foo",
		IdentityValidationExpression: "",
		AuthorizerResultTtlInSeconds: 3600,
		AuthorizerUri:                "arn:bar",
		ProviderARNs: []string{
			"arn:foo",
		},
	}
}

func getAuthDefCognitoPointer() *AWSAPIAuthorizer {
	return &AWSAPIAuthorizer{
		IdentitySource:               "foo",
		AuthorizerType:               "COGNITO_USER_POOLS",
		AuthorizerAuthType:           "foo",
		AuthorizerName:               "foo",
		IdentityValidationExpression: "",
		AuthorizerResultTtlInSeconds: 3600,
		AuthorizerUri:                "arn:bar",
		ProviderARNs: []string{
			"arn:foo",
		},
	}
}

func getAuthDefs2() []AWSAPIAuthorizer {
	return []AWSAPIAuthorizer{
		getAuthDefCognito(),
		getAuthDefToken(),
		getAuthDefRequest(),
	}
}

func getAPIDefWOUsagePlans() AWSAPIDefinition {
	return AWSAPIDefinition{
		Name:                  "api1",
		Context:               "api1",
		Authorizers:           getAuthDefs2(),
		AuthenticationEnabled: true,
		APIKeyEnabled:         true,
		Authorization_Enabled: true,
	}
}

func getAPIDefAPIKeyDisabled() AWSAPIDefinition {
	return AWSAPIDefinition{
		Name:                  "api2",
		Context:               "api2",
		Authorizers:           getAuthDefs2(),
		AuthenticationEnabled: true,
		APIKeyEnabled:         false,
		Authorization_Enabled: true,
	}
}

func getAPIDefAuthDisabled() AWSAPIDefinition {
	return AWSAPIDefinition{
		Name:                  "api3",
		Context:               "api3",
		Authorizers:           getAuthDefs2(),
		AuthenticationEnabled: false,
		APIKeyEnabled:         false,
		Authorization_Enabled: true,
		BinaryMediaTypes:      []string{"foo/bar"},
	}
}

func getAPIDefAuthorizationDisabled() AWSAPIDefinition {
	return AWSAPIDefinition{
		Name:                  "api4",
		Context:               "api4",
		Authorizers:           getAuthDefs2(),
		AuthenticationEnabled: false,
		APIKeyEnabled:         false,
		Authorization_Enabled: false,
		BinaryMediaTypes:      []string{"foo/bar"},
	}
}

func getAPIDefsWOUsagePlans() []AWSAPIDefinition {
	return []AWSAPIDefinition{
		getAPIDefWOUsagePlans(),
		getAPIDefAPIKeyDisabled(),
		getAPIDefAuthDisabled(),
		getAPIDefAuthorizationDisabled(),
	}
}

func getAWSAPIDefWOUsagePlansBytes() string {
	awsDefs := getAPIDefsWOUsagePlans()
	awsDefsBytes, _ := json.Marshal(awsDefs)
	return string(awsDefsBytes)
}

func getAPIResource() APIResource {
	return APIResource{
		Path: "/api/v1/foobar",
		Methods: []Method{
			{
				Method:                "GET",
				APIKeyEnabled:         true,
				Authorization_Enabled: true,
				Authorizator_Index:    0,
			},
			{
				Method:                "POST",
				APIKeyEnabled:         false,
				Authorization_Enabled: true,
				Authorizator_Index:    1,
				Authorization_Scopes: []string{
					"foo",
					"bar",
				},
			},
		},
		CachingEnabled: false,
		ProxyPathParams: []Param{
			{
				Param:    "fooid",
				Required: true,
			},
		},
		ProxyQueryParams: []Param{
			{
				Param:    "fooid",
				Required: true,
			},
		},
		ProxyHeaderParams: []Param{
			{
				Param:    "fooid",
				Required: true,
			},
		},
		PathParams: []ConstantParam{
			{
				Key:   "key",
				Value: "value",
			},
		},
		QueryParams: []ConstantParam{
			{
				Key:   "key",
				Value: "value",
			},
		},
		HeaderParams: []ConstantParam{
			{
				Key:   "key",
				Value: "value",
			},
		},
	}
}

func getLambdaAPIResource() APIResource {
	return APIResource{
		Path: "/api/v1/foolambda",
		Methods: []Method{
			{
				Method:                "POST",
				APIKeyEnabled:         false,
				Authorization_Enabled: true,
				Authorizator_Index:    1,
				Authorization_Scopes: []string{
					"foo",
					"bar",
				},
			},
		},
		Type:           "Lambda",
		LambdaArn:      "foo::bar",
		CachingEnabled: false,
		ProxyPathParams: []Param{
			{
				Param:    "fooid",
				Required: true,
			},
		},
		ProxyQueryParams: []Param{
			{
				Param:    "fooid",
				Required: true,
			},
		},
		ProxyHeaderParams: []Param{
			{
				Param:    "fooid",
				Required: true,
			},
		},
		PathParams: []ConstantParam{
			{
				Key:   "key",
				Value: "value",
			},
		},
		QueryParams: []ConstantParam{
			{
				Key:   "key",
				Value: "value",
			},
		},
		HeaderParams: []ConstantParam{
			{
				Key:   "key",
				Value: "value",
			},
		},
	}
}

func getAPIResourcesBytes() string {
	resourcesBytes, _ := json.Marshal(getAPIResources())
	return string(resourcesBytes)
}

func getAPIWithLambdaResourcesBytes() string {
	resourcesBytes, _ := json.Marshal(getAPIResourcesWithLambda())
	return string(resourcesBytes)
}

func getIngressRulesJsonStr() string {
	Rules := extensionsv1beta1.IngressRule{
		IngressRuleValue: extensionsv1beta1.IngressRuleValue{
			HTTP: &extensionsv1beta1.HTTPIngressRuleValue{
				Paths: []extensionsv1beta1.HTTPIngressPath{
					{
						Path: "/api/v1/foobar",
						Backend: extensionsv1beta1.IngressBackend{
							ServiceName: "foobar-service",
							ServicePort: intstr.FromInt(8080),
						},
					},
				},
			},
		},
	}
	rulePaths, err := json.Marshal(Rules.IngressRuleValue.HTTP.Paths)
	var rulePathsStr string
	if err != nil {
		fmt.Println(err)
		rulePathsStr = ""
	} else {
		rulePathsStr = string(rulePaths)
	}
	return rulePathsStr
}

func TestBuildApiGatewayTemplateFromIngressRule(t *testing.T) {
	tests := []struct {
		name string
		args *TemplateConfig
		want *cfn.Template
	}{
		{
			name: "generates template without custom domain",
			args: &TemplateConfig{
				Rule: extensionsv1beta1.IngressRule{
					IngressRuleValue: extensionsv1beta1.IngressRuleValue{
						HTTP: &extensionsv1beta1.HTTPIngressRuleValue{
							Paths: []extensionsv1beta1.HTTPIngressPath{
								{
									Path: "/api/v1/foobar",
									Backend: extensionsv1beta1.IngressBackend{
										ServiceName: "foobar-service",
										ServicePort: intstr.FromInt(8080),
									},
								},
							},
						},
					},
				},
				Network: &network.Network{
					Vpc: &ec2.Vpc{
						VpcId:     aws.String("foo"),
						CidrBlock: aws.String("10.0.0.0/24"),
					},
					InstanceIDs:      []string{"i-foo"},
					SubnetIDs:        []string{"sn-foo"},
					SecurityGroupIDs: []string{"sg-foo"},
				},
				Arns:                   []string{"arn::foo"},
				StageName:              "baz",
				NodePort:               30123,
				RequestTimeout:         10000,
				TLSPolicy:              "TLS_1_2",
				MinimumCompressionSize: 0,
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"RestAPIEmptyModel0":        buildAWSApiGatewayEmptyModel(0),
					"LambdaInvokeRole":          buildLambdaExecutionRole(),
					"Methodapi0":                buildAWSApiGatewayMethod("Resourceapi0", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv10":              buildAWSApiGatewayMethod("Resourceapiv10", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv1foobar0":        buildAWSApiGatewayMethod("Resourceapiv1foobar0", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv1foobarproxy0":   buildAWSApiGatewayMethod("Resourceapiv1foobarproxy0", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Resourceapi0":              buildAWSApiGatewayResource(cfn.GetAtt("RestAPI0", "RootResourceId"), "api", 0),
					"Resourceapiv10":            buildAWSApiGatewayResource(cfn.Ref("Resourceapi0"), "v1", 0),
					"Resourceapiv1foobar0":      buildAWSApiGatewayResource(cfn.Ref("Resourceapiv10"), "foobar", 0),
					"Resourceapiv1foobarproxy0": buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar0"), "{proxy+}", 0),
					"TargetGroup":               buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":                  buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":     buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI0":                  buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "AWS_IAM", 0, cfn.Ref("AWS::StackName"), []string{"AWS::NoValue"}),
					"Deployment0":               buildAWSApiGatewayDeployment("baz", []string{"Methodapi0", "Methodapiv10", "Methodapiv1foobar0", "Methodapiv1foobarproxy0"}, false, nil, "", "", 0),
					"LoadBalancer":              buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                   buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
				},
				Outputs: map[string]interface{}{
					"RestAPIID0":          Output{Value: cfn.Ref("RestAPI0")},
					"APIGatewayEndpoint0": Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI0"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"ClientARNS":          Output{Value: strings.Join([]string{"arn::foo"}, ",")},
					"APIGWEndpointType":   Output{Value: "EDGE"},
					"RequestTimeout":      Output{Value: "10000"},
					"IngressRules":        Output{Value: getIngressRulesJsonStr()},
				},
			},
		},
		{
			name: "generates template with content encoding",
			args: &TemplateConfig{
				Rule: extensionsv1beta1.IngressRule{
					IngressRuleValue: extensionsv1beta1.IngressRuleValue{
						HTTP: &extensionsv1beta1.HTTPIngressRuleValue{
							Paths: []extensionsv1beta1.HTTPIngressPath{
								{
									Path: "/api/v1/foobar",
									Backend: extensionsv1beta1.IngressBackend{
										ServiceName: "foobar-service",
										ServicePort: intstr.FromInt(8080),
									},
								},
							},
						},
					},
				},
				Network: &network.Network{
					Vpc: &ec2.Vpc{
						VpcId:     aws.String("foo"),
						CidrBlock: aws.String("10.0.0.0/24"),
					},
					InstanceIDs:      []string{"i-foo"},
					SubnetIDs:        []string{"sn-foo"},
					SecurityGroupIDs: []string{"sg-foo"},
				},
				Arns:                   []string{"arn::foo"},
				StageName:              "baz",
				NodePort:               30123,
				RequestTimeout:         10000,
				TLSPolicy:              "TLS_1_2",
				MinimumCompressionSize: 1000000000,
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"RestAPIEmptyModel0":        buildAWSApiGatewayEmptyModel(0),
					"LambdaInvokeRole":          buildLambdaExecutionRole(),
					"Methodapi0":                buildAWSApiGatewayMethod("Resourceapi0", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv10":              buildAWSApiGatewayMethod("Resourceapiv10", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv1foobar0":        buildAWSApiGatewayMethod("Resourceapiv1foobar0", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv1foobarproxy0":   buildAWSApiGatewayMethod("Resourceapiv1foobarproxy0", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Resourceapi0":              buildAWSApiGatewayResource(cfn.GetAtt("RestAPI0", "RootResourceId"), "api", 0),
					"Resourceapiv10":            buildAWSApiGatewayResource(cfn.Ref("Resourceapi0"), "v1", 0),
					"Resourceapiv1foobar0":      buildAWSApiGatewayResource(cfn.Ref("Resourceapiv10"), "foobar", 0),
					"Resourceapiv1foobarproxy0": buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar0"), "{proxy+}", 0),
					"TargetGroup":               buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":                  buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":     buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI0":                  buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "AWS_IAM", 1000000000, cfn.Ref("AWS::StackName"), []string{"AWS::NoValue"}),
					"Deployment0":               buildAWSApiGatewayDeployment("baz", []string{"Methodapi0", "Methodapiv10", "Methodapiv1foobar0", "Methodapiv1foobarproxy0"}, false, nil, "", "", 0),
					"LoadBalancer":              buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                   buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
				},
				Outputs: map[string]interface{}{
					"RestAPIID0":             Output{Value: cfn.Ref("RestAPI0")},
					"APIGatewayEndpoint0":    Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI0"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"ClientARNS":             Output{Value: strings.Join([]string{"arn::foo"}, ",")},
					"APIGWEndpointType":      Output{Value: "EDGE"},
					"RequestTimeout":         Output{Value: "10000"},
					"MinimumCompressionSize": Output{Value: "1000000000"},
					"IngressRules":           Output{Value: getIngressRulesJsonStr()},
				},
			},
		},
		{
			name: "generates template with content encoding api keys",
			args: &TemplateConfig{
				Rule: extensionsv1beta1.IngressRule{
					IngressRuleValue: extensionsv1beta1.IngressRuleValue{
						HTTP: &extensionsv1beta1.HTTPIngressRuleValue{
							Paths: []extensionsv1beta1.HTTPIngressPath{
								{
									Path: "/api/v1/foobar",
									Backend: extensionsv1beta1.IngressBackend{
										ServiceName: "foobar-service",
										ServicePort: intstr.FromInt(8080),
									},
								},
							},
						},
					},
				},
				Network: &network.Network{
					Vpc: &ec2.Vpc{
						VpcId:     aws.String("foo"),
						CidrBlock: aws.String("10.0.0.0/24"),
					},
					InstanceIDs:      []string{"i-foo"},
					SubnetIDs:        []string{"sn-foo"},
					SecurityGroupIDs: []string{"sg-foo"},
				},
				StageName:              "baz",
				NodePort:               30123,
				RequestTimeout:         10000,
				TLSPolicy:              "TLS_1_2",
				UsagePlans:             getUsagePlans(),
				MinimumCompressionSize: 1000000000,
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"RestAPIEmptyModel0":        buildAWSApiGatewayEmptyModel(0),
					"LambdaInvokeRole":          buildLambdaExecutionRole(),
					"Methodapi0":                buildAWSApiGatewayMethod("Resourceapi0", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 0, nil, 0, true, nil),
					"Methodapiv10":              buildAWSApiGatewayMethod("Resourceapiv10", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 0, nil, 0, true, nil),
					"Methodapiv1foobar0":        buildAWSApiGatewayMethod("Resourceapiv1foobar0", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 0, nil, 0, true, nil),
					"Methodapiv1foobarproxy0":   buildAWSApiGatewayMethod("Resourceapiv1foobarproxy0", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 0, nil, 0, true, nil),
					"Resourceapi0":              buildAWSApiGatewayResource(cfn.GetAtt("RestAPI0", "RootResourceId"), "api", 0),
					"Resourceapiv10":            buildAWSApiGatewayResource(cfn.Ref("Resourceapi0"), "v1", 0),
					"Resourceapiv1foobar0":      buildAWSApiGatewayResource(cfn.Ref("Resourceapiv10"), "foobar", 0),
					"Resourceapiv1foobarproxy0": buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar0"), "{proxy+}", 0),
					"TargetGroup":               buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":                  buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":     buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI0":                  buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "NONE", 1000000000, cfn.Ref("AWS::StackName"), []string{"AWS::NoValue"}),
					"Deployment0":               buildAWSApiGatewayDeployment("baz", []string{"Methodapi0", "Methodapiv10", "Methodapiv1foobar0", "Methodapiv1foobarproxy0"}, false, nil, "", "", 0),
					"LoadBalancer":              buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                   buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
					"APIKeyUsagePlan000":        getAPIKeyMappingBuild(0, 0, 0),
					"APIKeyUsagePlan010":        getAPIKeyMappingBuild(1, 0, 0),
					"UsagePlan00":               buildUsagePlan(getUsagePlan(), "baz", 0, buildMethodThrottling(getMethodThrottlingParams(), "baz", 0)),
					"APIKey000":                 getAPIKeyBuild(0),
					"APIKey010":                 getAPIKeyBuild(1),
				},
				Outputs: map[string]interface{}{
					"RestAPIID0":             Output{Value: cfn.Ref("RestAPI0")},
					"APIGatewayEndpoint0":    Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI0"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"APIGWEndpointType":      Output{Value: "EDGE"},
					"RequestTimeout":         Output{Value: "10000"},
					"MinimumCompressionSize": Output{Value: "1000000000"},
					"UsagePlansData":         Output{Value: getUsagePlanBytes()},
					"IngressRules":           Output{Value: getIngressRulesJsonStr()},
				},
			},
		},
		{
			name: "generates template with usage plan",
			args: &TemplateConfig{
				Rule: extensionsv1beta1.IngressRule{
					IngressRuleValue: extensionsv1beta1.IngressRuleValue{
						HTTP: &extensionsv1beta1.HTTPIngressRuleValue{
							Paths: []extensionsv1beta1.HTTPIngressPath{
								{
									Path: "/api/v1/foobar",
									Backend: extensionsv1beta1.IngressBackend{
										ServiceName: "foobar-service",
										ServicePort: intstr.FromInt(8080),
									},
								},
							},
						},
					},
				},
				Network: &network.Network{
					Vpc: &ec2.Vpc{
						VpcId:     aws.String("foo"),
						CidrBlock: aws.String("10.0.0.0/24"),
					},
					InstanceIDs:      []string{"i-foo"},
					SubnetIDs:        []string{"sn-foo"},
					SecurityGroupIDs: []string{"sg-foo"},
				},
				StageName:              "baz",
				NodePort:               30123,
				RequestTimeout:         10000,
				TLSPolicy:              "TLS_1_2",
				UsagePlans:             getUsagePlans(),
				MinimumCompressionSize: 0,
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"RestAPIEmptyModel0":        buildAWSApiGatewayEmptyModel(0),
					"LambdaInvokeRole":          buildLambdaExecutionRole(),
					"Methodapi0":                buildAWSApiGatewayMethod("Resourceapi0", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 0, nil, 0, true, nil),
					"Methodapiv10":              buildAWSApiGatewayMethod("Resourceapiv10", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 0, nil, 0, true, nil),
					"Methodapiv1foobar0":        buildAWSApiGatewayMethod("Resourceapiv1foobar0", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 0, nil, 0, true, nil),
					"Methodapiv1foobarproxy0":   buildAWSApiGatewayMethod("Resourceapiv1foobarproxy0", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 0, nil, 0, true, nil),
					"Resourceapi0":              buildAWSApiGatewayResource(cfn.GetAtt("RestAPI0", "RootResourceId"), "api", 0),
					"Resourceapiv10":            buildAWSApiGatewayResource(cfn.Ref("Resourceapi0"), "v1", 0),
					"Resourceapiv1foobar0":      buildAWSApiGatewayResource(cfn.Ref("Resourceapiv10"), "foobar", 0),
					"Resourceapiv1foobarproxy0": buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar0"), "{proxy+}", 0),
					"TargetGroup":               buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":                  buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":     buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI0":                  buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "NONE", 0, cfn.Ref("AWS::StackName"), []string{"AWS::NoValue"}),
					"Deployment0":               buildAWSApiGatewayDeployment("baz", []string{"Methodapi0", "Methodapiv10", "Methodapiv1foobar0", "Methodapiv1foobarproxy0"}, false, nil, "", "", 0),
					"LoadBalancer":              buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                   buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
					"APIKeyUsagePlan000":        getAPIKeyMappingBuild(0, 0, 0),
					"APIKeyUsagePlan010":        getAPIKeyMappingBuild(1, 0, 0),
					"UsagePlan00":               buildUsagePlan(getUsagePlan(), "baz", 0, buildMethodThrottling(getMethodThrottlingParams(), "baz", 0)),
					"APIKey000":                 getAPIKeyBuild(0),
					"APIKey010":                 getAPIKeyBuild(1),
				},
				Outputs: map[string]interface{}{
					"RestAPIID0":          Output{Value: cfn.Ref("RestAPI0")},
					"APIGatewayEndpoint0": Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI0"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"APIGWEndpointType":   Output{Value: "EDGE"},
					"RequestTimeout":      Output{Value: "10000"},
					"UsagePlansData":      Output{Value: getUsagePlanBytes()},
					"IngressRules":        Output{Value: getIngressRulesJsonStr()},
				},
			},
		},
		{
			name: "generates template with waf",
			args: &TemplateConfig{
				Rule: extensionsv1beta1.IngressRule{
					IngressRuleValue: extensionsv1beta1.IngressRuleValue{
						HTTP: &extensionsv1beta1.HTTPIngressRuleValue{
							Paths: []extensionsv1beta1.HTTPIngressPath{
								{
									Path: "/api/v1/foobar",
									Backend: extensionsv1beta1.IngressBackend{
										ServiceName: "foobar-service",
										ServicePort: intstr.FromInt(8080),
									},
								},
							},
						},
					},
				},
				Network: &network.Network{
					Vpc: &ec2.Vpc{
						VpcId:     aws.String("foo"),
						CidrBlock: aws.String("10.0.0.0/24"),
					},
					InstanceIDs:      []string{"i-foo"},
					SubnetIDs:        []string{"sn-foo"},
					SecurityGroupIDs: []string{"sg-foo"},
				},
				Arns:                   []string{"arn::foo"},
				StageName:              "baz",
				NodePort:               30123,
				WAFEnabled:             true,
				WAFRulesJSON:           "[]",
				WAFAssociation:         true,
				RequestTimeout:         10000,
				TLSPolicy:              "TLS_1_2",
				MinimumCompressionSize: 0,
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"RestAPIEmptyModel0":        buildAWSApiGatewayEmptyModel(0),
					"LambdaInvokeRole":          buildLambdaExecutionRole(),
					"Methodapi0":                buildAWSApiGatewayMethod("Resourceapi0", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv10":              buildAWSApiGatewayMethod("Resourceapiv10", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv1foobar0":        buildAWSApiGatewayMethod("Resourceapiv1foobar0", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv1foobarproxy0":   buildAWSApiGatewayMethod("Resourceapiv1foobarproxy0", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Resourceapi0":              buildAWSApiGatewayResource(cfn.GetAtt("RestAPI0", "RootResourceId"), "api", 0),
					"Resourceapiv10":            buildAWSApiGatewayResource(cfn.Ref("Resourceapi0"), "v1", 0),
					"Resourceapiv1foobar0":      buildAWSApiGatewayResource(cfn.Ref("Resourceapiv10"), "foobar", 0),
					"Resourceapiv1foobarproxy0": buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar0"), "{proxy+}", 0),
					"TargetGroup":               buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":                  buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":     buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI0":                  buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "AWS_IAM", 0, cfn.Ref("AWS::StackName"), []string{"AWS::NoValue"}),
					"Deployment0":               buildAWSApiGatewayDeployment("baz", []string{"Methodapi0", "Methodapiv10", "Methodapiv1foobar0", "Methodapiv1foobarproxy0"}, false, nil, "", "", 0),
					"LoadBalancer":              buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                   buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
					"WAFAcl":                    buildAWSWAFWebACL("REGIONAL", "[]"),
					"WAFAssociation0":           buildAWSWAFWebACLAssociation("baz", 0),
				},
				Outputs: map[string]interface{}{
					"RestAPIID0":          Output{Value: cfn.Ref("RestAPI0")},
					"APIGatewayEndpoint0": Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI0"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"ClientARNS":          Output{Value: strings.Join([]string{"arn::foo"}, ",")},
					"APIGWEndpointType":   Output{Value: "EDGE"},
					"WAFEnabled":          Output{Value: "true"},
					"WAFRules":            Output{Value: "[]"},
					"WAFScope":            Output{Value: "REGIONAL"},
					"WAFAssociation0":     Output{Value: cfn.Ref("WAFAssociation0")},
					"RequestTimeout":      Output{Value: "10000"},
					"IngressRules":        Output{Value: getIngressRulesJsonStr()},
				},
			},
		},
		{
			name: "generates template with waf regional api",
			args: &TemplateConfig{
				Rule: extensionsv1beta1.IngressRule{
					IngressRuleValue: extensionsv1beta1.IngressRuleValue{
						HTTP: &extensionsv1beta1.HTTPIngressRuleValue{
							Paths: []extensionsv1beta1.HTTPIngressPath{
								{
									Path: "/api/v1/foobar",
									Backend: extensionsv1beta1.IngressBackend{
										ServiceName: "foobar-service",
										ServicePort: intstr.FromInt(8080),
									},
								},
							},
						},
					},
				},
				Network: &network.Network{
					Vpc: &ec2.Vpc{
						VpcId:     aws.String("foo"),
						CidrBlock: aws.String("10.0.0.0/24"),
					},
					InstanceIDs:      []string{"i-foo"},
					SubnetIDs:        []string{"sn-foo"},
					SecurityGroupIDs: []string{"sg-foo"},
				},
				Arns:                   []string{"arn::foo"},
				StageName:              "baz",
				NodePort:               30123,
				WAFEnabled:             true,
				WAFRulesJSON:           "[]",
				WAFAssociation:         true,
				APIEndpointType:        "REGIONAL",
				RequestTimeout:         10000,
				TLSPolicy:              "TLS_1_2",
				MinimumCompressionSize: 0,
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"RestAPIEmptyModel0":        buildAWSApiGatewayEmptyModel(0),
					"LambdaInvokeRole":          buildLambdaExecutionRole(),
					"Methodapi0":                buildAWSApiGatewayMethod("Resourceapi0", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv10":              buildAWSApiGatewayMethod("Resourceapiv10", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv1foobar0":        buildAWSApiGatewayMethod("Resourceapiv1foobar0", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv1foobarproxy0":   buildAWSApiGatewayMethod("Resourceapiv1foobarproxy0", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Resourceapi0":              buildAWSApiGatewayResource(cfn.GetAtt("RestAPI0", "RootResourceId"), "api", 0),
					"Resourceapiv10":            buildAWSApiGatewayResource(cfn.Ref("Resourceapi0"), "v1", 0),
					"Resourceapiv1foobar0":      buildAWSApiGatewayResource(cfn.Ref("Resourceapiv10"), "foobar", 0),
					"Resourceapiv1foobarproxy0": buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar0"), "{proxy+}", 0),
					"TargetGroup":               buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":                  buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":     buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI0":                  buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "REGIONAL", "AWS_IAM", 0, cfn.Ref("AWS::StackName"), []string{"AWS::NoValue"}),
					"Deployment0":               buildAWSApiGatewayDeployment("baz", []string{"Methodapi0", "Methodapiv10", "Methodapiv1foobar0", "Methodapiv1foobarproxy0"}, false, nil, "", "", 0),
					"LoadBalancer":              buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                   buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
					"WAFAcl":                    buildAWSWAFWebACL("REGIONAL", "[]"),
					"WAFAssociation0":           buildAWSWAFWebACLAssociation("baz", 0),
				},
				Outputs: map[string]interface{}{
					"RestAPIID0":          Output{Value: cfn.Ref("RestAPI0")},
					"APIGatewayEndpoint0": Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI0"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"ClientARNS":          Output{Value: strings.Join([]string{"arn::foo"}, ",")},
					"APIGWEndpointType":   Output{Value: "REGIONAL"},
					"WAFEnabled":          Output{Value: "true"},
					"WAFRules":            Output{Value: "[]"},
					"WAFScope":            Output{Value: "REGIONAL"},
					"WAFAssociation0":     Output{Value: cfn.Ref("WAFAssociation0")},
					"RequestTimeout":      Output{Value: "10000"},
					"IngressRules":        Output{Value: getIngressRulesJsonStr()},
				},
			},
		},
		{
			name: "generates template with waf null rules",
			args: &TemplateConfig{
				Rule: extensionsv1beta1.IngressRule{
					IngressRuleValue: extensionsv1beta1.IngressRuleValue{
						HTTP: &extensionsv1beta1.HTTPIngressRuleValue{
							Paths: []extensionsv1beta1.HTTPIngressPath{
								{
									Path: "/api/v1/foobar",
									Backend: extensionsv1beta1.IngressBackend{
										ServiceName: "foobar-service",
										ServicePort: intstr.FromInt(8080),
									},
								},
							},
						},
					},
				},
				Network: &network.Network{
					Vpc: &ec2.Vpc{
						VpcId:     aws.String("foo"),
						CidrBlock: aws.String("10.0.0.0/24"),
					},
					InstanceIDs:      []string{"i-foo"},
					SubnetIDs:        []string{"sn-foo"},
					SecurityGroupIDs: []string{"sg-foo"},
				},
				Arns:                   []string{"arn::foo"},
				StageName:              "baz",
				NodePort:               30123,
				WAFAssociation:         true,
				WAFEnabled:             true,
				RequestTimeout:         10000,
				TLSPolicy:              "TLS_1_2",
				MinimumCompressionSize: 0,
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"RestAPIEmptyModel0":        buildAWSApiGatewayEmptyModel(0),
					"LambdaInvokeRole":          buildLambdaExecutionRole(),
					"Methodapi0":                buildAWSApiGatewayMethod("Resourceapi0", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv10":              buildAWSApiGatewayMethod("Resourceapiv10", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv1foobar0":        buildAWSApiGatewayMethod("Resourceapiv1foobar0", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv1foobarproxy0":   buildAWSApiGatewayMethod("Resourceapiv1foobarproxy0", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Resourceapi0":              buildAWSApiGatewayResource(cfn.GetAtt("RestAPI0", "RootResourceId"), "api", 0),
					"Resourceapiv10":            buildAWSApiGatewayResource(cfn.Ref("Resourceapi0"), "v1", 0),
					"Resourceapiv1foobar0":      buildAWSApiGatewayResource(cfn.Ref("Resourceapiv10"), "foobar", 0),
					"Resourceapiv1foobarproxy0": buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar0"), "{proxy+}", 0),
					"TargetGroup":               buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":                  buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":     buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI0":                  buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "AWS_IAM", 0, cfn.Ref("AWS::StackName"), []string{"AWS::NoValue"}),
					"Deployment0":               buildAWSApiGatewayDeployment("baz", []string{"Methodapi0", "Methodapiv10", "Methodapiv1foobar0", "Methodapiv1foobarproxy0"}, false, nil, "", "", 0),
					"LoadBalancer":              buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                   buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
					"WAFAcl":                    buildAWSWAFWebACL("REGIONAL", ""),
					"WAFAssociation0":           buildAWSWAFWebACLAssociation("baz", 0),
				},
				Outputs: map[string]interface{}{
					"RestAPIID0":          Output{Value: cfn.Ref("RestAPI0")},
					"APIGatewayEndpoint0": Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI0"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"ClientARNS":          Output{Value: strings.Join([]string{"arn::foo"}, ",")},
					"APIGWEndpointType":   Output{Value: "EDGE"},
					"WAFEnabled":          Output{Value: "true"},
					"WAFRules":            Output{Value: ""},
					"WAFScope":            Output{Value: "REGIONAL"},
					"WAFAssociation0":     Output{Value: cfn.Ref("WAFAssociation0")},
					"RequestTimeout":      Output{Value: "10000"},
					"IngressRules":        Output{Value: getIngressRulesJsonStr()},
				},
			},
		},
		{
			name: "generates template with waf error rules",
			args: &TemplateConfig{
				Rule: extensionsv1beta1.IngressRule{
					IngressRuleValue: extensionsv1beta1.IngressRuleValue{
						HTTP: &extensionsv1beta1.HTTPIngressRuleValue{
							Paths: []extensionsv1beta1.HTTPIngressPath{
								{
									Path: "/api/v1/foobar",
									Backend: extensionsv1beta1.IngressBackend{
										ServiceName: "foobar-service",
										ServicePort: intstr.FromInt(8080),
									},
								},
							},
						},
					},
				},
				Network: &network.Network{
					Vpc: &ec2.Vpc{
						VpcId:     aws.String("foo"),
						CidrBlock: aws.String("10.0.0.0/24"),
					},
					InstanceIDs:      []string{"i-foo"},
					SubnetIDs:        []string{"sn-foo"},
					SecurityGroupIDs: []string{"sg-foo"},
				},
				Arns:                   []string{"arn::foo"},
				StageName:              "baz",
				NodePort:               30123,
				WAFEnabled:             true,
				WAFRulesJSON:           "wrongjson",
				WAFAssociation:         true,
				RequestTimeout:         10000,
				TLSPolicy:              "TLS_1_2",
				MinimumCompressionSize: 0,
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"RestAPIEmptyModel0":        buildAWSApiGatewayEmptyModel(0),
					"LambdaInvokeRole":          buildLambdaExecutionRole(),
					"Methodapi0":                buildAWSApiGatewayMethod("Resourceapi0", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv10":              buildAWSApiGatewayMethod("Resourceapiv10", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv1foobar0":        buildAWSApiGatewayMethod("Resourceapiv1foobar0", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv1foobarproxy0":   buildAWSApiGatewayMethod("Resourceapiv1foobarproxy0", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Resourceapi0":              buildAWSApiGatewayResource(cfn.GetAtt("RestAPI0", "RootResourceId"), "api", 0),
					"Resourceapiv10":            buildAWSApiGatewayResource(cfn.Ref("Resourceapi0"), "v1", 0),
					"Resourceapiv1foobar0":      buildAWSApiGatewayResource(cfn.Ref("Resourceapiv10"), "foobar", 0),
					"Resourceapiv1foobarproxy0": buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar0"), "{proxy+}", 0),
					"TargetGroup":               buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":                  buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":     buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI0":                  buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "AWS_IAM", 0, cfn.Ref("AWS::StackName"), []string{"AWS::NoValue"}),
					"Deployment0":               buildAWSApiGatewayDeployment("baz", []string{"Methodapi0", "Methodapiv10", "Methodapiv1foobar0", "Methodapiv1foobarproxy0"}, false, nil, "", "", 0),
					"LoadBalancer":              buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                   buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
					"WAFAcl":                    buildAWSWAFWebACL("REGIONAL", ""),
					"WAFAssociation0":           buildAWSWAFWebACLAssociation("baz", 0),
				},
				Outputs: map[string]interface{}{
					"RestAPIID0":          Output{Value: cfn.Ref("RestAPI0")},
					"APIGatewayEndpoint0": Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI0"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"ClientARNS":          Output{Value: strings.Join([]string{"arn::foo"}, ",")},
					"APIGWEndpointType":   Output{Value: "EDGE"},
					"WAFEnabled":          Output{Value: "true"},
					"WAFRules":            Output{Value: "wrongjson"},
					"WAFScope":            Output{Value: "REGIONAL"},
					"WAFAssociation0":     Output{Value: cfn.Ref("WAFAssociation0")},
					"RequestTimeout":      Output{Value: "10000"},
					"IngressRules":        Output{Value: getIngressRulesJsonStr()},
				},
			},
		},
		{
			name: "generates template with custom domain",
			args: &TemplateConfig{
				Rule: extensionsv1beta1.IngressRule{
					IngressRuleValue: extensionsv1beta1.IngressRuleValue{
						HTTP: &extensionsv1beta1.HTTPIngressRuleValue{
							Paths: []extensionsv1beta1.HTTPIngressPath{
								{
									Path: "/api/v1/foobar",
									Backend: extensionsv1beta1.IngressBackend{
										ServiceName: "foobar-service",
										ServicePort: intstr.FromInt(8080),
									},
								},
							},
						},
					},
				},
				Network: &network.Network{
					Vpc: &ec2.Vpc{
						VpcId:     aws.String("foo"),
						CidrBlock: aws.String("10.0.0.0/24"),
					},
					InstanceIDs:      []string{"i-foo"},
					SubnetIDs:        []string{"sn-foo"},
					SecurityGroupIDs: []string{"sg-foo"},
				},
				Arns:                   []string{"arn::foo"},
				StageName:              "baz",
				NodePort:               30123,
				CustomDomainName:       "example.com",
				CertificateArn:         "arn::foobar",
				RequestTimeout:         10000,
				TLSPolicy:              "TLS_1_2",
				MinimumCompressionSize: 0,
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"RestAPIEmptyModel0":           buildAWSApiGatewayEmptyModel(0),
					"LambdaInvokeRole":             buildLambdaExecutionRole(),
					"Methodapi0":                   buildAWSApiGatewayMethod("Resourceapi0", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv10":                 buildAWSApiGatewayMethod("Resourceapiv10", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv1foobar0":           buildAWSApiGatewayMethod("Resourceapiv1foobar0", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv1foobarproxy0":      buildAWSApiGatewayMethod("Resourceapiv1foobarproxy0", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Resourceapi0":                 buildAWSApiGatewayResource(cfn.GetAtt("RestAPI0", "RootResourceId"), "api", 0),
					"Resourceapiv10":               buildAWSApiGatewayResource(cfn.Ref("Resourceapi0"), "v1", 0),
					"Resourceapiv1foobar0":         buildAWSApiGatewayResource(cfn.Ref("Resourceapiv10"), "foobar", 0),
					"Resourceapiv1foobarproxy0":    buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar0"), "{proxy+}", 0),
					"TargetGroup":                  buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":                     buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":        buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI0":                     buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "AWS_IAM", 0, cfn.Ref("AWS::StackName"), []string{"AWS::NoValue"}),
					"Deployment0":                  buildAWSApiGatewayDeployment("baz", []string{"Methodapi0", "Methodapiv10", "Methodapiv1foobar0", "Methodapiv1foobarproxy0"}, false, nil, "", "", 0),
					"LoadBalancer":                 buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                      buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
					"CustomDomain":                 buildCustomDomain("example.com", "arn::foobar", "EDGE", "TLS_1_2"),
					"CustomDomainBasePathMapping0": buildCustomDomainBasePathMapping("example.com", "baz", "", 0),
				},
				Outputs: map[string]interface{}{
					"RestAPIID0":               Output{Value: cfn.Ref("RestAPI0")},
					"APIGatewayEndpoint0":      Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI0"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"ClientARNS":               Output{Value: strings.Join([]string{"arn::foo"}, ",")},
					"APIGWEndpointType":        Output{Value: "EDGE"},
					"SSLCertArn":               Output{Value: "arn::foobar"},
					"CustomDomainName":         Output{Value: "example.com"},
					"CustomDomainHostname":     Output{Value: cfn.GetAtt("CustomDomain", "DistributionDomainName")},
					"CustomDomainHostedZoneID": Output{Value: cfn.GetAtt("CustomDomain", "DistributionHostedZoneId")},
					"RequestTimeout":           Output{Value: "10000"},
					"TLSPolicy":                Output{Value: "TLS_1_2"},
					"CustomDomainBasePath":     Output{Value: ""},
					"IngressRules":             Output{Value: getIngressRulesJsonStr()},
				},
			},
		},
		{
			name: "generates template with custom domain with base path",
			args: &TemplateConfig{
				Rule: extensionsv1beta1.IngressRule{
					IngressRuleValue: extensionsv1beta1.IngressRuleValue{
						HTTP: &extensionsv1beta1.HTTPIngressRuleValue{
							Paths: []extensionsv1beta1.HTTPIngressPath{
								{
									Path: "/api/v1/foobar",
									Backend: extensionsv1beta1.IngressBackend{
										ServiceName: "foobar-service",
										ServicePort: intstr.FromInt(8080),
									},
								},
							},
						},
					},
				},
				Network: &network.Network{
					Vpc: &ec2.Vpc{
						VpcId:     aws.String("foo"),
						CidrBlock: aws.String("10.0.0.0/24"),
					},
					InstanceIDs:      []string{"i-foo"},
					SubnetIDs:        []string{"sn-foo"},
					SecurityGroupIDs: []string{"sg-foo"},
				},
				Arns:                   []string{"arn::foo"},
				StageName:              "baz",
				NodePort:               30123,
				CustomDomainName:       "example.com",
				CustomDomainBasePath:   "foo",
				CertificateArn:         "arn::foobar",
				RequestTimeout:         10000,
				TLSPolicy:              "TLS_1_2",
				MinimumCompressionSize: 0,
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"RestAPIEmptyModel0":           buildAWSApiGatewayEmptyModel(0),
					"LambdaInvokeRole":             buildLambdaExecutionRole(),
					"Methodapi0":                   buildAWSApiGatewayMethod("Resourceapi0", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv10":                 buildAWSApiGatewayMethod("Resourceapiv10", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv1foobar0":           buildAWSApiGatewayMethod("Resourceapiv1foobar0", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv1foobarproxy0":      buildAWSApiGatewayMethod("Resourceapiv1foobarproxy0", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Resourceapi0":                 buildAWSApiGatewayResource(cfn.GetAtt("RestAPI0", "RootResourceId"), "api", 0),
					"Resourceapiv10":               buildAWSApiGatewayResource(cfn.Ref("Resourceapi0"), "v1", 0),
					"Resourceapiv1foobar0":         buildAWSApiGatewayResource(cfn.Ref("Resourceapiv10"), "foobar", 0),
					"Resourceapiv1foobarproxy0":    buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar0"), "{proxy+}", 0),
					"TargetGroup":                  buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":                     buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":        buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI0":                     buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "AWS_IAM", 0, cfn.Ref("AWS::StackName"), []string{"AWS::NoValue"}),
					"Deployment0":                  buildAWSApiGatewayDeployment("baz", []string{"Methodapi0", "Methodapiv10", "Methodapiv1foobar0", "Methodapiv1foobarproxy0"}, false, nil, "", "", 0),
					"LoadBalancer":                 buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                      buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
					"CustomDomain":                 buildCustomDomain("example.com", "arn::foobar", "EDGE", "TLS_1_2"),
					"CustomDomainBasePathMapping0": buildCustomDomainBasePathMapping("example.com", "baz", "foo", 0),
				},
				Outputs: map[string]interface{}{
					"RestAPIID0":               Output{Value: cfn.Ref("RestAPI0")},
					"APIGatewayEndpoint0":      Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI0"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"ClientARNS":               Output{Value: strings.Join([]string{"arn::foo"}, ",")},
					"APIGWEndpointType":        Output{Value: "EDGE"},
					"SSLCertArn":               Output{Value: "arn::foobar"},
					"CustomDomainName":         Output{Value: "example.com"},
					"CustomDomainHostname":     Output{Value: cfn.GetAtt("CustomDomain", "DistributionDomainName")},
					"CustomDomainHostedZoneID": Output{Value: cfn.GetAtt("CustomDomain", "DistributionHostedZoneId")},
					"RequestTimeout":           Output{Value: "10000"},
					"TLSPolicy":                Output{Value: "TLS_1_2"},
					"CustomDomainBasePath":     Output{Value: "foo"},
					"IngressRules":             Output{Value: getIngressRulesJsonStr()},
				},
			},
		},
		{
			name: "generates template with custom domain regional api",
			args: &TemplateConfig{
				Rule: extensionsv1beta1.IngressRule{
					IngressRuleValue: extensionsv1beta1.IngressRuleValue{
						HTTP: &extensionsv1beta1.HTTPIngressRuleValue{
							Paths: []extensionsv1beta1.HTTPIngressPath{
								{
									Path: "/api/v1/foobar",
									Backend: extensionsv1beta1.IngressBackend{
										ServiceName: "foobar-service",
										ServicePort: intstr.FromInt(8080),
									},
								},
							},
						},
					},
				},
				Network: &network.Network{
					Vpc: &ec2.Vpc{
						VpcId:     aws.String("foo"),
						CidrBlock: aws.String("10.0.0.0/24"),
					},
					InstanceIDs:      []string{"i-foo"},
					SubnetIDs:        []string{"sn-foo"},
					SecurityGroupIDs: []string{"sg-foo"},
				},
				Arns:                   []string{"arn::foo"},
				StageName:              "baz",
				NodePort:               30123,
				CustomDomainName:       "example.com",
				CertificateArn:         "arn::foobar",
				APIEndpointType:        "REGIONAL",
				TLSPolicy:              "TLS_1_2",
				RequestTimeout:         10000,
				MinimumCompressionSize: 0,
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"RestAPIEmptyModel0":           buildAWSApiGatewayEmptyModel(0),
					"LambdaInvokeRole":             buildLambdaExecutionRole(),
					"Methodapi0":                   buildAWSApiGatewayMethod("Resourceapi0", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv10":                 buildAWSApiGatewayMethod("Resourceapiv10", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv1foobar0":           buildAWSApiGatewayMethod("Resourceapiv1foobar0", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv1foobarproxy0":      buildAWSApiGatewayMethod("Resourceapiv1foobarproxy0", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Resourceapi0":                 buildAWSApiGatewayResource(cfn.GetAtt("RestAPI0", "RootResourceId"), "api", 0),
					"Resourceapiv10":               buildAWSApiGatewayResource(cfn.Ref("Resourceapi0"), "v1", 0),
					"Resourceapiv1foobar0":         buildAWSApiGatewayResource(cfn.Ref("Resourceapiv10"), "foobar", 0),
					"Resourceapiv1foobarproxy0":    buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar0"), "{proxy+}", 0),
					"TargetGroup":                  buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":                     buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":        buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI0":                     buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "REGIONAL", "AWS_IAM", 0, cfn.Ref("AWS::StackName"), []string{"AWS::NoValue"}),
					"Deployment0":                  buildAWSApiGatewayDeployment("baz", []string{"Methodapi0", "Methodapiv10", "Methodapiv1foobar0", "Methodapiv1foobarproxy0"}, false, nil, "", "", 0),
					"LoadBalancer":                 buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                      buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
					"CustomDomain":                 buildCustomDomain("example.com", "arn::foobar", "REGIONAL", "TLS_1_2"),
					"CustomDomainBasePathMapping0": buildCustomDomainBasePathMapping("example.com", "baz", "", 0),
				},
				Outputs: map[string]interface{}{
					"RestAPIID0":               Output{Value: cfn.Ref("RestAPI0")},
					"APIGatewayEndpoint0":      Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI0"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"ClientARNS":               Output{Value: strings.Join([]string{"arn::foo"}, ",")},
					"APIGWEndpointType":        Output{Value: "REGIONAL"},
					"SSLCertArn":               Output{Value: "arn::foobar"},
					"CustomDomainName":         Output{Value: "example.com"},
					"CustomDomainHostname":     Output{Value: cfn.GetAtt("CustomDomain", "RegionalDomainName")},
					"CustomDomainHostedZoneID": Output{Value: cfn.GetAtt("CustomDomain", "RegionalHostedZoneId")},
					"RequestTimeout":           Output{Value: "10000"},
					"TLSPolicy":                Output{Value: "TLS_1_2"},
					"CustomDomainBasePath":     Output{Value: ""},
					"IngressRules":             Output{Value: getIngressRulesJsonStr()},
				},
			},
		},
		{
			name: "generates template with custom domain edge api with WAF",
			args: &TemplateConfig{
				Rule: extensionsv1beta1.IngressRule{
					IngressRuleValue: extensionsv1beta1.IngressRuleValue{
						HTTP: &extensionsv1beta1.HTTPIngressRuleValue{
							Paths: []extensionsv1beta1.HTTPIngressPath{
								{
									Path: "/api/v1/foobar",
									Backend: extensionsv1beta1.IngressBackend{
										ServiceName: "foobar-service",
										ServicePort: intstr.FromInt(8080),
									},
								},
							},
						},
					},
				},
				Network: &network.Network{
					Vpc: &ec2.Vpc{
						VpcId:     aws.String("foo"),
						CidrBlock: aws.String("10.0.0.0/24"),
					},
					InstanceIDs:      []string{"i-foo"},
					SubnetIDs:        []string{"sn-foo"},
					SecurityGroupIDs: []string{"sg-foo"},
				},
				Arns:                   []string{"arn::foo"},
				StageName:              "baz",
				NodePort:               30123,
				CustomDomainName:       "example.com",
				CertificateArn:         "arn::foobar",
				WAFEnabled:             true,
				WAFRulesJSON:           "[]",
				WAFAssociation:         true,
				RequestTimeout:         10000,
				TLSPolicy:              "TLS_1_2",
				MinimumCompressionSize: 0,
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"RestAPIEmptyModel0":           buildAWSApiGatewayEmptyModel(0),
					"LambdaInvokeRole":             buildLambdaExecutionRole(),
					"Methodapi0":                   buildAWSApiGatewayMethod("Resourceapi0", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv10":                 buildAWSApiGatewayMethod("Resourceapiv10", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv1foobar0":           buildAWSApiGatewayMethod("Resourceapiv1foobar0", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv1foobarproxy0":      buildAWSApiGatewayMethod("Resourceapiv1foobarproxy0", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Resourceapi0":                 buildAWSApiGatewayResource(cfn.GetAtt("RestAPI0", "RootResourceId"), "api", 0),
					"Resourceapiv10":               buildAWSApiGatewayResource(cfn.Ref("Resourceapi0"), "v1", 0),
					"Resourceapiv1foobar0":         buildAWSApiGatewayResource(cfn.Ref("Resourceapiv10"), "foobar", 0),
					"Resourceapiv1foobarproxy0":    buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar0"), "{proxy+}", 0),
					"TargetGroup":                  buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":                     buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":        buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI0":                     buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "AWS_IAM", 0, cfn.Ref("AWS::StackName"), []string{"AWS::NoValue"}),
					"Deployment0":                  buildAWSApiGatewayDeployment("baz", []string{"Methodapi0", "Methodapiv10", "Methodapiv1foobar0", "Methodapiv1foobarproxy0"}, false, nil, "", "", 0),
					"LoadBalancer":                 buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                      buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
					"CustomDomain":                 buildCustomDomain("example.com", "arn::foobar", "EDGE", "TLS_1_2"),
					"CustomDomainBasePathMapping0": buildCustomDomainBasePathMapping("example.com", "baz", "", 0),
					"WAFAcl":                       buildAWSWAFWebACL("REGIONAL", "[]"),
					"WAFAssociation0":              buildAWSWAFWebACLAssociation("baz", 0),
				},
				Outputs: map[string]interface{}{
					"RestAPIID0":               Output{Value: cfn.Ref("RestAPI0")},
					"APIGatewayEndpoint0":      Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI0"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"ClientARNS":               Output{Value: strings.Join([]string{"arn::foo"}, ",")},
					"APIGWEndpointType":        Output{Value: "EDGE"},
					"SSLCertArn":               Output{Value: "arn::foobar"},
					"CustomDomainName":         Output{Value: "example.com"},
					"CustomDomainHostname":     Output{Value: cfn.GetAtt("CustomDomain", "DistributionDomainName")},
					"CustomDomainHostedZoneID": Output{Value: cfn.GetAtt("CustomDomain", "DistributionHostedZoneId")},
					"WAFEnabled":               Output{Value: "true"},
					"WAFRules":                 Output{Value: "[]"},
					"WAFScope":                 Output{Value: "REGIONAL"},
					"WAFAssociation0":          Output{Value: cfn.Ref("WAFAssociation0")},
					"RequestTimeout":           Output{Value: "10000"},
					"TLSPolicy":                Output{Value: "TLS_1_2"},
					"CustomDomainBasePath":     Output{Value: ""},
					"IngressRules":             Output{Value: getIngressRulesJsonStr()},
				},
			},
		},
		{
			name: "generates template with custom domain edge api with WAF without association",
			args: &TemplateConfig{
				Rule: extensionsv1beta1.IngressRule{
					IngressRuleValue: extensionsv1beta1.IngressRuleValue{
						HTTP: &extensionsv1beta1.HTTPIngressRuleValue{
							Paths: []extensionsv1beta1.HTTPIngressPath{
								{
									Path: "/api/v1/foobar",
									Backend: extensionsv1beta1.IngressBackend{
										ServiceName: "foobar-service",
										ServicePort: intstr.FromInt(8080),
									},
								},
							},
						},
					},
				},
				Network: &network.Network{
					Vpc: &ec2.Vpc{
						VpcId:     aws.String("foo"),
						CidrBlock: aws.String("10.0.0.0/24"),
					},
					InstanceIDs:      []string{"i-foo"},
					SubnetIDs:        []string{"sn-foo"},
					SecurityGroupIDs: []string{"sg-foo"},
				},
				Arns:                   []string{"arn::foo"},
				StageName:              "baz",
				NodePort:               30123,
				CustomDomainName:       "example.com",
				CertificateArn:         "arn::foobar",
				WAFEnabled:             true,
				WAFRulesJSON:           "[]",
				WAFAssociation:         false,
				RequestTimeout:         10000,
				TLSPolicy:              "TLS_1_2",
				MinimumCompressionSize: 0,
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"RestAPIEmptyModel0":           buildAWSApiGatewayEmptyModel(0),
					"LambdaInvokeRole":             buildLambdaExecutionRole(),
					"Methodapi0":                   buildAWSApiGatewayMethod("Resourceapi0", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv10":                 buildAWSApiGatewayMethod("Resourceapiv10", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv1foobar0":           buildAWSApiGatewayMethod("Resourceapiv1foobar0", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv1foobarproxy0":      buildAWSApiGatewayMethod("Resourceapiv1foobarproxy0", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Resourceapi0":                 buildAWSApiGatewayResource(cfn.GetAtt("RestAPI0", "RootResourceId"), "api", 0),
					"Resourceapiv10":               buildAWSApiGatewayResource(cfn.Ref("Resourceapi0"), "v1", 0),
					"Resourceapiv1foobar0":         buildAWSApiGatewayResource(cfn.Ref("Resourceapiv10"), "foobar", 0),
					"Resourceapiv1foobarproxy0":    buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar0"), "{proxy+}", 0),
					"TargetGroup":                  buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":                     buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":        buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI0":                     buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "AWS_IAM", 0, cfn.Ref("AWS::StackName"), []string{"AWS::NoValue"}),
					"Deployment0":                  buildAWSApiGatewayDeployment("baz", []string{"Methodapi0", "Methodapiv10", "Methodapiv1foobar0", "Methodapiv1foobarproxy0"}, false, nil, "", "", 0),
					"LoadBalancer":                 buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                      buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
					"CustomDomain":                 buildCustomDomain("example.com", "arn::foobar", "EDGE", "TLS_1_2"),
					"CustomDomainBasePathMapping0": buildCustomDomainBasePathMapping("example.com", "baz", "", 0),
					"WAFAcl":                       buildAWSWAFWebACL("REGIONAL", "[]"),
				},
				Outputs: map[string]interface{}{
					"RestAPIID0":               Output{Value: cfn.Ref("RestAPI0")},
					"APIGatewayEndpoint0":      Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI0"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"ClientARNS":               Output{Value: strings.Join([]string{"arn::foo"}, ",")},
					"APIGWEndpointType":        Output{Value: "EDGE"},
					"SSLCertArn":               Output{Value: "arn::foobar"},
					"CustomDomainName":         Output{Value: "example.com"},
					"CustomDomainHostname":     Output{Value: cfn.GetAtt("CustomDomain", "DistributionDomainName")},
					"CustomDomainHostedZoneID": Output{Value: cfn.GetAtt("CustomDomain", "DistributionHostedZoneId")},
					"WAFEnabled":               Output{Value: "true"},
					"WAFRules":                 Output{Value: "[]"},
					"WAFScope":                 Output{Value: "REGIONAL"},
					"WAFAssociation0":          Output{Value: cfn.Ref("WAFAssociation0")},
					"RequestTimeout":           Output{Value: "10000"},
					"TLSPolicy":                Output{Value: "TLS_1_2"},
					"CustomDomainBasePath":     Output{Value: ""},
					"IngressRules":             Output{Value: getIngressRulesJsonStr()},
				},
			},
		},
		{
			name: "generates template with custom domain regional api with WAF",
			args: &TemplateConfig{
				Rule: extensionsv1beta1.IngressRule{
					IngressRuleValue: extensionsv1beta1.IngressRuleValue{
						HTTP: &extensionsv1beta1.HTTPIngressRuleValue{
							Paths: []extensionsv1beta1.HTTPIngressPath{
								{
									Path: "/api/v1/foobar",
									Backend: extensionsv1beta1.IngressBackend{
										ServiceName: "foobar-service",
										ServicePort: intstr.FromInt(8080),
									},
								},
							},
						},
					},
				},
				Network: &network.Network{
					Vpc: &ec2.Vpc{
						VpcId:     aws.String("foo"),
						CidrBlock: aws.String("10.0.0.0/24"),
					},
					InstanceIDs:      []string{"i-foo"},
					SubnetIDs:        []string{"sn-foo"},
					SecurityGroupIDs: []string{"sg-foo"},
				},
				Arns:                   []string{"arn::foo"},
				StageName:              "baz",
				NodePort:               30123,
				CustomDomainName:       "example.com",
				CertificateArn:         "arn::foobar",
				APIEndpointType:        "REGIONAL",
				WAFEnabled:             true,
				WAFRulesJSON:           "[]",
				WAFAssociation:         true,
				RequestTimeout:         10000,
				TLSPolicy:              "TLS_1_2",
				MinimumCompressionSize: 0,
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"RestAPIEmptyModel0":           buildAWSApiGatewayEmptyModel(0),
					"LambdaInvokeRole":             buildLambdaExecutionRole(),
					"Methodapi0":                   buildAWSApiGatewayMethod("Resourceapi0", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv10":                 buildAWSApiGatewayMethod("Resourceapiv10", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv1foobar0":           buildAWSApiGatewayMethod("Resourceapiv1foobar0", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Methodapiv1foobarproxy0":      buildAWSApiGatewayMethod("Resourceapiv1foobarproxy0", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM", "ANY", APIResource{}, 0, nil, 0, false, nil),
					"Resourceapi0":                 buildAWSApiGatewayResource(cfn.GetAtt("RestAPI0", "RootResourceId"), "api", 0),
					"Resourceapiv10":               buildAWSApiGatewayResource(cfn.Ref("Resourceapi0"), "v1", 0),
					"Resourceapiv1foobar0":         buildAWSApiGatewayResource(cfn.Ref("Resourceapiv10"), "foobar", 0),
					"Resourceapiv1foobarproxy0":    buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar0"), "{proxy+}", 0),
					"TargetGroup":                  buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":                     buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":        buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI0":                     buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "REGIONAL", "AWS_IAM", 0, cfn.Ref("AWS::StackName"), []string{"AWS::NoValue"}),
					"Deployment0":                  buildAWSApiGatewayDeployment("baz", []string{"Methodapi0", "Methodapiv10", "Methodapiv1foobar0", "Methodapiv1foobarproxy0"}, false, nil, "", "", 0),
					"LoadBalancer":                 buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                      buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
					"CustomDomain":                 buildCustomDomain("example.com", "arn::foobar", "REGIONAL", "TLS_1_2"),
					"CustomDomainBasePathMapping0": buildCustomDomainBasePathMapping("example.com", "baz", "", 0),
					"WAFAcl":                       buildAWSWAFWebACL("REGIONAL", "[]"),
					"WAFAssociation0":              buildAWSWAFWebACLAssociation("baz", 0),
				},
				Outputs: map[string]interface{}{
					"RestAPIID0":               Output{Value: cfn.Ref("RestAPI0")},
					"APIGatewayEndpoint0":      Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI0"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"ClientARNS":               Output{Value: strings.Join([]string{"arn::foo"}, ",")},
					"APIGWEndpointType":        Output{Value: "REGIONAL"},
					"SSLCertArn":               Output{Value: "arn::foobar"},
					"CustomDomainName":         Output{Value: "example.com"},
					"CustomDomainHostname":     Output{Value: cfn.GetAtt("CustomDomain", "RegionalDomainName")},
					"CustomDomainHostedZoneID": Output{Value: cfn.GetAtt("CustomDomain", "RegionalHostedZoneId")},
					"WAFEnabled":               Output{Value: "true"},
					"WAFRules":                 Output{Value: "[]"},
					"WAFScope":                 Output{Value: "REGIONAL"},
					"WAFAssociation0":          Output{Value: cfn.Ref("WAFAssociation0")},
					"RequestTimeout":           Output{Value: "10000"},
					"TLSPolicy":                Output{Value: "TLS_1_2"},
					"CustomDomainBasePath":     Output{Value: ""},
					"IngressRules":             Output{Value: getIngressRulesJsonStr()},
				},
			},
		},
		{
			name: "generates template with defined public apis",
			args: &TemplateConfig{
				Rule: extensionsv1beta1.IngressRule{
					IngressRuleValue: extensionsv1beta1.IngressRuleValue{
						HTTP: &extensionsv1beta1.HTTPIngressRuleValue{
							Paths: []extensionsv1beta1.HTTPIngressPath{
								{
									Path: "/api/v1/foobar",
									Backend: extensionsv1beta1.IngressBackend{
										ServiceName: "foobar-service",
										ServicePort: intstr.FromInt(8080),
									},
								},
							},
						},
					},
				},
				Network: &network.Network{
					Vpc: &ec2.Vpc{
						VpcId:     aws.String("foo"),
						CidrBlock: aws.String("10.0.0.0/24"),
					},
					InstanceIDs:      []string{"i-foo"},
					SubnetIDs:        []string{"sn-foo"},
					SecurityGroupIDs: []string{"sg-foo"},
				},
				Arns:                   []string{"arn::foo"},
				StageName:              "baz",
				NodePort:               30123,
				RequestTimeout:         10000,
				TLSPolicy:              "TLS_1_2",
				MinimumCompressionSize: 0,
				APIResources:           getAPIResourcesWithLambda(),
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"RestAPIEmptyModel0":        buildAWSApiGatewayEmptyModel(0),
					"LambdaInvokeRole":          buildLambdaExecutionRole(),
					"Methodapiv1foobarGET0":     buildAWSApiGatewayMethod("Resourceapiv1foobar0", toPath(3, []string{"", "api", "v1", "foobar"}), 10000, "AWS_IAM", "GET", getAPIResource(), 0, nil, 0, true, nil),
					"Methodapiv1foobarPOST0":    buildAWSApiGatewayMethod("Resourceapiv1foobar0", toPath(3, []string{"", "api", "v1", "foobar"}), 10000, "AWS_IAM", "POST", getAPIResource(), 0, nil, 0, false, []string{"foo", "bar"}),
					"Methodapiv1foolambdaPOST0": buildAWSApiGatewayMethod("Resourceapiv1foolambda0", toPath(3, []string{"", "api", "v1", "foolambda"}), 10000, "AWS_IAM", "POST", getLambdaAPIResource(), 0, nil, 0, false, []string{"foo", "bar"}),
					"Resourceapi0":              buildAWSApiGatewayResource(cfn.GetAtt("RestAPI0", "RootResourceId"), "api", 0),
					"Resourceapiv10":            buildAWSApiGatewayResource(cfn.Ref("Resourceapi0"), "v1", 0),
					"Resourceapiv1foobar0":      buildAWSApiGatewayResource(cfn.Ref("Resourceapiv10"), "foobar", 0),
					"Resourceapiv1foolambda0":   buildAWSApiGatewayResource(cfn.Ref("Resourceapiv10"), "foolambda", 0),
					"TargetGroup":               buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":                  buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":     buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI0":                  buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "AWS_IAM", 0, cfn.Ref("AWS::StackName"), []string{"AWS::NoValue"}),
					"Deployment0":               buildAWSApiGatewayDeployment("baz", []string{"Methodapiv1foobarGET0", "Methodapiv1foobarPOST0", "Methodapiv1foolambdaPOST0"}, false, getAPIResources(), "", "", 0),
					"LoadBalancer":              buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                   buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
				},
				Outputs: map[string]interface{}{
					"RestAPIID0":          Output{Value: cfn.Ref("RestAPI0")},
					"APIGatewayEndpoint0": Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI0"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"ClientARNS":          Output{Value: strings.Join([]string{"arn::foo"}, ",")},
					"APIGWEndpointType":   Output{Value: "EDGE"},
					"RequestTimeout":      Output{Value: "10000"},
					"APIResources":        Output{Value: getAPIWithLambdaResourcesBytes()},
					"IngressRules":        Output{Value: getIngressRulesJsonStr()},
				},
			},
		},
		{
			name: "generates template with defined public apis with cache",
			args: &TemplateConfig{
				Rule: extensionsv1beta1.IngressRule{
					IngressRuleValue: extensionsv1beta1.IngressRuleValue{
						HTTP: &extensionsv1beta1.HTTPIngressRuleValue{
							Paths: []extensionsv1beta1.HTTPIngressPath{
								{
									Path: "/api/v1/foobar",
									Backend: extensionsv1beta1.IngressBackend{
										ServiceName: "foobar-service",
										ServicePort: intstr.FromInt(8080),
									},
								},
							},
						},
					},
				},
				Network: &network.Network{
					Vpc: &ec2.Vpc{
						VpcId:     aws.String("foo"),
						CidrBlock: aws.String("10.0.0.0/24"),
					},
					InstanceIDs:      []string{"i-foo"},
					SubnetIDs:        []string{"sn-foo"},
					SecurityGroupIDs: []string{"sg-foo"},
				},
				Arns:                   []string{"arn::foo"},
				StageName:              "baz",
				NodePort:               30123,
				RequestTimeout:         10000,
				TLSPolicy:              "TLS_1_2",
				MinimumCompressionSize: 0,
				APIResources:           getAPIResources(),
				CachingEnabled:         true,
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"RestAPIEmptyModel0":     buildAWSApiGatewayEmptyModel(0),
					"LambdaInvokeRole":       buildLambdaExecutionRole(),
					"Methodapiv1foobarGET0":  buildAWSApiGatewayMethod("Resourceapiv1foobar0", toPath(3, []string{"", "api", "v1", "foobar"}), 10000, "AWS_IAM", "GET", getAPIResource(), 0, nil, 0, true, nil),
					"Methodapiv1foobarPOST0": buildAWSApiGatewayMethod("Resourceapiv1foobar0", toPath(3, []string{"", "api", "v1", "foobar"}), 10000, "AWS_IAM", "POST", getAPIResource(), 0, nil, 0, false, []string{"foo", "bar"}),
					"Resourceapi0":           buildAWSApiGatewayResource(cfn.GetAtt("RestAPI0", "RootResourceId"), "api", 0),
					"Resourceapiv10":         buildAWSApiGatewayResource(cfn.Ref("Resourceapi0"), "v1", 0),
					"Resourceapiv1foobar0":   buildAWSApiGatewayResource(cfn.Ref("Resourceapiv10"), "foobar", 0),
					"TargetGroup":            buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":               buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":  buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI0":               buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "AWS_IAM", 0, cfn.Ref("AWS::StackName"), []string{"AWS::NoValue"}),
					"Deployment0":            buildAWSApiGatewayDeployment("baz", []string{"Methodapiv1foobarGET0", "Methodapiv1foobarPOST0"}, true, getAPIResources(), "0.5", "", 0),
					"LoadBalancer":           buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
				},
				Outputs: map[string]interface{}{
					"RestAPIID0":          Output{Value: cfn.Ref("RestAPI0")},
					"APIGatewayEndpoint0": Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI0"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"ClientARNS":          Output{Value: strings.Join([]string{"arn::foo"}, ",")},
					"APIGWEndpointType":   Output{Value: "EDGE"},
					"RequestTimeout":      Output{Value: "10000"},
					"CachingEnabled":      Output{Value: "true"},
					"CachingSize":         Output{Value: "0.5"},
					"APIResources":        Output{Value: getAPIResourcesBytes()},
					"IngressRules":        Output{Value: getIngressRulesJsonStr()},
				},
			},
		},
		{
			name: "generates template with defined public apis with cache size only",
			args: &TemplateConfig{
				Rule: extensionsv1beta1.IngressRule{
					IngressRuleValue: extensionsv1beta1.IngressRuleValue{
						HTTP: &extensionsv1beta1.HTTPIngressRuleValue{
							Paths: []extensionsv1beta1.HTTPIngressPath{
								{
									Path: "/api/v1/foobar",
									Backend: extensionsv1beta1.IngressBackend{
										ServiceName: "foobar-service",
										ServicePort: intstr.FromInt(8080),
									},
								},
							},
						},
					},
				},
				Network: &network.Network{
					Vpc: &ec2.Vpc{
						VpcId:     aws.String("foo"),
						CidrBlock: aws.String("10.0.0.0/24"),
					},
					InstanceIDs:      []string{"i-foo"},
					SubnetIDs:        []string{"sn-foo"},
					SecurityGroupIDs: []string{"sg-foo"},
				},
				Arns:                   []string{"arn::foo"},
				StageName:              "baz",
				NodePort:               30123,
				RequestTimeout:         10000,
				TLSPolicy:              "TLS_1_2",
				MinimumCompressionSize: 0,
				APIResources:           getAPIResources(),
				CachingSize:            "0.5",
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"RestAPIEmptyModel0":     buildAWSApiGatewayEmptyModel(0),
					"LambdaInvokeRole":       buildLambdaExecutionRole(),
					"Methodapiv1foobarGET0":  buildAWSApiGatewayMethod("Resourceapiv1foobar0", toPath(3, []string{"", "api", "v1", "foobar"}), 10000, "AWS_IAM", "GET", getAPIResource(), 0, nil, 0, true, nil),
					"Methodapiv1foobarPOST0": buildAWSApiGatewayMethod("Resourceapiv1foobar0", toPath(3, []string{"", "api", "v1", "foobar"}), 10000, "AWS_IAM", "POST", getAPIResource(), 0, nil, 0, false, []string{"foo", "bar"}),
					"Resourceapi0":           buildAWSApiGatewayResource(cfn.GetAtt("RestAPI0", "RootResourceId"), "api", 0),
					"Resourceapiv10":         buildAWSApiGatewayResource(cfn.Ref("Resourceapi0"), "v1", 0),
					"Resourceapiv1foobar0":   buildAWSApiGatewayResource(cfn.Ref("Resourceapiv10"), "foobar", 0),
					"TargetGroup":            buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":               buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":  buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI0":               buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "AWS_IAM", 0, cfn.Ref("AWS::StackName"), []string{"AWS::NoValue"}),
					"Deployment0":            buildAWSApiGatewayDeployment("baz", []string{"Methodapiv1foobarGET0", "Methodapiv1foobarPOST0"}, true, getAPIResources(), "0.5", "", 0),
					"LoadBalancer":           buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
				},
				Outputs: map[string]interface{}{
					"RestAPIID0":          Output{Value: cfn.Ref("RestAPI0")},
					"APIGatewayEndpoint0": Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI0"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"ClientARNS":          Output{Value: strings.Join([]string{"arn::foo"}, ",")},
					"APIGWEndpointType":   Output{Value: "EDGE"},
					"RequestTimeout":      Output{Value: "10000"},
					"CachingEnabled":      Output{Value: "true"},
					"CachingSize":         Output{Value: "0.5"},
					"APIResources":        Output{Value: getAPIResourcesBytes()},
					"IngressRules":        Output{Value: getIngressRulesJsonStr()},
				},
			},
		},
		{
			name: "generates template API Defs with Usage plans and auth enabled",
			args: &TemplateConfig{
				Rule: extensionsv1beta1.IngressRule{
					IngressRuleValue: extensionsv1beta1.IngressRuleValue{
						HTTP: &extensionsv1beta1.HTTPIngressRuleValue{
							Paths: []extensionsv1beta1.HTTPIngressPath{
								{
									Path: "/api/v1/foobar",
									Backend: extensionsv1beta1.IngressBackend{
										ServiceName: "foobar-service",
										ServicePort: intstr.FromInt(8080),
									},
								},
							},
						},
					},
				},
				Network: &network.Network{
					Vpc: &ec2.Vpc{
						VpcId:     aws.String("foo"),
						CidrBlock: aws.String("10.0.0.0/24"),
					},
					InstanceIDs:      []string{"i-foo"},
					SubnetIDs:        []string{"sn-foo"},
					SecurityGroupIDs: []string{"sg-foo"},
				},
				Arns:                   []string{"arn::foo"},
				StageName:              "baf",
				NodePort:               30123,
				RequestTimeout:         10000,
				TLSPolicy:              "TLS_1_2",
				MinimumCompressionSize: 0,
				AWSAPIDefinitions:      getAPIDefs(),
				CustomDomainName:       "example.com",
				CertificateArn:         "arn::foobar",
				UsagePlans:             getSecondUsagePlans(),
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"RestAPIEmptyModel0":           buildAWSApiGatewayEmptyModel(0),
					"RestAPIEmptyModel1":           buildAWSApiGatewayEmptyModel(1),
					"LambdaInvokeRole":             buildLambdaExecutionRole(),
					"Methodapiv1foobarGET0":        buildAWSApiGatewayMethod("Resourceapiv1foobar0", toPath(3, []string{"", "api", "v1", "foobar"}), 10000, "AWS_IAM", "GET", getAPIResource(), 0, getAuthDefPointer(), 0, true, nil),
					"Methodapiv1foobarPOST0":       buildAWSApiGatewayMethod("Resourceapiv1foobar0", toPath(3, []string{"", "api", "v1", "foobar"}), 10000, "AWS_IAM", "POST", getAPIResource(), 0, getCognitoAuthDefPointer(), 1, false, []string{"foo", "bar"}),
					"Methodapiv1foobarGET1":        buildAWSApiGatewayMethod("Resourceapiv1foobar1", toPath(3, []string{"", "api", "v1", "foobar"}), 10000, "AWS_IAM", "GET", getAPIResource(), 1, getAuthDefPointer(), 0, true, nil),
					"Methodapiv1foobarPOST1":       buildAWSApiGatewayMethod("Resourceapiv1foobar1", toPath(3, []string{"", "api", "v1", "foobar"}), 10000, "AWS_IAM", "POST", getAPIResource(), 1, getCognitoAuthDefPointer(), 1, false, []string{"foo", "bar"}),
					"Resourceapi0":                 buildAWSApiGatewayResource(cfn.GetAtt("RestAPI0", "RootResourceId"), "api", 0),
					"Resourceapiv10":               buildAWSApiGatewayResource(cfn.Ref("Resourceapi0"), "v1", 0),
					"Resourceapiv1foobar0":         buildAWSApiGatewayResource(cfn.Ref("Resourceapiv10"), "foobar", 0),
					"Resourceapi1":                 buildAWSApiGatewayResource(cfn.GetAtt("RestAPI1", "RootResourceId"), "api", 1),
					"Resourceapiv11":               buildAWSApiGatewayResource(cfn.Ref("Resourceapi1"), "v1", 1),
					"Resourceapiv1foobar1":         buildAWSApiGatewayResource(cfn.Ref("Resourceapiv11"), "foobar", 1),
					"TargetGroup":                  buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":                     buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":        buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI0":                     buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "AWS_IAM", 0, "api0", []string{"foo/bar"}),
					"RestAPI1":                     buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "AWS_IAM", 0, "api1", nil),
					"Deployment0":                  buildAWSApiGatewayDeployment("baf", []string{"Methodapiv1foobarGET0", "Methodapiv1foobarPOST0"}, false, nil, "", "", 0),
					"Deployment1":                  buildAWSApiGatewayDeployment("baf", []string{"Methodapiv1foobarGET1", "Methodapiv1foobarPOST1"}, false, nil, "", "", 1),
					"LoadBalancer":                 buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                      buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
					"APIKeyUsagePlan000":           getSecondAPIKeyMappingBuild(0, 0, 0),
					"APIKeyUsagePlan010":           getSecondAPIKeyMappingBuild(1, 0, 0),
					"APIKeyUsagePlan100":           getSecondAPIKeyMappingBuild(0, 1, 0),
					"APIKeyUsagePlan110":           getSecondAPIKeyMappingBuild(1, 1, 0),
					"APIKeyUsagePlan001":           getSecondAPIKeyMappingBuild(0, 0, 1),
					"APIKeyUsagePlan011":           getSecondAPIKeyMappingBuild(1, 0, 1),
					"APIKeyUsagePlan101":           getSecondAPIKeyMappingBuild(0, 1, 1),
					"APIKeyUsagePlan111":           getSecondAPIKeyMappingBuild(1, 1, 1),
					"UsagePlan00":                  buildUsagePlan(getUsagePlanSilver(), "baf", 0, buildMethodThrottling(getMethodThrottlingParams(), "baf", 0)),
					"UsagePlan10":                  buildUsagePlan(getSecondUsagePlan(), "baf", 0, buildMethodThrottling(getMethodThrottlingParams(), "baf", 0)),
					"UsagePlan01":                  buildGlobalUsagePlan(getUsagePlanSilver(), "baf", 1, buildMethodThrottling(getMethodThrottlingParams(), "baf", 1), 2),
					"UsagePlan11":                  buildGlobalUsagePlan(getSecondUsagePlan(), "baf", 1, buildMethodThrottling(getMethodThrottlingParams(), "baf", 1), 2),
					"APIKey000":                    getSecondAPIKeyBuild(0, 0),
					"APIKey100":                    getSecondAPIKeyBuild(0, 0),
					"APIKey010":                    getSecondAPIKeyBuild(1, 0),
					"APIKey110":                    getSecondAPIKeyBuild(1, 0),
					"APIKey001":                    getSecondAPIKeyBuild(0, 1),
					"APIKey101":                    getSecondAPIKeyBuild(0, 1),
					"APIKey011":                    getSecondAPIKeyBuild(1, 1),
					"APIKey111":                    getSecondAPIKeyBuild(1, 1),
					"RestAPIAuthorizer00":          buildAuthorizer(getAuthDef(), 0),
					"RestAPIAuthorizer01":          buildAuthorizer(getAuthDefCognito(), 0),
					"RestAPIAuthorizer10":          buildAuthorizer(getAuthDef(), 1),
					"RestAPIAuthorizer11":          buildAuthorizer(getAuthDefCognito(), 1),
					"CustomDomain":                 buildCustomDomain("example.com", "arn::foobar", "EDGE", "TLS_1_2"),
					"CustomDomainBasePathMapping0": buildCustomDomainBasePathMapping("example.com", "baf", "api0", 0),
					"CustomDomainBasePathMapping1": buildCustomDomainBasePathMapping("example.com", "baf", "api1", 1),
				},
				Outputs: map[string]interface{}{
					"RestAPIID0":               Output{Value: cfn.Ref("RestAPI0")},
					"RestAPIID1":               Output{Value: cfn.Ref("RestAPI1")},
					"APIGatewayEndpoint0":      Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI0"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baf"})},
					"APIGatewayEndpoint1":      Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI1"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baf"})},
					"ClientARNS":               Output{Value: strings.Join([]string{"arn::foo"}, ",")},
					"APIGWEndpointType":        Output{Value: "EDGE"},
					"RequestTimeout":           Output{Value: "10000"},
					"AWSAPIConfigs":            Output{Value: getAWSAPIDefBytes()},
					"SSLCertArn":               Output{Value: "arn::foobar"},
					"CustomDomainName":         Output{Value: "example.com"},
					"CustomDomainHostname":     Output{Value: cfn.GetAtt("CustomDomain", "DistributionDomainName")},
					"CustomDomainHostedZoneID": Output{Value: cfn.GetAtt("CustomDomain", "DistributionHostedZoneId")},
					"TLSPolicy":                Output{Value: "TLS_1_2"},
					"CustomDomainBasePath":     Output{Value: ""},
					"IngressRules":             Output{Value: getIngressRulesJsonStr()},
					"UsagePlansData":           Output{Value: getSecondUsagePlanBytes()},
				},
			},
		},
		{
			name: "generates template API Defs without Usage plans and with auth enabled",
			args: &TemplateConfig{
				Rule: extensionsv1beta1.IngressRule{
					IngressRuleValue: extensionsv1beta1.IngressRuleValue{
						HTTP: &extensionsv1beta1.HTTPIngressRuleValue{
							Paths: []extensionsv1beta1.HTTPIngressPath{
								{
									Path: "/api/v1/foobar",
									Backend: extensionsv1beta1.IngressBackend{
										ServiceName: "foobar-service",
										ServicePort: intstr.FromInt(8080),
									},
								},
							},
						},
					},
				},
				Network: &network.Network{
					Vpc: &ec2.Vpc{
						VpcId:     aws.String("foo"),
						CidrBlock: aws.String("10.0.0.0/24"),
					},
					InstanceIDs:      []string{"i-foo"},
					SubnetIDs:        []string{"sn-foo"},
					SecurityGroupIDs: []string{"sg-foo"},
				},
				StageName:              "baz",
				NodePort:               30123,
				RequestTimeout:         10000,
				TLSPolicy:              "TLS_1_2",
				UsagePlans:             getUsagePlans(),
				MinimumCompressionSize: 1000000000,
				AWSAPIDefinitions:      getAPIDefsWOUsagePlans(),
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"RestAPIEmptyModel0":        buildAWSApiGatewayEmptyModel(0),
					"RestAPIEmptyModel1":        buildAWSApiGatewayEmptyModel(1),
					"RestAPIEmptyModel2":        buildAWSApiGatewayEmptyModel(2),
					"RestAPIEmptyModel3":        buildAWSApiGatewayEmptyModel(3),
					"LambdaInvokeRole":          buildLambdaExecutionRole(),
					"Methodapi0":                buildAWSApiGatewayMethod("Resourceapi0", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 0, getAuthDefCognitoPointer(), 0, true, nil),
					"Methodapiv10":              buildAWSApiGatewayMethod("Resourceapiv10", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 0, getAuthDefCognitoPointer(), 0, true, nil),
					"Methodapiv1foobar0":        buildAWSApiGatewayMethod("Resourceapiv1foobar0", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 0, getAuthDefCognitoPointer(), 0, true, nil),
					"Methodapiv1foobarproxy0":   buildAWSApiGatewayMethod("Resourceapiv1foobarproxy0", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 0, getAuthDefCognitoPointer(), 0, true, nil),
					"Methodapi1":                buildAWSApiGatewayMethod("Resourceapi1", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 1, getAuthDefCognitoPointer(), 0, false, nil),
					"Methodapiv11":              buildAWSApiGatewayMethod("Resourceapiv11", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 1, getAuthDefCognitoPointer(), 0, false, nil),
					"Methodapiv1foobar1":        buildAWSApiGatewayMethod("Resourceapiv1foobar1", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 1, getAuthDefCognitoPointer(), 0, false, nil),
					"Methodapiv1foobarproxy1":   buildAWSApiGatewayMethod("Resourceapiv1foobarproxy1", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 1, getAuthDefCognitoPointer(), 0, false, nil),
					"Methodapi2":                buildAWSApiGatewayMethod("Resourceapi2", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 2, getAuthDefCognitoPointer(), 0, false, nil),
					"Methodapiv12":              buildAWSApiGatewayMethod("Resourceapiv12", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 2, getAuthDefCognitoPointer(), 0, false, nil),
					"Methodapiv1foobar2":        buildAWSApiGatewayMethod("Resourceapiv1foobar2", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 2, getAuthDefCognitoPointer(), 0, false, nil),
					"Methodapiv1foobarproxy2":   buildAWSApiGatewayMethod("Resourceapiv1foobarproxy2", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 2, getAuthDefCognitoPointer(), 0, false, nil),
					"Methodapi3":                buildAWSApiGatewayMethod("Resourceapi3", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 3, getAuthDefCognitoPointer(), 0, false, nil),
					"Methodapiv13":              buildAWSApiGatewayMethod("Resourceapiv13", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 3, getAuthDefCognitoPointer(), 0, false, nil),
					"Methodapiv1foobar3":        buildAWSApiGatewayMethod("Resourceapiv1foobar3", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 3, getAuthDefCognitoPointer(), 0, false, nil),
					"Methodapiv1foobarproxy3":   buildAWSApiGatewayMethod("Resourceapiv1foobarproxy3", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 3, getAuthDefCognitoPointer(), 0, false, nil),
					"Resourceapi0":              buildAWSApiGatewayResource(cfn.GetAtt("RestAPI0", "RootResourceId"), "api", 0),
					"Resourceapi1":              buildAWSApiGatewayResource(cfn.GetAtt("RestAPI1", "RootResourceId"), "api", 1),
					"Resourceapi2":              buildAWSApiGatewayResource(cfn.GetAtt("RestAPI2", "RootResourceId"), "api", 2),
					"Resourceapi3":              buildAWSApiGatewayResource(cfn.GetAtt("RestAPI3", "RootResourceId"), "api", 3),
					"Resourceapiv10":            buildAWSApiGatewayResource(cfn.Ref("Resourceapi0"), "v1", 0),
					"Resourceapiv1foobar0":      buildAWSApiGatewayResource(cfn.Ref("Resourceapiv10"), "foobar", 0),
					"Resourceapiv1foobarproxy0": buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar0"), "{proxy+}", 0),
					"Resourceapiv11":            buildAWSApiGatewayResource(cfn.Ref("Resourceapi1"), "v1", 1),
					"Resourceapiv1foobar1":      buildAWSApiGatewayResource(cfn.Ref("Resourceapiv11"), "foobar", 1),
					"Resourceapiv1foobarproxy1": buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar1"), "{proxy+}", 1),
					"Resourceapiv12":            buildAWSApiGatewayResource(cfn.Ref("Resourceapi2"), "v1", 2),
					"Resourceapiv1foobar2":      buildAWSApiGatewayResource(cfn.Ref("Resourceapiv12"), "foobar", 2),
					"Resourceapiv1foobarproxy2": buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar2"), "{proxy+}", 2),
					"Resourceapiv13":            buildAWSApiGatewayResource(cfn.Ref("Resourceapi3"), "v1", 3),
					"Resourceapiv1foobar3":      buildAWSApiGatewayResource(cfn.Ref("Resourceapiv13"), "foobar", 3),
					"Resourceapiv1foobarproxy3": buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar3"), "{proxy+}", 3),
					"TargetGroup":               buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":                  buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":     buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI0":                  buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "NONE", 1000000000, "api1", nil),
					"RestAPI1":                  buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "NONE", 1000000000, "api2", nil),
					"RestAPI2":                  buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "NONE", 1000000000, "api3", []string{"foo/bar"}),
					"RestAPI3":                  buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "NONE", 1000000000, "api4", []string{"foo/bar"}),
					"Deployment0":               buildAWSApiGatewayDeployment("baz", []string{"Methodapi0", "Methodapiv10", "Methodapiv1foobar0", "Methodapiv1foobarproxy0"}, false, nil, "", "", 0),
					"Deployment1":               buildAWSApiGatewayDeployment("baz", []string{"Methodapi1", "Methodapiv11", "Methodapiv1foobar1", "Methodapiv1foobarproxy1"}, false, nil, "", "", 1),
					"Deployment2":               buildAWSApiGatewayDeployment("baz", []string{"Methodapi2", "Methodapiv12", "Methodapiv1foobar2", "Methodapiv1foobarproxy2"}, false, nil, "", "", 2),
					"Deployment3":               buildAWSApiGatewayDeployment("baz", []string{"Methodapi3", "Methodapiv13", "Methodapiv1foobar3", "Methodapiv1foobarproxy3"}, false, nil, "", "", 3),
					"LoadBalancer":              buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                   buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
					"APIKeyUsagePlan000":        getAPIKeyMappingBuild(0, 0, 0),
					"APIKeyUsagePlan010":        getAPIKeyMappingBuild(1, 0, 0),
					"UsagePlan00":               buildGlobalUsagePlan(getUsagePlan(), "baz", 0, nil, 4),
					"APIKey000":                 getAPIKeyBuild(0),
					"APIKey010":                 getAPIKeyBuild(1),
					"RestAPIAuthorizer00":       buildAuthorizer(getAuthDefCognito(), 0),
					"RestAPIAuthorizer01":       buildAuthorizer(getAuthDefToken(), 0),
					"RestAPIAuthorizer02":       buildAuthorizer(getAuthDefRequest(), 0),
					"RestAPIAuthorizer10":       buildAuthorizer(getAuthDefCognito(), 1),
					"RestAPIAuthorizer11":       buildAuthorizer(getAuthDefToken(), 1),
					"RestAPIAuthorizer12":       buildAuthorizer(getAuthDefRequest(), 1),
					"RestAPIAuthorizer20":       buildAuthorizer(getAuthDefCognito(), 2),
					"RestAPIAuthorizer21":       buildAuthorizer(getAuthDefToken(), 2),
					"RestAPIAuthorizer22":       buildAuthorizer(getAuthDefRequest(), 2),
				},
				Outputs: map[string]interface{}{
					"RestAPIID0":             Output{Value: cfn.Ref("RestAPI0")},
					"RestAPIID1":             Output{Value: cfn.Ref("RestAPI1")},
					"RestAPIID2":             Output{Value: cfn.Ref("RestAPI2")},
					"RestAPIID3":             Output{Value: cfn.Ref("RestAPI3")},
					"APIGatewayEndpoint0":    Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI0"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"APIGatewayEndpoint1":    Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI1"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"APIGatewayEndpoint2":    Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI2"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"APIGatewayEndpoint3":    Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI3"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"APIGWEndpointType":      Output{Value: "EDGE"},
					"RequestTimeout":         Output{Value: "10000"},
					"MinimumCompressionSize": Output{Value: "1000000000"},
					"UsagePlansData":         Output{Value: getUsagePlanBytes()},
					"AWSAPIConfigs":          Output{Value: getAWSAPIDefWOUsagePlansBytes()},
					"IngressRules":           Output{Value: getIngressRulesJsonStr()},
				},
			},
		},
		{
			name: "generates template API Defs without Usage plans and with auth enabled no compression",
			args: &TemplateConfig{
				Rule: extensionsv1beta1.IngressRule{
					IngressRuleValue: extensionsv1beta1.IngressRuleValue{
						HTTP: &extensionsv1beta1.HTTPIngressRuleValue{
							Paths: []extensionsv1beta1.HTTPIngressPath{
								{
									Path: "/api/v1/foobar",
									Backend: extensionsv1beta1.IngressBackend{
										ServiceName: "foobar-service",
										ServicePort: intstr.FromInt(8080),
									},
								},
							},
						},
					},
				},
				Network: &network.Network{
					Vpc: &ec2.Vpc{
						VpcId:     aws.String("foo"),
						CidrBlock: aws.String("10.0.0.0/24"),
					},
					InstanceIDs:      []string{"i-foo"},
					SubnetIDs:        []string{"sn-foo"},
					SecurityGroupIDs: []string{"sg-foo"},
				},
				StageName:         "baz",
				NodePort:          30123,
				RequestTimeout:    10000,
				TLSPolicy:         "TLS_1_2",
				UsagePlans:        getUsagePlans(),
				AWSAPIDefinitions: getAPIDefsWOUsagePlans(),
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"RestAPIEmptyModel0":        buildAWSApiGatewayEmptyModel(0),
					"RestAPIEmptyModel1":        buildAWSApiGatewayEmptyModel(1),
					"RestAPIEmptyModel2":        buildAWSApiGatewayEmptyModel(2),
					"RestAPIEmptyModel3":        buildAWSApiGatewayEmptyModel(3),
					"LambdaInvokeRole":          buildLambdaExecutionRole(),
					"Methodapi0":                buildAWSApiGatewayMethod("Resourceapi0", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 0, getAuthDefCognitoPointer(), 0, true, nil),
					"Methodapiv10":              buildAWSApiGatewayMethod("Resourceapiv10", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 0, getAuthDefCognitoPointer(), 0, true, nil),
					"Methodapiv1foobar0":        buildAWSApiGatewayMethod("Resourceapiv1foobar0", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 0, getAuthDefCognitoPointer(), 0, true, nil),
					"Methodapiv1foobarproxy0":   buildAWSApiGatewayMethod("Resourceapiv1foobarproxy0", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 0, getAuthDefCognitoPointer(), 0, true, nil),
					"Methodapi1":                buildAWSApiGatewayMethod("Resourceapi1", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 1, getAuthDefCognitoPointer(), 0, false, nil),
					"Methodapiv11":              buildAWSApiGatewayMethod("Resourceapiv11", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 1, getAuthDefCognitoPointer(), 0, false, nil),
					"Methodapiv1foobar1":        buildAWSApiGatewayMethod("Resourceapiv1foobar1", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 1, getAuthDefCognitoPointer(), 0, false, nil),
					"Methodapiv1foobarproxy1":   buildAWSApiGatewayMethod("Resourceapiv1foobarproxy1", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 1, getAuthDefCognitoPointer(), 0, false, nil),
					"Methodapi2":                buildAWSApiGatewayMethod("Resourceapi2", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 2, getAuthDefCognitoPointer(), 0, false, nil),
					"Methodapiv12":              buildAWSApiGatewayMethod("Resourceapiv12", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 2, getAuthDefCognitoPointer(), 0, false, nil),
					"Methodapiv1foobar2":        buildAWSApiGatewayMethod("Resourceapiv1foobar2", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 2, getAuthDefCognitoPointer(), 0, false, nil),
					"Methodapiv1foobarproxy2":   buildAWSApiGatewayMethod("Resourceapiv1foobarproxy2", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 2, getAuthDefCognitoPointer(), 0, false, nil),
					"Methodapi3":                buildAWSApiGatewayMethod("Resourceapi3", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 3, getAuthDefCognitoPointer(), 0, false, nil),
					"Methodapiv13":              buildAWSApiGatewayMethod("Resourceapiv13", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 3, getAuthDefCognitoPointer(), 0, false, nil),
					"Methodapiv1foobar3":        buildAWSApiGatewayMethod("Resourceapiv1foobar3", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 3, getAuthDefCognitoPointer(), 0, false, nil),
					"Methodapiv1foobarproxy3":   buildAWSApiGatewayMethod("Resourceapiv1foobarproxy3", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE", "ANY", APIResource{}, 3, getAuthDefCognitoPointer(), 0, false, nil),
					"Resourceapi0":              buildAWSApiGatewayResource(cfn.GetAtt("RestAPI0", "RootResourceId"), "api", 0),
					"Resourceapi1":              buildAWSApiGatewayResource(cfn.GetAtt("RestAPI1", "RootResourceId"), "api", 1),
					"Resourceapi2":              buildAWSApiGatewayResource(cfn.GetAtt("RestAPI2", "RootResourceId"), "api", 2),
					"Resourceapi3":              buildAWSApiGatewayResource(cfn.GetAtt("RestAPI3", "RootResourceId"), "api", 3),
					"Resourceapiv10":            buildAWSApiGatewayResource(cfn.Ref("Resourceapi0"), "v1", 0),
					"Resourceapiv1foobar0":      buildAWSApiGatewayResource(cfn.Ref("Resourceapiv10"), "foobar", 0),
					"Resourceapiv1foobarproxy0": buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar0"), "{proxy+}", 0),
					"Resourceapiv11":            buildAWSApiGatewayResource(cfn.Ref("Resourceapi1"), "v1", 1),
					"Resourceapiv1foobar1":      buildAWSApiGatewayResource(cfn.Ref("Resourceapiv11"), "foobar", 1),
					"Resourceapiv1foobarproxy1": buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar1"), "{proxy+}", 1),
					"Resourceapiv12":            buildAWSApiGatewayResource(cfn.Ref("Resourceapi2"), "v1", 2),
					"Resourceapiv1foobar2":      buildAWSApiGatewayResource(cfn.Ref("Resourceapiv12"), "foobar", 2),
					"Resourceapiv1foobarproxy2": buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar2"), "{proxy+}", 2),
					"Resourceapiv13":            buildAWSApiGatewayResource(cfn.Ref("Resourceapi3"), "v1", 3),
					"Resourceapiv1foobar3":      buildAWSApiGatewayResource(cfn.Ref("Resourceapiv13"), "foobar", 3),
					"Resourceapiv1foobarproxy3": buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar3"), "{proxy+}", 3),
					"TargetGroup":               buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":                  buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":     buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI0":                  buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "NONE", 0, "api1", nil),
					"RestAPI1":                  buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "NONE", 0, "api2", nil),
					"RestAPI2":                  buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "NONE", 0, "api3", []string{"foo/bar"}),
					"RestAPI3":                  buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "NONE", 0, "api4", []string{"foo/bar"}),
					"Deployment0":               buildAWSApiGatewayDeployment("baz", []string{"Methodapi0", "Methodapiv10", "Methodapiv1foobar0", "Methodapiv1foobarproxy0"}, false, nil, "", "", 0),
					"Deployment1":               buildAWSApiGatewayDeployment("baz", []string{"Methodapi1", "Methodapiv11", "Methodapiv1foobar1", "Methodapiv1foobarproxy1"}, false, nil, "", "", 1),
					"Deployment2":               buildAWSApiGatewayDeployment("baz", []string{"Methodapi2", "Methodapiv12", "Methodapiv1foobar2", "Methodapiv1foobarproxy2"}, false, nil, "", "", 2),
					"Deployment3":               buildAWSApiGatewayDeployment("baz", []string{"Methodapi3", "Methodapiv13", "Methodapiv1foobar3", "Methodapiv1foobarproxy3"}, false, nil, "", "", 3),
					"LoadBalancer":              buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                   buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
					"APIKeyUsagePlan000":        getAPIKeyMappingBuild(0, 0, 0),
					"APIKeyUsagePlan010":        getAPIKeyMappingBuild(1, 0, 0),
					"UsagePlan00":               buildGlobalUsagePlan(getUsagePlan(), "baz", 0, nil, 4),
					"APIKey000":                 getAPIKeyBuild(0),
					"APIKey010":                 getAPIKeyBuild(1),
					"RestAPIAuthorizer00":       buildAuthorizer(getAuthDefCognito(), 0),
					"RestAPIAuthorizer01":       buildAuthorizer(getAuthDefToken(), 0),
					"RestAPIAuthorizer02":       buildAuthorizer(getAuthDefRequest(), 0),
					"RestAPIAuthorizer10":       buildAuthorizer(getAuthDefCognito(), 1),
					"RestAPIAuthorizer11":       buildAuthorizer(getAuthDefToken(), 1),
					"RestAPIAuthorizer12":       buildAuthorizer(getAuthDefRequest(), 1),
					"RestAPIAuthorizer20":       buildAuthorizer(getAuthDefCognito(), 2),
					"RestAPIAuthorizer21":       buildAuthorizer(getAuthDefToken(), 2),
					"RestAPIAuthorizer22":       buildAuthorizer(getAuthDefRequest(), 2),
				},
				Outputs: map[string]interface{}{
					"RestAPIID0":             Output{Value: cfn.Ref("RestAPI0")},
					"RestAPIID1":             Output{Value: cfn.Ref("RestAPI1")},
					"RestAPIID2":             Output{Value: cfn.Ref("RestAPI2")},
					"RestAPIID3":             Output{Value: cfn.Ref("RestAPI3")},
					"APIGatewayEndpoint0":    Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI0"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"APIGatewayEndpoint1":    Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI1"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"APIGatewayEndpoint2":    Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI2"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"APIGatewayEndpoint3":    Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI3"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"APIGWEndpointType":      Output{Value: "EDGE"},
					"RequestTimeout":         Output{Value: "10000"},
					"MinimumCompressionSize": Output{Value: "1000000000"},
					"UsagePlansData":         Output{Value: getUsagePlanBytes()},
					"AWSAPIConfigs":          Output{Value: getAWSAPIDefWOUsagePlansBytes()},
					"IngressRules":           Output{Value: getIngressRulesJsonStr()},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildAPIGatewayTemplateFromIngressRule(tt.args)
			// printed := false
			for k, resource := range got.Resources {
				if !reflect.DeepEqual(resource, tt.want.Resources[k]) {
					// if !printed {
					// 	gotYaml, _ := got.YAML()
					// 	wantYaml, _ := tt.want.YAML()
					// 	t.Errorf("Got Resources.%s = %v, want %v", k, string(gotYaml), string(wantYaml))
					// 	printed = true
					// }
					t.Errorf("Got Resources.%s = %v, want %v", k, got.Resources, tt.want.Resources)
				}
			}
			for k, resource := range got.Outputs {
				if !reflect.DeepEqual(resource, tt.want.Outputs[k]) {
					t.Errorf("Got Outputs.%s = %v, want %v", k, got.Outputs, tt.want.Outputs)
				}
			}
		})
	}
}

func TestBuildApiGatewayTemplateForRoute53(t *testing.T) {
	tests := []struct {
		name string
		args *Route53TemplateConfig
		want *cfn.Template
	}{
		{
			name: "generates template for edge hosted zone",
			args: &Route53TemplateConfig{
				CustomDomainName:         "example.com",
				CustomDomainHostName:     "d-example.aws.com",
				CustomDomainHostedZoneID: "123234",
				HostedZoneName:           "example.com",
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"LambdaInvokeRole": buildLambdaExecutionRole(),
					"Route53RecordSet": buildCustomDomainRoute53Record("example.com", "example.com", "d-example.aws.com", "123234"),
				},
				Outputs: map[string]interface{}{
					"CustomDomainHostname":     Output{Value: "d-example.aws.com"},
					"CustomDomainHostedZoneID": Output{Value: "123234"},
					"CustomDomainName":         Output{Value: "example.com"},
					"HostedZone":               Output{Value: "example.com"},
				},
			},
		},
		{
			name: "generates template for regional hosted zone",
			args: &Route53TemplateConfig{
				CustomDomainName:         "example.com",
				CustomDomainHostName:     "d-example.aws.com",
				CustomDomainHostedZoneID: "123234",
				HostedZoneName:           "example.com",
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"LambdaInvokeRole": buildLambdaExecutionRole(),
					"Route53RecordSet": buildCustomDomainRoute53Record("example.com", "example.com", "d-example.aws.com", "123234"),
				},
				Outputs: map[string]interface{}{
					"CustomDomainHostname":     Output{Value: "d-example.aws.com"},
					"CustomDomainHostedZoneID": Output{Value: "123234"},
					"CustomDomainName":         Output{Value: "example.com"},
					"HostedZone":               Output{Value: "example.com"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildAPIGatewayRoute53Template(tt.args)
			for k, resource := range got.Resources {
				if !reflect.DeepEqual(resource, tt.want.Resources[k]) {
					t.Errorf("Got Resources.%s = %v, want %v", k, got.Resources, tt.want.Resources)
				}
			}
			for k, resource := range got.Outputs {
				if !reflect.DeepEqual(resource, tt.want.Outputs[k]) {
					t.Errorf("Got Outputs.%s = %v, want %v", k, got.Outputs, tt.want.Outputs)
				}
			}
		})
	}
}
