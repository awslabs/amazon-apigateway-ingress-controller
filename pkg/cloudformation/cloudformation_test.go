package cloudformation

import (
	"encoding/json"
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
	}
}

func getUsagePlanBytes() string {
	usagePlan := getUsagePlans()
	usagePlanBytes, _ := json.Marshal(usagePlan)
	return string(usagePlanBytes)
}

func getAPIKeyMappingBuild(i int, k int) *apigateway.UsagePlanKey {
	arr := buildUsagePlanAPIKeyMapping(getUsagePlan(), k)
	for k, key := range arr {
		if k == i {
			return key
		}
	}
	return nil
}

func getAPIKeyBuild(i int) *apigateway.ApiKey {
	arr := buildAPIKey(getUsagePlan())
	for k, key := range arr {
		if k == i {
			return key
		}
	}
	return nil
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
				Arns:           []string{"arn::foo"},
				StageName:      "baz",
				NodePort:       30123,
				RequestTimeout: 10000,
				TLSPolicy:      "TLS_1_2",
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"Methodapi":                buildAWSApiGatewayMethod("Resourceapi", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1":              buildAWSApiGatewayMethod("Resourceapiv1", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1foobar":        buildAWSApiGatewayMethod("Resourceapiv1foobar", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1foobarproxy":   buildAWSApiGatewayMethod("Resourceapiv1foobarproxy", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Resourceapi":              buildAWSApiGatewayResource(cfn.GetAtt("RestAPI", "RootResourceId"), "api"),
					"Resourceapiv1":            buildAWSApiGatewayResource(cfn.Ref("Resourceapi"), "v1"),
					"Resourceapiv1foobar":      buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1"), "foobar"),
					"Resourceapiv1foobarproxy": buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar"), "{proxy+}"),
					"TargetGroup":              buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":                 buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":    buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI":                  buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "AWS_IAM"),
					"Deployment":               buildAWSApiGatewayDeployment("baz", []string{"Methodapi", "Methodapiv1", "Methodapiv1foobar", "Methodapiv1foobarproxy"}),
					"LoadBalancer":             buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                  buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
				},
				Outputs: map[string]interface{}{
					"RestAPIID":          Output{Value: cfn.Ref("RestAPI")},
					"APIGatewayEndpoint": Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"ClientARNS":         Output{Value: strings.Join([]string{"arn::foo"}, ",")},
					"APIGWEndpointType":  Output{Value: "EDGE"},
					"RequestTimeout":     Output{Value: "10000"},
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
				Arns:           []string{"arn::foo"},
				StageName:      "baz",
				NodePort:       30123,
				RequestTimeout: 10000,
				TLSPolicy:      "TLS_1_2",
				UsagePlans:     getUsagePlans(),
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"Methodapi":                buildAWSApiGatewayMethod("Resourceapi", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE"),
					"Methodapiv1":              buildAWSApiGatewayMethod("Resourceapiv1", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE"),
					"Methodapiv1foobar":        buildAWSApiGatewayMethod("Resourceapiv1foobar", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE"),
					"Methodapiv1foobarproxy":   buildAWSApiGatewayMethod("Resourceapiv1foobarproxy", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "NONE"),
					"Resourceapi":              buildAWSApiGatewayResource(cfn.GetAtt("RestAPI", "RootResourceId"), "api"),
					"Resourceapiv1":            buildAWSApiGatewayResource(cfn.Ref("Resourceapi"), "v1"),
					"Resourceapiv1foobar":      buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1"), "foobar"),
					"Resourceapiv1foobarproxy": buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar"), "{proxy+}"),
					"TargetGroup":              buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":                 buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":    buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI":                  buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "NONE"),
					"Deployment":               buildAWSApiGatewayDeployment("baz", []string{"Methodapi", "Methodapiv1", "Methodapiv1foobar", "Methodapiv1foobarproxy"}),
					"LoadBalancer":             buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                  buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
					"APIKeyUsagePlan00":        getAPIKeyMappingBuild(0, 0),
					"APIKeyUsagePlan01":        getAPIKeyMappingBuild(1, 0),
					"UsagePlan0":               buildUsagePlan(getUsagePlan(), "baz"),
					"APIKey00":                 getAPIKeyBuild(0),
					"APIKey01":                 getAPIKeyBuild(1),
				},
				Outputs: map[string]interface{}{
					"RestAPIID":          Output{Value: cfn.Ref("RestAPI")},
					"APIGatewayEndpoint": Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"APIGWEndpointType":  Output{Value: "EDGE"},
					"RequestTimeout":     Output{Value: "10000"},
					"UsagePlansData":     Output{Value: getUsagePlanBytes()},
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
				Arns:           []string{"arn::foo"},
				StageName:      "baz",
				NodePort:       30123,
				WAFEnabled:     true,
				WAFRulesJSON:   "[]",
				WAFAssociation: true,
				RequestTimeout: 10000,
				TLSPolicy:      "TLS_1_2",
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"Methodapi":                buildAWSApiGatewayMethod("Resourceapi", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1":              buildAWSApiGatewayMethod("Resourceapiv1", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1foobar":        buildAWSApiGatewayMethod("Resourceapiv1foobar", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1foobarproxy":   buildAWSApiGatewayMethod("Resourceapiv1foobarproxy", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Resourceapi":              buildAWSApiGatewayResource(cfn.GetAtt("RestAPI", "RootResourceId"), "api"),
					"Resourceapiv1":            buildAWSApiGatewayResource(cfn.Ref("Resourceapi"), "v1"),
					"Resourceapiv1foobar":      buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1"), "foobar"),
					"Resourceapiv1foobarproxy": buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar"), "{proxy+}"),
					"TargetGroup":              buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":                 buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":    buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI":                  buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "AWS_IAM"),
					"Deployment":               buildAWSApiGatewayDeployment("baz", []string{"Methodapi", "Methodapiv1", "Methodapiv1foobar", "Methodapiv1foobarproxy"}),
					"LoadBalancer":             buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                  buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
					"WAFAcl":                   buildAWSWAFWebACL("REGIONAL", "[]"),
					"WAFAssociation":           buildAWSWAFWebACLAssociation("baz"),
				},
				Outputs: map[string]interface{}{
					"RestAPIID":          Output{Value: cfn.Ref("RestAPI")},
					"APIGatewayEndpoint": Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"ClientARNS":         Output{Value: strings.Join([]string{"arn::foo"}, ",")},
					"APIGWEndpointType":  Output{Value: "EDGE"},
					"WAFEnabled":         Output{Value: "true"},
					"WAFRules":           Output{Value: "[]"},
					"WAFScope":           Output{Value: "REGIONAL"},
					"WAFAssociation":     Output{Value: cfn.Ref("WAFAssociation")},
					"RequestTimeout":     Output{Value: "10000"},
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
				Arns:            []string{"arn::foo"},
				StageName:       "baz",
				NodePort:        30123,
				WAFEnabled:      true,
				WAFRulesJSON:    "[]",
				WAFAssociation:  true,
				APIEndpointType: "REGIONAL",
				RequestTimeout:  10000,
				TLSPolicy:       "TLS_1_2",
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"Methodapi":                buildAWSApiGatewayMethod("Resourceapi", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1":              buildAWSApiGatewayMethod("Resourceapiv1", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1foobar":        buildAWSApiGatewayMethod("Resourceapiv1foobar", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1foobarproxy":   buildAWSApiGatewayMethod("Resourceapiv1foobarproxy", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Resourceapi":              buildAWSApiGatewayResource(cfn.GetAtt("RestAPI", "RootResourceId"), "api"),
					"Resourceapiv1":            buildAWSApiGatewayResource(cfn.Ref("Resourceapi"), "v1"),
					"Resourceapiv1foobar":      buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1"), "foobar"),
					"Resourceapiv1foobarproxy": buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar"), "{proxy+}"),
					"TargetGroup":              buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":                 buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":    buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI":                  buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "REGIONAL", "AWS_IAM"),
					"Deployment":               buildAWSApiGatewayDeployment("baz", []string{"Methodapi", "Methodapiv1", "Methodapiv1foobar", "Methodapiv1foobarproxy"}),
					"LoadBalancer":             buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                  buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
					"WAFAcl":                   buildAWSWAFWebACL("REGIONAL", "[]"),
					"WAFAssociation":           buildAWSWAFWebACLAssociation("baz"),
				},
				Outputs: map[string]interface{}{
					"RestAPIID":          Output{Value: cfn.Ref("RestAPI")},
					"APIGatewayEndpoint": Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"ClientARNS":         Output{Value: strings.Join([]string{"arn::foo"}, ",")},
					"APIGWEndpointType":  Output{Value: "REGIONAL"},
					"WAFEnabled":         Output{Value: "true"},
					"WAFRules":           Output{Value: "[]"},
					"WAFScope":           Output{Value: "REGIONAL"},
					"WAFAssociation":     Output{Value: cfn.Ref("WAFAssociation")},
					"RequestTimeout":     Output{Value: "10000"},
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
				Arns:           []string{"arn::foo"},
				StageName:      "baz",
				NodePort:       30123,
				WAFAssociation: true,
				WAFEnabled:     true,
				RequestTimeout: 10000,
				TLSPolicy:      "TLS_1_2",
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"Methodapi":                buildAWSApiGatewayMethod("Resourceapi", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1":              buildAWSApiGatewayMethod("Resourceapiv1", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1foobar":        buildAWSApiGatewayMethod("Resourceapiv1foobar", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1foobarproxy":   buildAWSApiGatewayMethod("Resourceapiv1foobarproxy", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Resourceapi":              buildAWSApiGatewayResource(cfn.GetAtt("RestAPI", "RootResourceId"), "api"),
					"Resourceapiv1":            buildAWSApiGatewayResource(cfn.Ref("Resourceapi"), "v1"),
					"Resourceapiv1foobar":      buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1"), "foobar"),
					"Resourceapiv1foobarproxy": buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar"), "{proxy+}"),
					"TargetGroup":              buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":                 buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":    buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI":                  buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "AWS_IAM"),
					"Deployment":               buildAWSApiGatewayDeployment("baz", []string{"Methodapi", "Methodapiv1", "Methodapiv1foobar", "Methodapiv1foobarproxy"}),
					"LoadBalancer":             buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                  buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
					"WAFAcl":                   buildAWSWAFWebACL("REGIONAL", ""),
					"WAFAssociation":           buildAWSWAFWebACLAssociation("baz"),
				},
				Outputs: map[string]interface{}{
					"RestAPIID":          Output{Value: cfn.Ref("RestAPI")},
					"APIGatewayEndpoint": Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"ClientARNS":         Output{Value: strings.Join([]string{"arn::foo"}, ",")},
					"APIGWEndpointType":  Output{Value: "EDGE"},
					"WAFEnabled":         Output{Value: "true"},
					"WAFRules":           Output{Value: ""},
					"WAFScope":           Output{Value: "REGIONAL"},
					"WAFAssociation":     Output{Value: cfn.Ref("WAFAssociation")},
					"RequestTimeout":     Output{Value: "10000"},
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
				Arns:           []string{"arn::foo"},
				StageName:      "baz",
				NodePort:       30123,
				WAFEnabled:     true,
				WAFRulesJSON:   "wrongjson",
				WAFAssociation: true,
				RequestTimeout: 10000,
				TLSPolicy:      "TLS_1_2",
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"Methodapi":                buildAWSApiGatewayMethod("Resourceapi", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1":              buildAWSApiGatewayMethod("Resourceapiv1", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1foobar":        buildAWSApiGatewayMethod("Resourceapiv1foobar", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1foobarproxy":   buildAWSApiGatewayMethod("Resourceapiv1foobarproxy", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Resourceapi":              buildAWSApiGatewayResource(cfn.GetAtt("RestAPI", "RootResourceId"), "api"),
					"Resourceapiv1":            buildAWSApiGatewayResource(cfn.Ref("Resourceapi"), "v1"),
					"Resourceapiv1foobar":      buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1"), "foobar"),
					"Resourceapiv1foobarproxy": buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar"), "{proxy+}"),
					"TargetGroup":              buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":                 buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":    buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI":                  buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "AWS_IAM"),
					"Deployment":               buildAWSApiGatewayDeployment("baz", []string{"Methodapi", "Methodapiv1", "Methodapiv1foobar", "Methodapiv1foobarproxy"}),
					"LoadBalancer":             buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                  buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
					"WAFAcl":                   buildAWSWAFWebACL("REGIONAL", ""),
					"WAFAssociation":           buildAWSWAFWebACLAssociation("baz"),
				},
				Outputs: map[string]interface{}{
					"RestAPIID":          Output{Value: cfn.Ref("RestAPI")},
					"APIGatewayEndpoint": Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"ClientARNS":         Output{Value: strings.Join([]string{"arn::foo"}, ",")},
					"APIGWEndpointType":  Output{Value: "EDGE"},
					"WAFEnabled":         Output{Value: "true"},
					"WAFRules":           Output{Value: "wrongjson"},
					"WAFScope":           Output{Value: "REGIONAL"},
					"WAFAssociation":     Output{Value: cfn.Ref("WAFAssociation")},
					"RequestTimeout":     Output{Value: "10000"},
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
				Arns:             []string{"arn::foo"},
				StageName:        "baz",
				NodePort:         30123,
				CustomDomainName: "example.com",
				CertificateArn:   "arn::foobar",
				RequestTimeout:   10000,
				TLSPolicy:        "TLS_1_2",
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"Methodapi":                   buildAWSApiGatewayMethod("Resourceapi", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1":                 buildAWSApiGatewayMethod("Resourceapiv1", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1foobar":           buildAWSApiGatewayMethod("Resourceapiv1foobar", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1foobarproxy":      buildAWSApiGatewayMethod("Resourceapiv1foobarproxy", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Resourceapi":                 buildAWSApiGatewayResource(cfn.GetAtt("RestAPI", "RootResourceId"), "api"),
					"Resourceapiv1":               buildAWSApiGatewayResource(cfn.Ref("Resourceapi"), "v1"),
					"Resourceapiv1foobar":         buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1"), "foobar"),
					"Resourceapiv1foobarproxy":    buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar"), "{proxy+}"),
					"TargetGroup":                 buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":                    buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":       buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI":                     buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "AWS_IAM"),
					"Deployment":                  buildAWSApiGatewayDeployment("baz", []string{"Methodapi", "Methodapiv1", "Methodapiv1foobar", "Methodapiv1foobarproxy"}),
					"LoadBalancer":                buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                     buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
					"CustomDomain":                buildCustomDomain("example.com", "arn::foobar", "EDGE", "TLS_1_2"),
					"CustomDomainBasePathMapping": buildCustomDomainBasePathMapping("example.com", "baz"),
				},
				Outputs: map[string]interface{}{
					"RestAPIID":                Output{Value: cfn.Ref("RestAPI")},
					"APIGatewayEndpoint":       Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"ClientARNS":               Output{Value: strings.Join([]string{"arn::foo"}, ",")},
					"APIGWEndpointType":        Output{Value: "EDGE"},
					"SSLCertArn":               Output{Value: "arn::foobar"},
					"CustomDomainName":         Output{Value: "example.com"},
					"CustomDomainHostname":     Output{Value: cfn.GetAtt("CustomDomain", "DistributionDomainName")},
					"CustomDomainHostedZoneID": Output{Value: cfn.GetAtt("CustomDomain", "DistributionHostedZoneId")},
					"RequestTimeout":           Output{Value: "10000"},
					"TLSPolicy":                Output{Value: "TLS_1_2"},
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
				Arns:             []string{"arn::foo"},
				StageName:        "baz",
				NodePort:         30123,
				CustomDomainName: "example.com",
				CertificateArn:   "arn::foobar",
				APIEndpointType:  "REGIONAL",
				TLSPolicy:        "TLS_1_2",
				RequestTimeout:   10000,
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"Methodapi":                   buildAWSApiGatewayMethod("Resourceapi", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1":                 buildAWSApiGatewayMethod("Resourceapiv1", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1foobar":           buildAWSApiGatewayMethod("Resourceapiv1foobar", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1foobarproxy":      buildAWSApiGatewayMethod("Resourceapiv1foobarproxy", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Resourceapi":                 buildAWSApiGatewayResource(cfn.GetAtt("RestAPI", "RootResourceId"), "api"),
					"Resourceapiv1":               buildAWSApiGatewayResource(cfn.Ref("Resourceapi"), "v1"),
					"Resourceapiv1foobar":         buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1"), "foobar"),
					"Resourceapiv1foobarproxy":    buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar"), "{proxy+}"),
					"TargetGroup":                 buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":                    buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":       buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI":                     buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "REGIONAL", "AWS_IAM"),
					"Deployment":                  buildAWSApiGatewayDeployment("baz", []string{"Methodapi", "Methodapiv1", "Methodapiv1foobar", "Methodapiv1foobarproxy"}),
					"LoadBalancer":                buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                     buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
					"CustomDomain":                buildCustomDomain("example.com", "arn::foobar", "REGIONAL", "TLS_1_2"),
					"CustomDomainBasePathMapping": buildCustomDomainBasePathMapping("example.com", "baz"),
				},
				Outputs: map[string]interface{}{
					"RestAPIID":                Output{Value: cfn.Ref("RestAPI")},
					"APIGatewayEndpoint":       Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"ClientARNS":               Output{Value: strings.Join([]string{"arn::foo"}, ",")},
					"APIGWEndpointType":        Output{Value: "REGIONAL"},
					"SSLCertArn":               Output{Value: "arn::foobar"},
					"CustomDomainName":         Output{Value: "example.com"},
					"CustomDomainHostname":     Output{Value: cfn.GetAtt("CustomDomain", "RegionalDomainName")},
					"CustomDomainHostedZoneID": Output{Value: cfn.GetAtt("CustomDomain", "RegionalHostedZoneId")},
					"RequestTimeout":           Output{Value: "10000"},
					"TLSPolicy":                Output{Value: "TLS_1_2"},
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
				Arns:             []string{"arn::foo"},
				StageName:        "baz",
				NodePort:         30123,
				CustomDomainName: "example.com",
				CertificateArn:   "arn::foobar",
				WAFEnabled:       true,
				WAFRulesJSON:     "[]",
				WAFAssociation:   true,
				RequestTimeout:   10000,
				TLSPolicy:        "TLS_1_2",
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"Methodapi":                   buildAWSApiGatewayMethod("Resourceapi", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1":                 buildAWSApiGatewayMethod("Resourceapiv1", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1foobar":           buildAWSApiGatewayMethod("Resourceapiv1foobar", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1foobarproxy":      buildAWSApiGatewayMethod("Resourceapiv1foobarproxy", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Resourceapi":                 buildAWSApiGatewayResource(cfn.GetAtt("RestAPI", "RootResourceId"), "api"),
					"Resourceapiv1":               buildAWSApiGatewayResource(cfn.Ref("Resourceapi"), "v1"),
					"Resourceapiv1foobar":         buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1"), "foobar"),
					"Resourceapiv1foobarproxy":    buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar"), "{proxy+}"),
					"TargetGroup":                 buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":                    buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":       buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI":                     buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "AWS_IAM"),
					"Deployment":                  buildAWSApiGatewayDeployment("baz", []string{"Methodapi", "Methodapiv1", "Methodapiv1foobar", "Methodapiv1foobarproxy"}),
					"LoadBalancer":                buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                     buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
					"CustomDomain":                buildCustomDomain("example.com", "arn::foobar", "EDGE", "TLS_1_2"),
					"CustomDomainBasePathMapping": buildCustomDomainBasePathMapping("example.com", "baz"),
					"WAFAcl":                      buildAWSWAFWebACL("REGIONAL", "[]"),
					"WAFAssociation":              buildAWSWAFWebACLAssociation("baz"),
				},
				Outputs: map[string]interface{}{
					"RestAPIID":                Output{Value: cfn.Ref("RestAPI")},
					"APIGatewayEndpoint":       Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"ClientARNS":               Output{Value: strings.Join([]string{"arn::foo"}, ",")},
					"APIGWEndpointType":        Output{Value: "EDGE"},
					"SSLCertArn":               Output{Value: "arn::foobar"},
					"CustomDomainName":         Output{Value: "example.com"},
					"CustomDomainHostname":     Output{Value: cfn.GetAtt("CustomDomain", "DistributionDomainName")},
					"CustomDomainHostedZoneID": Output{Value: cfn.GetAtt("CustomDomain", "DistributionHostedZoneId")},
					"WAFEnabled":               Output{Value: "true"},
					"WAFRules":                 Output{Value: "[]"},
					"WAFScope":                 Output{Value: "REGIONAL"},
					"WAFAssociation":           Output{Value: cfn.Ref("WAFAssociation")},
					"RequestTimeout":           Output{Value: "10000"},
					"TLSPolicy":                Output{Value: "TLS_1_2"},
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
				Arns:             []string{"arn::foo"},
				StageName:        "baz",
				NodePort:         30123,
				CustomDomainName: "example.com",
				CertificateArn:   "arn::foobar",
				WAFEnabled:       true,
				WAFRulesJSON:     "[]",
				WAFAssociation:   false,
				RequestTimeout:   10000,
				TLSPolicy:        "TLS_1_2",
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"Methodapi":                   buildAWSApiGatewayMethod("Resourceapi", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1":                 buildAWSApiGatewayMethod("Resourceapiv1", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1foobar":           buildAWSApiGatewayMethod("Resourceapiv1foobar", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1foobarproxy":      buildAWSApiGatewayMethod("Resourceapiv1foobarproxy", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Resourceapi":                 buildAWSApiGatewayResource(cfn.GetAtt("RestAPI", "RootResourceId"), "api"),
					"Resourceapiv1":               buildAWSApiGatewayResource(cfn.Ref("Resourceapi"), "v1"),
					"Resourceapiv1foobar":         buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1"), "foobar"),
					"Resourceapiv1foobarproxy":    buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar"), "{proxy+}"),
					"TargetGroup":                 buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":                    buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":       buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI":                     buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "EDGE", "AWS_IAM"),
					"Deployment":                  buildAWSApiGatewayDeployment("baz", []string{"Methodapi", "Methodapiv1", "Methodapiv1foobar", "Methodapiv1foobarproxy"}),
					"LoadBalancer":                buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                     buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
					"CustomDomain":                buildCustomDomain("example.com", "arn::foobar", "EDGE", "TLS_1_2"),
					"CustomDomainBasePathMapping": buildCustomDomainBasePathMapping("example.com", "baz"),
					"WAFAcl":                      buildAWSWAFWebACL("REGIONAL", "[]"),
				},
				Outputs: map[string]interface{}{
					"RestAPIID":                Output{Value: cfn.Ref("RestAPI")},
					"APIGatewayEndpoint":       Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"ClientARNS":               Output{Value: strings.Join([]string{"arn::foo"}, ",")},
					"APIGWEndpointType":        Output{Value: "EDGE"},
					"SSLCertArn":               Output{Value: "arn::foobar"},
					"CustomDomainName":         Output{Value: "example.com"},
					"CustomDomainHostname":     Output{Value: cfn.GetAtt("CustomDomain", "DistributionDomainName")},
					"CustomDomainHostedZoneID": Output{Value: cfn.GetAtt("CustomDomain", "DistributionHostedZoneId")},
					"WAFEnabled":               Output{Value: "true"},
					"WAFRules":                 Output{Value: "[]"},
					"WAFScope":                 Output{Value: "REGIONAL"},
					"WAFAssociation":           Output{Value: cfn.Ref("WAFAssociation")},
					"RequestTimeout":           Output{Value: "10000"},
					"TLSPolicy":                Output{Value: "TLS_1_2"},
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
				Arns:             []string{"arn::foo"},
				StageName:        "baz",
				NodePort:         30123,
				CustomDomainName: "example.com",
				CertificateArn:   "arn::foobar",
				APIEndpointType:  "REGIONAL",
				WAFEnabled:       true,
				WAFRulesJSON:     "[]",
				WAFAssociation:   true,
				RequestTimeout:   10000,
				TLSPolicy:        "TLS_1_2",
			},
			want: &cfn.Template{
				Resources: cfn.Resources{
					"Methodapi":                   buildAWSApiGatewayMethod("Resourceapi", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1":                 buildAWSApiGatewayMethod("Resourceapiv1", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1foobar":           buildAWSApiGatewayMethod("Resourceapiv1foobar", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Methodapiv1foobarproxy":      buildAWSApiGatewayMethod("Resourceapiv1foobarproxy", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"}), 10000, "AWS_IAM"),
					"Resourceapi":                 buildAWSApiGatewayResource(cfn.GetAtt("RestAPI", "RootResourceId"), "api"),
					"Resourceapiv1":               buildAWSApiGatewayResource(cfn.Ref("Resourceapi"), "v1"),
					"Resourceapiv1foobar":         buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1"), "foobar"),
					"Resourceapiv1foobarproxy":    buildAWSApiGatewayResource(cfn.Ref("Resourceapiv1foobar"), "{proxy+}"),
					"TargetGroup":                 buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
					"Listener":                    buildAWSElasticLoadBalancingV2Listener(),
					"SecurityGroupIngress0":       buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
					"RestAPI":                     buildAWSApiGatewayRestAPI([]string{"arn::foo"}, "REGIONAL", "AWS_IAM"),
					"Deployment":                  buildAWSApiGatewayDeployment("baz", []string{"Methodapi", "Methodapiv1", "Methodapiv1foobar", "Methodapiv1foobarproxy"}),
					"LoadBalancer":                buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
					"VPCLink":                     buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
					"CustomDomain":                buildCustomDomain("example.com", "arn::foobar", "REGIONAL", "TLS_1_2"),
					"CustomDomainBasePathMapping": buildCustomDomainBasePathMapping("example.com", "baz"),
					"WAFAcl":                      buildAWSWAFWebACL("REGIONAL", "[]"),
					"WAFAssociation":              buildAWSWAFWebACLAssociation("baz"),
				},
				Outputs: map[string]interface{}{
					"RestAPIID":                Output{Value: cfn.Ref("RestAPI")},
					"APIGatewayEndpoint":       Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
					"ClientARNS":               Output{Value: strings.Join([]string{"arn::foo"}, ",")},
					"APIGWEndpointType":        Output{Value: "REGIONAL"},
					"SSLCertArn":               Output{Value: "arn::foobar"},
					"CustomDomainName":         Output{Value: "example.com"},
					"CustomDomainHostname":     Output{Value: cfn.GetAtt("CustomDomain", "RegionalDomainName")},
					"CustomDomainHostedZoneID": Output{Value: cfn.GetAtt("CustomDomain", "RegionalHostedZoneId")},
					"WAFEnabled":               Output{Value: "true"},
					"WAFRules":                 Output{Value: "[]"},
					"WAFScope":                 Output{Value: "REGIONAL"},
					"WAFAssociation":           Output{Value: cfn.Ref("WAFAssociation")},
					"RequestTimeout":           Output{Value: "10000"},
					"TLSPolicy":                Output{Value: "TLS_1_2"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildAPIGatewayTemplateFromIngressRule(tt.args)
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
