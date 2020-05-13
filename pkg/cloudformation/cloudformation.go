package cloudformation

import (
	"fmt"
	"sort"
	"strings"

	"github.com/awslabs/amazon-apigateway-ingress-controller/pkg/network"
	cfn "github.com/awslabs/goformation/v4/cloudformation"
	"github.com/awslabs/goformation/v4/cloudformation/apigateway"
	"github.com/awslabs/goformation/v4/cloudformation/ec2"
	"github.com/awslabs/goformation/v4/cloudformation/elasticloadbalancingv2"
	"github.com/awslabs/goformation/v4/cloudformation/tags"
	"github.com/awslabs/goformation/v4/cloudformation/wafv2"

	extensionsv1beta1 "k8s.io/api/extensions/v1beta1"
)

const (
	OutputKeyRestApiID          = "RestAPIID"
	OutputKeyAPIGatewayEndpoint = "APIGatewayEndpoint"
	OutputKeyClientARNS         = "ClientARNS"
)

func toLogicalName(idx int, parts []string) string {
	s := strings.Join(parts[:idx+1], "")
	remove := []string{"{", "}", "+"}
	for _, char := range remove {
		s = strings.Replace(s, char, "", -1)
	}
	return s
}

func toPath(idx int, parts []string) string {
	if parts[idx] == "{proxy+}" {
		return strings.Join(parts[:idx], "/") + "/{proxy}"
	}
	return strings.Join(parts[:idx+1], "/")
}

func mapApiGatewayMethodsAndResourcesFromPaths(paths []extensionsv1beta1.HTTPIngressPath) map[string]cfn.Resource {
	m := map[string]cfn.Resource{}

	for _, path := range paths {
		parts := strings.Split(path.Path, "/")
		parts = append(parts, "{proxy+}")
		for idx, part := range parts {
			if idx == 0 {
				continue
			}
			ref := cfn.GetAtt("RestAPI", "RootResourceId")
			if idx > 1 {
				ref = cfn.Ref(fmt.Sprintf("Resource%s", toLogicalName(idx-1, parts)))
			}

			resourceLogicalName := fmt.Sprintf("Resource%s", toLogicalName(idx, parts))
			m[resourceLogicalName] = buildAWSApiGatewayResource(ref, part)
			m[fmt.Sprintf("Method%s", toLogicalName(idx, parts))] = buildAWSApiGatewayMethod(resourceLogicalName, toPath(idx, parts))
		}
	}

	return m
}

func buildAWSApiGatewayResource(ref, part string) *apigateway.Resource {
	return &apigateway.Resource{
		ParentId:  ref,
		PathPart:  part,
		RestApiId: cfn.Ref("RestAPI"),
	}
}

func buildAWSApiGatewayRestAPI(arns []string, apiEPTypes string) *apigateway.RestApi {
	return &apigateway.RestApi{
		ApiKeySourceType: "HEADER",
		EndpointConfiguration: &apigateway.RestApi_EndpointConfiguration{
			Types: []string{apiEPTypes},
		},
		Name: cfn.Ref("AWS::StackName"),
		Policy: &PolicyDocument{
			Version: "2012-10-17",
			Statement: []Statement{
				{
					Action:    []string{"execute-api:Invoke"},
					Effect:    "Allow",
					Principal: map[string][]string{"AWS": arns},
					Resource:  []string{"*"},
				},
			},
		},
	}
}

func buildAWSWAFWebACLAssociation() *wafv2.WebACLAssociation {
	return &wafv2.WebACLAssociation{
		WebACLArn:   cfn.GetAtt("APIGWWebACL", "Arn"),
		ResourceArn: cfn.Ref("RestAPI"),
	}
}

func buildAWSApiGatewayDeployment(stageName string, dependsOn []string) *apigateway.Deployment {
	d := &apigateway.Deployment{
		RestApiId: cfn.Ref("RestAPI"),
		StageName: stageName,
	}

	// Since we construct a map of in `mapApiGatewayMethodsAndResourcesFromPaths` we can't determine the order
	// that this list will be in - making it difficult to test - the order isn't important - but passing tests are.
	// This isn't the worst thing in the world - and - I considered refactoring - but I like how simple this is for now.
	// Also the order doesn't matter to CFN in the end.
	sort.Strings(dependsOn)
	d.AWSCloudFormationDependsOn = dependsOn

	return d
}

func buildAWSElasticLoadBalancingV2Listener() *elasticloadbalancingv2.Listener {
	return &elasticloadbalancingv2.Listener{
		LoadBalancerArn: cfn.Ref("LoadBalancer"),
		Protocol:        "TCP",
		Port:            80,
		DefaultActions: []elasticloadbalancingv2.Listener_Action{
			elasticloadbalancingv2.Listener_Action{
				TargetGroupArn: cfn.Ref("TargetGroup"),
				Type:           "forward",
			},
		},
	}
}

func buildAWSElasticLoadBalancingV2LoadBalancer(subnetIDs []string) *elasticloadbalancingv2.LoadBalancer {
	return &elasticloadbalancingv2.LoadBalancer{
		IpAddressType: "ipv4",
		Scheme:        "internal",
		Subnets:       subnetIDs,
		Tags: []tags.Tag{
			{
				Key:   "com.github.amazon-apigateway-ingress-controller/stack",
				Value: cfn.Ref("AWS::StackName"),
			},
		},
		Type: "network",
	}
}

func buildAWSElasticLoadBalancingV2TargetGroup(vpcID string, instanceIDs []string, nodePort int, dependsOn []string) *elasticloadbalancingv2.TargetGroup {
	targets := make([]elasticloadbalancingv2.TargetGroup_TargetDescription, len(instanceIDs))
	for i, instanceID := range instanceIDs {
		targets[i] = elasticloadbalancingv2.TargetGroup_TargetDescription{Id: instanceID}
	}

	return &elasticloadbalancingv2.TargetGroup{
		HealthCheckIntervalSeconds: 30,
		HealthCheckPort:            "traffic-port",
		HealthCheckProtocol:        "TCP",
		HealthCheckTimeoutSeconds:  10,
		HealthyThresholdCount:      3,
		Port:                       nodePort,
		Protocol:                   "TCP",
		Tags: []tags.Tag{
			{
				Key:   "com.github.amazon-apigateway-ingress-controller/stack",
				Value: cfn.Ref("AWS::StackName"),
			},
		},
		TargetType:              "instance",
		Targets:                 targets,
		UnhealthyThresholdCount: 3,
		VpcId:                   vpcID,
	}

}

func buildAWSApiGatewayVpcLink(dependsOn []string) *apigateway.VpcLink {
	r := &apigateway.VpcLink{
		Name:       cfn.Ref("AWS::StackName"),
		TargetArns: []string{cfn.Ref("LoadBalancer")},
	}

	r.AWSCloudFormationDependsOn = dependsOn

	return r
}

func buildAWSApiGatewayMethod(resourceLogicalName, path string) *apigateway.Method {
	m := &apigateway.Method{
		RequestParameters: map[string]bool{
			"method.request.path.proxy": true,
		},
		AuthorizationType: "AWS_IAM",
		HttpMethod:        "ANY",
		ResourceId:        cfn.Ref(resourceLogicalName),
		RestApiId:         cfn.Ref("RestAPI"),
		Integration: &apigateway.Method_Integration{
			ConnectionId:          cfn.Ref("VPCLink"),
			ConnectionType:        "VPC_LINK",
			IntegrationHttpMethod: "ANY",
			PassthroughBehavior:   "WHEN_NO_MATCH",
			RequestParameters: map[string]string{
				"integration.request.path.proxy":             "method.request.path.proxy",
				"integration.request.header.Accept-Encoding": "'identity'",
			},
			Type:            "HTTP_PROXY",
			TimeoutInMillis: 29000,
			Uri:             cfn.Join("", []string{"http://", cfn.GetAtt("LoadBalancer", "DNSName"), path}),
		},
	}

	m.AWSCloudFormationDependsOn = []string{"LoadBalancer"}
	return m
}

func buildAWSEC2SecurityGroupIngresses(securityGroupIds []string, cidr string, nodePort int) []*ec2.SecurityGroupIngress {
	sgIngresses := make([]*ec2.SecurityGroupIngress, len(securityGroupIds))
	for i, sgID := range securityGroupIds {
		sgIngresses[i] = &ec2.SecurityGroupIngress{
			IpProtocol: "TCP",
			CidrIp:     cidr,
			FromPort:   nodePort,
			ToPort:     nodePort,
			GroupId:    sgID,
		}
	}

	return sgIngresses
}

func buildCustomDomain(domainName, certificateArn string) *apigateway.DomainName {
	return &apigateway.DomainName{
		CertificateArn: certificateArn,
		DomainName:     domainName,
		EndpointConfiguration: &apigateway.DomainName_EndpointConfiguration{
			Types: []string{"EDGE"},
		},
	}
}

type TemplateConfig struct {
	Network          *network.Network
	Rule             extensionsv1beta1.IngressRule
	NodePort         int
	StageName        string
	Arns             []string
	CustomDomainName string
	CertificateArn   string
	APIEndpointTypes string
}

func BuildApiGatewayTemplateFromIngressRule(cfg *TemplateConfig) *cfn.Template {
	template := cfn.NewTemplate()
	paths := cfg.Rule.IngressRuleValue.HTTP.Paths

	methodLogicalNames := []string{}
	resourceMap := mapApiGatewayMethodsAndResourcesFromPaths(paths)
	for k, resource := range resourceMap {
		if _, ok := resource.(*apigateway.Method); ok {
			methodLogicalNames = append(methodLogicalNames, k)
		}

		template.Resources[k] = resource
	}

	targetGroup := buildAWSElasticLoadBalancingV2TargetGroup(*cfg.Network.Vpc.VpcId, cfg.Network.InstanceIDs, cfg.NodePort, []string{"LoadBalancer"})
	template.Resources["TargetGroup"] = targetGroup

	listener := buildAWSElasticLoadBalancingV2Listener()
	template.Resources["Listener"] = listener

	securityGroupIngresses := buildAWSEC2SecurityGroupIngresses(cfg.Network.SecurityGroupIDs, *cfg.Network.Vpc.CidrBlock, cfg.NodePort)
	for i, sgI := range securityGroupIngresses {
		template.Resources[fmt.Sprintf("SecurityGroupIngress%d", i)] = sgI
	}

	restAPI := buildAWSApiGatewayRestAPI(cfg.Arns, cfg.APIEndpointTypes)
	template.Resources["RestAPI"] = restAPI

	deployment := buildAWSApiGatewayDeployment(cfg.StageName, methodLogicalNames)
	template.Resources["Deployment"] = deployment

	loadBalancer := buildAWSElasticLoadBalancingV2LoadBalancer(cfg.Network.SubnetIDs)
	template.Resources["LoadBalancer"] = loadBalancer

	vPCLink := buildAWSApiGatewayVpcLink([]string{"LoadBalancer"})
	template.Resources["VPCLink"] = vPCLink

	if cfg.CustomDomainName != "" && cfg.CertificateArn != "" {
		customDomain := buildCustomDomain(cfg.CustomDomainName, cfg.CertificateArn)
		template.Resources["CustomDomain"] = customDomain
	}

	template.Outputs = map[string]interface{}{
		OutputKeyRestApiID:          Output{Value: cfn.Ref("RestAPI")},
		OutputKeyAPIGatewayEndpoint: Output{Value: cfn.Join("", []string{"https://", cfn.Ref("RestAPI"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", cfg.StageName})},
		OutputKeyClientARNS:         Output{Value: strings.Join(cfg.Arns, ",")},
	}

	return template
}
