package cloudformation

import (
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/awslabs/amazon-apigateway-ingress-controller/pkg/network"
	"github.com/awslabs/goformation/cloudformation"
	cfn "github.com/awslabs/goformation/cloudformation"
	extensionsv1beta1 "k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestBuildApiGatewayTemplateFromIngressRule(t *testing.T) {
	type want struct {
		template *cloudformation.Template
		wantErr  bool
	}
	tests := []struct {
		name string
		args *TemplateConfig
		want want
	}{
		{
			name: "generates template if config is valid",
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
				Arns:      []string{"arn::foo"},
				StageName: "baz",
				NodePort:  30123,
			},
			want: want{
				template: &cloudformation.Template{
					Resources: cloudformation.Resources{
						"Methodapi":                buildAWSApiGatewayMethod("Resourceapi", toPath(1, []string{"", "api", "v1", "foobar", "{proxy+}"})),
						"Methodapiv1":              buildAWSApiGatewayMethod("Resourceapiv1", toPath(2, []string{"", "api", "v1", "foobar", "{proxy+}"})),
						"Methodapiv1foobar":        buildAWSApiGatewayMethod("Resourceapiv1foobar", toPath(3, []string{"", "api", "v1", "foobar", "{proxy+}"})),
						"Methodapiv1foobarproxy":   buildAWSApiGatewayMethod("Resourceapiv1foobarproxy", toPath(4, []string{"", "api", "v1", "foobar", "{proxy+}"})),
						"Resourceapi":              buildAWSApiGatewayResource(cloudformation.GetAtt("RestAPI", "RootResourceId"), "api"),
						"Resourceapiv1":            buildAWSApiGatewayResource(cloudformation.Ref("Resourceapi"), "v1"),
						"Resourceapiv1foobar":      buildAWSApiGatewayResource(cloudformation.Ref("Resourceapiv1"), "foobar"),
						"Resourceapiv1foobarproxy": buildAWSApiGatewayResource(cloudformation.Ref("Resourceapiv1foobar"), "{proxy+}"),
						"TargetGroup":              buildAWSElasticLoadBalancingV2TargetGroup("foo", []string{"i-foo"}, 30123, []string{"LoadBalancer"}),
						"Listener":                 buildAWSElasticLoadBalancingV2Listener(),
						"SecurityGroupIngress0":    buildAWSEC2SecurityGroupIngresses([]string{"sg-foo"}, "10.0.0.0/24", 30123)[0],
						"RestAPI":                  buildAWSApiGatewayRestAPI([]string{"arn::foo"}),
						"Deployment":               buildAWSApiGatewayDeployment("baz", []string{"Methodapi", "Methodapiv1", "Methodapiv1foobar", "Methodapiv1foobarproxy"}),
						"LoadBalancer":             buildAWSElasticLoadBalancingV2LoadBalancer([]string{"sn-foo"}),
						"VPCLink":                  buildAWSApiGatewayVpcLink([]string{"LoadBalancer"}),
					},
					Outputs: map[string]interface{}{
						"RestApiId":          Output{Value: cloudformation.Ref("RestAPI")},
						"APIGatewayEndpoint": Output{Value: cloudformation.Join("", []string{"https://", cloudformation.Ref("RestAPI"), ".execute-api.", cfn.Ref("AWS::Region"), ".amazonaws.com/", "baz"})},
						"ClientARNS":         Output{Value: strings.Join([]string{"arn::foo"}, ",")},
					},
				},
				wantErr: false,
			},
		},
		{
			name: "returns error if template config is invalid",
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
				CustomDomainName: "foobar",
			},
			want: want{
				template: &cloudformation.Template{Resources: map[string]cloudformation.Resource{}},
				wantErr:  true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BuildApiGatewayTemplateFromIngressRule(tt.args)

			for k, resource := range got.Resources {
				if !reflect.DeepEqual(resource, tt.want.template.Resources[k]) {
					t.Errorf("Got Resources.%s = %v, want %v", k, got, tt.want)
				}
			}

			if tt.want.wantErr == (err == nil) {
				t.Errorf("Got err = %v, want %v", err, tt.want.wantErr)
			}

		})
	}
}
