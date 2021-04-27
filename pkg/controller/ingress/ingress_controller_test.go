/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ingress

import (
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/apigateway/apigatewayiface"
	"github.com/aws/aws-sdk-go/service/autoscaling/autoscalingiface"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/cloudformation/cloudformationiface"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	controllercfn "github.com/awslabs/amazon-apigateway-ingress-controller/pkg/cloudformation"
	"github.com/awslabs/amazon-apigateway-ingress-controller/pkg/logging"
	"go.uber.org/zap"
	extensionsv1beta1 "k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestReconcileIngress_Reconcile(t *testing.T) {
	type fields struct {
		Client          client.Client
		scheme          *runtime.Scheme
		cfnSvc          cloudformationiface.CloudFormationAPI
		ec2Svc          ec2iface.EC2API
		apigatewaySvc   apigatewayiface.APIGatewayAPI
		austoscalingSvc autoscalingiface.AutoScalingAPI
		log             *zap.Logger
	}
	type args struct {
		request reconcile.Request
	}
	tests := []struct {
		name            string
		fields          fields
		args            args
		want            reconcile.Result
		wantErr         bool
		expectedIngress *extensionsv1beta1.Ingress
	}{
		{
			name: "if k8s object doesn't exist",
			fields: fields{
				Client:          fakeclient.NewFakeClient(),
				cfnSvc:          &mockCloudformation{},
				ec2Svc:          &mockEC2{},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{},
				log:             logging.New(),
			},
			args: args{
				request: reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "foo",
						Namespace: "default",
					},
				},
			},
			want:    reconcile.Result{},
			wantErr: false,
		},
		{
			name: "if ingress object doesn't have correct annotations",
			fields: fields{
				Client: fakeclient.NewFakeClient(
					&extensionsv1beta1.Ingress{
						ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: "default"},
					},
				),
				cfnSvc:          &mockCloudformation{},
				ec2Svc:          &mockEC2{},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{},
				log:             logging.New(),
			},
			args: args{
				request: reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "foo",
						Namespace: "default",
					},
				},
			},
			want:    reconcile.Result{},
			wantErr: false,
		},
		{
			name: "if delete called but no cfn stack exists",
			fields: fields{
				Client: fakeclient.NewFakeClient(newMockIngress("complete", true, true)),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{},
				},
				ec2Svc:          &mockEC2{},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{},
				log:             logging.New(),
			},
			args: args{
				request: reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "complete",
						Namespace: "default",
					},
				},
			},
			want:    reconcile.Result{},
			wantErr: false,
		},
		{
			name: "if cfn stack has status of DELETE_IN_PROGRESS - requeue request",
			fields: fields{
				Client: fakeclient.NewFakeClient(newMockIngress("deleteinprogress", true, true)),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{
						"deleteinprogress": &cloudformation.Stack{
							StackStatus: aws.String(cloudformation.StackStatusDeleteInProgress),
						},
					},
				},
				ec2Svc:          &mockEC2{},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{},
				log:             logging.New(),
			},
			args: args{
				request: reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "deleteinprogress",
						Namespace: "default",
					},
				},
			},
			want:    reconcile.Result{RequeueAfter: 5 * time.Second},
			wantErr: false,
		},
		{
			name: "if deletionTimestamp exists but finalizer does not - return and leave for garbage collecion",
			fields: fields{
				Client: fakeclient.NewFakeClient(newMockIngress("deletecomplete", true, false)),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{
						"deletecomplete": &cloudformation.Stack{
							StackStatus: aws.String(cloudformation.StackStatusDeleteComplete),
						},
					},
				},
				ec2Svc:          &mockEC2{},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{},
				log:             logging.New(),
			},
			args: args{
				request: reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "deletecomplete",
						Namespace: "default",
					},
				},
			},
			want:    reconcile.Result{},
			wantErr: false,
		},
		{
			name: "if cfn stack has DELETE_COMPLETE status - removes finalizer",
			fields: fields{
				Client: fakeclient.NewFakeClient(newMockIngress("deletecomplete", true, true)),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{
						"deletecomplete": &cloudformation.Stack{
							StackStatus: aws.String(cloudformation.StackStatusDeleteComplete),
						},
					},
				},
				ec2Svc:          &mockEC2{},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{},
				log:             logging.New(),
			},
			args: args{
				request: reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "deletecomplete",
						Namespace: "default",
					},
				},
			},
			want:    reconcile.Result{},
			wantErr: false,
		},
		{
			name: "if cfn stack deletion has not completed - then call delete and requeue",
			fields: fields{
				Client: fakeclient.NewFakeClient(newMockIngress("foobar", true, true), newMockNodeList()),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{
						"foobar": &cloudformation.Stack{
							StackStatus: aws.String(cloudformation.StackStatusCreateComplete),
						},
					},
				},
				ec2Svc:          &mockEC2{},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{},
				log:             logging.New(),
			},
			args: args{
				request: reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "foobar",
						Namespace: "default",
					},
				},
			},
			want:    reconcile.Result{Requeue: true},
			wantErr: false,
		},
		{
			name: "cfn stack deletion with asg data in instances",
			fields: fields{
				Client: fakeclient.NewFakeClient(newMockIngress("foobar", true, true), newMockNodeList()),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{
						"foobar": &cloudformation.Stack{
							StackStatus: aws.String(cloudformation.StackStatusCreateComplete),
						},
					},
				},
				ec2Svc:          &mockEC2{getASGTag: true},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{withTargetGroupARN: true},
				log:             logging.New(),
			},
			args: args{
				request: reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "foobar",
						Namespace: "default",
					},
				},
			},
			want:    reconcile.Result{Requeue: true},
			wantErr: false,
		},
		{
			name: "if cfn stack deletion fails (cfn describe stack fails)",
			fields: fields{
				Client: fakeclient.NewFakeClient(newMockIngress("broken", true, true), newMockNodeList()),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{
						"broken": &cloudformation.Stack{
							StackStatus: aws.String(cloudformation.StackStatusCreateComplete),
						},
					},
				},
				ec2Svc:          &mockEC2{},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{},
				log:             logging.New(),
			},
			args: args{
				request: reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "broken",
						Namespace: "default",
					},
				},
			},
			want:    reconcile.Result{},
			wantErr: true,
		},
		{
			name: "if cfn stack deletion fails (cfn delete stack fails)",
			fields: fields{
				Client: fakeclient.NewFakeClient(newMockIngress("brokenDelete", true, true), newMockNodeList()),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{
						"brokenDelete": &cloudformation.Stack{
							StackStatus: aws.String(cloudformation.StackStatusCreateComplete),
						},
					},
				},
				ec2Svc:          &mockEC2{},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{},
				log:             logging.New(),
			},
			args: args{
				request: reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "brokenDelete",
						Namespace: "default",
					},
				},
			},
			want:    reconcile.Result{},
			wantErr: true,
		},
		{
			name: "if cfn stack has failed status",
			fields: fields{
				Client: fakeclient.NewFakeClient(newMockIngress("failed", false, false)),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{
						"failed": &cloudformation.Stack{
							StackStatus: aws.String(cloudformation.StackStatusCreateFailed),
						},
					},
				},
				ec2Svc:          &mockEC2{},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{},
				log:             logging.New(),
			},
			args: args{
				request: reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "failed",
						Namespace: "default",
					},
				},
			},
			want:    reconcile.Result{},
			wantErr: false,
		},
		{
			name: "if unable to describe stack (error isn't because stack doesn't exist)",
			fields: fields{
				scheme: scheme.Scheme,
				Client: fakeclient.NewFakeClient(
					newMockIngress("broken", false, false),
				),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{
						"broken": &cloudformation.Stack{},
					},
				},
				ec2Svc:          &mockEC2{},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{},
				log:             logging.New(),
			},
			args: args{
				request: reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "broken",
						Namespace: "default",
					},
				},
			},
			want:    reconcile.Result{},
			wantErr: true,
		},
		{
			name: "if create call fails (no nodes)",
			fields: fields{
				scheme: scheme.Scheme,
				Client: fakeclient.NewFakeClient(
					newMockIngress("foobar", false, false),
				),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{},
				},
				ec2Svc:          &mockEC2{},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{},
				log:             logging.New(),
			},
			args: args{
				request: reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "foobar",
						Namespace: "default",
					},
				},
			},
			want:    reconcile.Result{},
			wantErr: true,
		},
		{
			name: "if create call fails (cfn create fails)",
			fields: fields{
				scheme: scheme.Scheme,
				Client: fakeclient.NewFakeClient(
					newMockIngress("brokenCreate", false, false),
					newMockNodeList(),
				),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{},
				},
				ec2Svc:          &mockEC2{},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{},
				log:             logging.New(),
			},
			args: args{
				request: reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "brokenCreate",
						Namespace: "default",
					},
				},
			},
			want:    reconcile.Result{},
			wantErr: true,
		},
		{
			name: "fails if ingress name is too long",
			fields: fields{
				scheme: scheme.Scheme,
				Client: fakeclient.NewFakeClient(
					newMockIngress("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarf", false, false),
					newMockNodeList(),
				),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{},
				},
				ec2Svc:          &mockEC2{},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{},
				log:             logging.New(),
			},
			args: args{
				request: reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarf",
						Namespace: "default",
					},
				},
			},
			want:    reconcile.Result{},
			wantErr: true,
		},
		{
			name: "if stack doesn't exist, create stack",
			fields: fields{
				scheme: scheme.Scheme,
				Client: fakeclient.NewFakeClient(
					newMockIngress("createme", false, false),
					newMockNodeList(),
				),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{},
				},
				ec2Svc:          &mockEC2{},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{},
				log:             logging.New(),
			},
			args: args{
				request: reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "createme",
						Namespace: "default",
					},
				},
			},
			want:    reconcile.Result{Requeue: true},
			wantErr: false,
		},
		{
			name: "if cfn stack has not finished creating",
			fields: fields{
				Client: fakeclient.NewFakeClient(newMockIngress("notcomplete", false, false)),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{
						"notcomplete": &cloudformation.Stack{
							StackStatus: aws.String(cloudformation.StackStatusCreateInProgress),
						},
					},
				},
				ec2Svc:          &mockEC2{},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{},
				log:             logging.New(),
			},
			args: args{
				request: reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "notcomplete",
						Namespace: "default",
					},
				},
			},
			want:    reconcile.Result{RequeueAfter: 5 * time.Second},
			wantErr: false,
		},
		{
			name: "if cfn stack is complete but controller is unable to trigger APIGateway deploy",
			fields: fields{
				Client: fakeclient.NewFakeClient(newMockIngress("complete", false, false), newMockNodeList()),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{
						"complete": &cloudformation.Stack{
							StackStatus: aws.String(cloudformation.StackStatusCreateComplete),
							Outputs: []*cloudformation.Output{
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyRestAPIID), OutputValue: aws.String("test")},
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyAPIGatewayEndpoint), OutputValue: aws.String("https://foo.bar")},
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyClientARNS), OutputValue: aws.String("foo,bar")},
							},
						},
					},
				},
				ec2Svc:          &mockEC2{},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{},
				log:             logging.New(),
			},
			args: args{
				request: reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "complete",
						Namespace: "default",
					},
				},
			},
			want:    reconcile.Result{},
			wantErr: false,
		},
		{
			name: "if cfn stack is complete but client ARNs have changed - call update",
			fields: fields{
				scheme: scheme.Scheme,
				Client: fakeclient.NewFakeClient(
					newMockIngress("update", false, false),
					newMockService("update"),
					newMockNodeList(),
				),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{
						"update": &cloudformation.Stack{
							StackStatus: aws.String(cloudformation.StackStatusCreateComplete),
							Outputs: []*cloudformation.Output{
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyRestAPIID), OutputValue: aws.String("test")},
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyAPIGatewayEndpoint), OutputValue: aws.String("https://foo.bar")},
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyClientARNS), OutputValue: aws.String("foo")},
							},
						},
					},
				},
				ec2Svc:          &mockEC2{},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{},
				log:             logging.New(),
			},
			args: args{
				request: reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "update",
						Namespace: "default",
					},
				},
			},
			want:    reconcile.Result{Requeue: true},
			wantErr: false,
		},
		{
			name: "if update fails - (no nodes)",
			fields: fields{
				scheme: scheme.Scheme,
				Client: fakeclient.NewFakeClient(
					newMockIngress("update", false, false),
					newMockService("update"),
				),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{
						"update": &cloudformation.Stack{
							StackStatus: aws.String(cloudformation.StackStatusCreateComplete),
							Outputs: []*cloudformation.Output{
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyRestAPIID), OutputValue: aws.String("test")},
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyAPIGatewayEndpoint), OutputValue: aws.String("https://foo.bar")},
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyClientARNS), OutputValue: aws.String("foo")},
							},
						},
					},
				},
				ec2Svc:          &mockEC2{},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{},
				log:             logging.New(),
			},
			args: args{
				request: reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "update",
						Namespace: "default",
					},
				},
			},
			want:    reconcile.Result{},
			wantErr: true,
		},
		{
			name: "if reverse proxy doesn't exist - create it - (no service)",
			fields: fields{
				scheme: scheme.Scheme,
				Client: fakeclient.NewFakeClient(
					newMockIngress("update", false, false),
					newMockNodeList(),
				),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{
						"update": &cloudformation.Stack{
							StackStatus: aws.String(cloudformation.StackStatusCreateComplete),
							Outputs: []*cloudformation.Output{
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyRestAPIID), OutputValue: aws.String("test")},
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyAPIGatewayEndpoint), OutputValue: aws.String("https://foo.bar")},
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyClientARNS), OutputValue: aws.String("foo")},
							},
						},
					},
				},
				ec2Svc:          &mockEC2{},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{},
				log:             logging.New(),
			},
			args: args{
				request: reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "update",
						Namespace: "default",
					},
				},
			},
			want:    reconcile.Result{Requeue: true},
			wantErr: false,
		},
		{
			name: "if update fails - (unable to update cfn stack)",
			fields: fields{
				scheme: scheme.Scheme,
				Client: fakeclient.NewFakeClient(
					newMockIngress("brokenStackUpdate", false, false),
					newMockService("brokenStackUpdate"),
					newMockNodeList(),
				),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{
						"brokenStackUpdate": &cloudformation.Stack{
							StackStatus: aws.String(cloudformation.StackStatusCreateComplete),
							Outputs: []*cloudformation.Output{
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyRestAPIID), OutputValue: aws.String("test")},
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyAPIGatewayEndpoint), OutputValue: aws.String("https://foo.bar")},
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyClientARNS), OutputValue: aws.String("foo")},
							},
						},
					},
				},
				ec2Svc:          &mockEC2{},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{},
				log:             logging.New(),
			},
			args: args{
				request: reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "brokenStackUpdate",
						Namespace: "default",
					},
				},
			},
			want:    reconcile.Result{},
			wantErr: true,
		},
		{
			name: "if deploy api fails",
			fields: fields{
				Client: fakeclient.NewFakeClient(
					newMockIngress("deployAPIfails", false, false),
					newMockService("deployAPIfails"),
					newMockNodeList(),
				),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{
						"deployAPIfails": &cloudformation.Stack{
							StackStatus: aws.String(cloudformation.StackStatusCreateComplete),
							Outputs: []*cloudformation.Output{
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyRestAPIID), OutputValue: aws.String("test")},
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyAPIGatewayEndpoint), OutputValue: aws.String("http123://user:abc{DEf1=ghi@bad-URL-example.com:5432")},
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyClientARNS), OutputValue: aws.String("foo,bar")},
							},
						},
					},
				},
				ec2Svc: &mockEC2{},
				apigatewaySvc: &mockAPIGateway{
					CreateDeploymentFail: true,
				},
				austoscalingSvc: &mockAutoscaling{},
				log:             logging.New(),
			},
			args: args{
				request: reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "deployAPIfails",
						Namespace: "default",
					},
				},
			},
			want:    reconcile.Result{},
			wantErr: true,
		},
		{
			name: "if controller is unable to parse APIGatewayEndpoint from cfn stack output",
			fields: fields{
				Client: fakeclient.NewFakeClient(
					newMockIngress("complete", false, false),
					newMockService("complete"),
					newMockNodeList(),
				),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{
						"complete": &cloudformation.Stack{
							StackStatus: aws.String(cloudformation.StackStatusCreateComplete),
							Outputs: []*cloudformation.Output{
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyRestAPIID), OutputValue: aws.String("test")},
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyAPIGatewayEndpoint), OutputValue: aws.String("http123://user:abc{DEf1=ghi@bad-URL-example.com:5432")},
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyClientARNS), OutputValue: aws.String("foo,bar")},
							},
						},
					},
				},
				ec2Svc:          &mockEC2{},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{},
				log:             logging.New(),
			},
			args: args{
				request: reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "complete",
						Namespace: "default",
					},
				},
			},
			want:    reconcile.Result{},
			wantErr: true,
		},
		{
			name: "if cfn stack is complete and attaching targetGroupARN to ASG",
			fields: fields{
				Client: fakeclient.NewFakeClient(newMockIngress("complete", false, false), newMockNodeList()),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{
						"complete": &cloudformation.Stack{
							StackStatus: aws.String(cloudformation.StackStatusCreateComplete),
							Outputs: []*cloudformation.Output{
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyRestAPIID), OutputValue: aws.String("test")},
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyAPIGatewayEndpoint), OutputValue: aws.String("https://foo.bar")},
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyClientARNS), OutputValue: aws.String("foo,bar")},
							},
						},
					},
				},
				ec2Svc:          &mockEC2{getASGTag: true},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{},
				log:             logging.New(),
			},
			args: args{
				request: reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "complete",
						Namespace: "default",
					},
				},
			},
			want:    reconcile.Result{},
			wantErr: false,
		},
		{
			name: "if cfn stack is complete and not attaching targetGroupARN to ASG",
			fields: fields{
				Client: fakeclient.NewFakeClient(newMockIngress("complete", false, false), newMockNodeList()),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{
						"complete": &cloudformation.Stack{
							StackStatus: aws.String(cloudformation.StackStatusCreateComplete),
							Outputs: []*cloudformation.Output{
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyRestAPIID), OutputValue: aws.String("test")},
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyAPIGatewayEndpoint), OutputValue: aws.String("https://foo.bar")},
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyClientARNS), OutputValue: aws.String("foo,bar")},
							},
						},
					},
				},
				ec2Svc:          &mockEC2{getASGTag: true},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{withTargetGroupARN: true},
				log:             logging.New(),
			},
			args: args{
				request: reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "complete",
						Namespace: "default",
					},
				},
			},
			want:    reconcile.Result{},
			wantErr: false,
		},
		{
			name: "if cfn stack is complete and attaching targetGroupARN to ASG failed",
			fields: fields{
				Client: fakeclient.NewFakeClient(newMockIngress("complete", false, false), newMockNodeList()),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{
						"complete": &cloudformation.Stack{
							StackStatus: aws.String(cloudformation.StackStatusCreateComplete),
							Outputs: []*cloudformation.Output{
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyRestAPIID), OutputValue: aws.String("test")},
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyAPIGatewayEndpoint), OutputValue: aws.String("https://foo.bar")},
								&cloudformation.Output{OutputKey: aws.String(controllercfn.OutputKeyClientARNS), OutputValue: aws.String("foo,bar")},
							},
						},
					},
				},
				ec2Svc:          &mockEC2{getASGTag: true},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{attachTGErr: true},
				log:             logging.New(),
			},
			args: args{
				request: reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "complete",
						Namespace: "default",
					},
				},
			},
			want:    reconcile.Result{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &ReconcileIngress{
				Client:         tt.fields.Client,
				scheme:         tt.fields.scheme,
				cfnSvc:         tt.fields.cfnSvc,
				ec2Svc:         tt.fields.ec2Svc,
				apigatewaySvc:  tt.fields.apigatewaySvc,
				autoscalingSvc: tt.fields.austoscalingSvc,
				log:            tt.fields.log,
			}
			got, err := r.Reconcile(tt.args.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReconcileIngress.Reconcile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ReconcileIngress.Reconcile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReconcileIngress_create(t *testing.T) {
	type fields struct {
		Client          client.Client
		scheme          *runtime.Scheme
		cfnSvc          cloudformationiface.CloudFormationAPI
		ec2Svc          ec2iface.EC2API
		apigatewaySvc   apigatewayiface.APIGatewayAPI
		austoscalingSvc autoscalingiface.AutoScalingAPI
		log             *zap.Logger
	}
	type args struct {
		instance *extensionsv1beta1.Ingress
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *extensionsv1beta1.Ingress
		wantErr bool
	}{
		{
			name: "successful create adds finalizer",
			fields: fields{
				scheme: scheme.Scheme,
				Client: fakeclient.NewFakeClient(newMockNodeList()),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{},
				},
				ec2Svc:          &mockEC2{},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{},
				log:             logging.New(),
			},
			args: args{
				instance: newMockIngress("foobar", false, false),
			},
			want:    newMockIngress("foobar", false, true),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &ReconcileIngress{
				Client:         tt.fields.Client,
				scheme:         tt.fields.scheme,
				cfnSvc:         tt.fields.cfnSvc,
				ec2Svc:         tt.fields.ec2Svc,
				apigatewaySvc:  tt.fields.apigatewaySvc,
				autoscalingSvc: tt.fields.austoscalingSvc,
				log:            tt.fields.log,
			}
			got, err := r.create(tt.args.instance)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReconcileIngress.create() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ReconcileIngress.create() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReconcileIngress_delete(t *testing.T) {
	type fields struct {
		Client          client.Client
		scheme          *runtime.Scheme
		cfnSvc          cloudformationiface.CloudFormationAPI
		ec2Svc          ec2iface.EC2API
		apigatewaySvc   apigatewayiface.APIGatewayAPI
		austoscalingSvc autoscalingiface.AutoScalingAPI
		log             *zap.Logger
	}
	type args struct {
		instance *extensionsv1beta1.Ingress
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *extensionsv1beta1.Ingress
		want1   *reconcile.Result
		wantErr bool
	}{
		{
			name: "cfn stack doesn't exist removes finalizer",
			fields: fields{
				scheme: scheme.Scheme,
				Client: fakeclient.NewFakeClient(newMockNodeList()),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{},
				},
				ec2Svc:          &mockEC2{},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{},
				log:             logging.New(),
			},
			args: args{
				instance: &extensionsv1beta1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "foobar",
						Namespace:   "default",
						Annotations: map[string]string{},
						Finalizers:  []string{FinalizerCFNStack},
					},
					Spec: extensionsv1beta1.IngressSpec{}},
			},
			want: &extensionsv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "foobar",
					Namespace:   "default",
					Annotations: map[string]string{},
					Finalizers:  []string{},
				},
				Spec: extensionsv1beta1.IngressSpec{}},
			want1:   nil,
			wantErr: false,
		},
		{
			name: "successful delete removes finalizer",
			fields: fields{
				scheme: scheme.Scheme,
				Client: fakeclient.NewFakeClient(newMockNodeList()),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{
						"foobar": &cloudformation.Stack{
							StackStatus: aws.String(cloudformation.StackStatusDeleteComplete),
						},
					},
				},
				ec2Svc:          &mockEC2{},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{},
				log:             logging.New(),
			},
			args: args{
				instance: &extensionsv1beta1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "foobar",
						Namespace:   "default",
						Annotations: map[string]string{},
						Finalizers:  []string{FinalizerCFNStack},
					},
					Spec: extensionsv1beta1.IngressSpec{}},
			},
			want: &extensionsv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "foobar",
					Namespace:   "default",
					Annotations: map[string]string{},
					Finalizers:  []string{},
				},
				Spec: extensionsv1beta1.IngressSpec{}},
			want1:   nil,
			wantErr: false,
		},
		{
			name: "successful deatch targetARN from AG and delete",
			fields: fields{
				scheme: scheme.Scheme,
				Client: fakeclient.NewFakeClient(newMockNodeList()),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{
						"foobar": &cloudformation.Stack{
							StackStatus: aws.String(cloudformation.StackStatusCreateComplete),
						},
					},
				},
				ec2Svc:          &mockEC2{getASGTag: true},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{withTargetGroupARN: true},
				log:             logging.New(),
			},
			args: args{
				instance: &extensionsv1beta1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "foobar",
						Namespace:   "default",
						Annotations: map[string]string{},
						Finalizers:  []string{FinalizerCFNStack},
					},
					Spec: extensionsv1beta1.IngressSpec{}},
			},
			want: &extensionsv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "foobar",
					Namespace:   "default",
					Annotations: map[string]string{},
					Finalizers:  []string{FinalizerCFNStack},
				},
				Spec: extensionsv1beta1.IngressSpec{}},
			want1:   &reconcile.Result{Requeue: true},
			wantErr: false,
		},
		{
			name: "do not perform detach of targetGroupARN from ASG and successful delete",
			fields: fields{
				scheme: scheme.Scheme,
				Client: fakeclient.NewFakeClient(newMockNodeList()),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{
						"foobar": &cloudformation.Stack{
							StackStatus: aws.String(cloudformation.StackStatusCreateComplete),
						},
					},
				},
				ec2Svc:          &mockEC2{getASGTag: true},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{},
				log:             logging.New(),
			},
			args: args{
				instance: &extensionsv1beta1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "foobar",
						Namespace:   "default",
						Annotations: map[string]string{},
						Finalizers:  []string{FinalizerCFNStack},
					},
					Spec: extensionsv1beta1.IngressSpec{}},
			},
			want: &extensionsv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "foobar",
					Namespace:   "default",
					Annotations: map[string]string{},
					Finalizers:  []string{FinalizerCFNStack},
				},
				Spec: extensionsv1beta1.IngressSpec{}},
			want1:   &reconcile.Result{Requeue: true},
			wantErr: false,
		},
		{
			name: "detaching tragetGroupARN from ASG fails",
			fields: fields{
				scheme: scheme.Scheme,
				Client: fakeclient.NewFakeClient(newMockNodeList()),
				cfnSvc: &mockCloudformation{
					Stacks: map[string]*cloudformation.Stack{
						"foobar": &cloudformation.Stack{
							StackStatus: aws.String(cloudformation.StackStatusCreateComplete),
						},
					},
				},
				ec2Svc:          &mockEC2{getASGTag: true},
				apigatewaySvc:   &mockAPIGateway{},
				austoscalingSvc: &mockAutoscaling{detachTGErr: true, withTargetGroupARN: true},
				log:             logging.New(),
			},
			args: args{
				instance: &extensionsv1beta1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "foobar",
						Namespace:   "default",
						Annotations: map[string]string{},
						Finalizers:  []string{FinalizerCFNStack},
					},
					Spec: extensionsv1beta1.IngressSpec{}},
			},
			want:    nil,
			want1:   nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &ReconcileIngress{
				Client:         tt.fields.Client,
				scheme:         tt.fields.scheme,
				cfnSvc:         tt.fields.cfnSvc,
				ec2Svc:         tt.fields.ec2Svc,
				apigatewaySvc:  tt.fields.apigatewaySvc,
				autoscalingSvc: tt.fields.austoscalingSvc,
				log:            tt.fields.log,
			}
			got, got1, err := r.delete(tt.args.instance)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReconcileIngress.delete() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ReconcileIngress.delete() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("ReconcileIngress.delete() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
