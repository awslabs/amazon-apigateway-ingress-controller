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
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/labels"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/apigateway"
	"github.com/aws/aws-sdk-go/service/apigateway/apigatewayiface"
	"github.com/aws/aws-sdk-go/service/autoscaling"
	"github.com/aws/aws-sdk-go/service/autoscaling/autoscalingiface"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/cloudformation/cloudformationiface"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	cfn "github.com/awslabs/amazon-apigateway-ingress-controller/pkg/cloudformation"
	"github.com/awslabs/amazon-apigateway-ingress-controller/pkg/finalizers"
	"github.com/awslabs/amazon-apigateway-ingress-controller/pkg/logging"
	"github.com/awslabs/amazon-apigateway-ingress-controller/pkg/network"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	extensionsv1beta1 "k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const (
	ingressNameLengthLimit            = 51
	FinalizerCFNStack                 = "apigateway.networking.amazonaws.com/ingress-finalizer"
	IngressClassAnnotation            = "kubernetes.io/ingress.class"
	IngressAnnotationNodeSelector     = "apigateway.ingress.kubernetes.io/node-selector"
	IngressAnnotationClientArns       = "apigateway.ingress.kubernetes.io/client-arns"
	IngressAnnotationCustomDomainName = "apigateway.ingress.kubernetes.io/custom-domain-name"
	IngressAnnotationCertificateArn   = "apigateway.ingress.kubernetes.io/certificate-arn"
	IngressAnnotationStageName        = "apigateway.ingress.kubernetes.io/stage-name"
	IngressAnnotationNginxReplicas    = "apigateway.ingress.kubernetes.io/nginx-replicas"
	IngressAnnotationNginxImage       = "apigateway.ingress.kubernetes.io/nginx-image"
	IngressAnnotationNginxServicePort = "apigateway.ingress.kubernetes.io/nginx-service-port"
	IngressAnnotationEndpointTypes    = "apigateway.ingress.kubernetes.io/apigw-endpoint-type"
)

var (
	DefaultNginxReplicas    = 3
	DefaultNginxImage       = "nginx:latest"
	DefaultNginxServicePort = 8080
	DefaultNodeSelector     = labels.NewSelector()
)

// Add creates a new Ingress Controller and adds it to the Manager with default RBAC. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

func getAWSSession(logger *zap.Logger) *session.Session {
	logger.Info("creating session for ec2metadata service")
	sess, err := session.NewSession(&aws.Config{Region: aws.String("us-west-2")})
	if err != nil {
		logger.Fatal("unable create session for ec2 metadata service call", zap.Error(err))
	}

	ec2metadataSvc := ec2metadata.New(sess)
	logger.Info("fetching ec2 identity document")
	ec2IdentityDocument, err := ec2metadataSvc.GetInstanceIdentityDocument()
	if err != nil {
		logger.Fatal("unable to determine region from ec2", zap.Error(err))
	}

	logger.Info("creating AWS api session", zap.String("region", ec2IdentityDocument.Region))
	sess, err = session.NewSession(&aws.Config{
		Region: aws.String(ec2IdentityDocument.Region),
	})

	if err != nil {
		logger.Fatal("unable to create session for AWS services", zap.Error(err))
	}

	return sess
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	logger := logging.New()

	sess := getAWSSession(logger)

	return &ReconcileIngress{
		Client:         mgr.GetClient(),
		scheme:         mgr.GetScheme(),
		log:            logger,
		cfnSvc:         cloudformation.New(sess),
		ec2Svc:         ec2.New(sess),
		apigatewaySvc:  apigateway.New(sess),
		autoscalingSvc: autoscaling.New(sess),
	}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("ingress-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to Ingress
	err = c.Watch(&source.Kind{Type: &extensionsv1beta1.Ingress{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	// // TODO(user): Modify this to be the types you create
	// // Uncomment watch a Deployment created by Ingress - change this for objects you create
	// err = c.Watch(&source.Kind{Type: &appsv1.Deployment{}}, &handler.EnqueueRequestForOwner{
	// 	IsController: true,
	// 	OwnerType:    &extensionsv1beta1.Ingress{},
	// })
	// if err != nil {
	// 	return err
	// }

	return nil
}

var _ reconcile.Reconciler = &ReconcileIngress{}

// ReconcileIngress reconciles a Ingress object
type ReconcileIngress struct {
	client.Client
	scheme         *runtime.Scheme
	cfnSvc         cloudformationiface.CloudFormationAPI
	ec2Svc         ec2iface.EC2API
	apigatewaySvc  apigatewayiface.APIGatewayAPI
	autoscalingSvc autoscalingiface.AutoScalingAPI
	log            *zap.Logger
}

func (r *ReconcileIngress) fetchNetworkingInfo(instance *extensionsv1beta1.Ingress) (*network.Network, error) {
	// TODO: We probably want to add some way of specifying which worker nodes we want to use. (security group ingress rules etc...)
	r.log.Info("fetching worker nodes")
	nodes := corev1.NodeList{
		Items: []corev1.Node{},
	}

	if err := r.Client.List(context.TODO(), &client.ListOptions{
		LabelSelector: getNodeSelector(instance),
	}, &nodes); err != nil {
		return nil, err
	}

	if len(nodes.Items) == 0 {
		return nil, fmt.Errorf("no worker nodes found")
	}

	nodeInstanceIds := []string{}
	for _, node := range nodes.Items {
		nodeInstanceIds = append(nodeInstanceIds, node.Spec.ProviderID[strings.LastIndex(node.Spec.ProviderID, "/")+1:])
	}

	r.log.Info("getting vpcID, securityGroups, subnetIds, asgNames for worker nodes")
	vpcIDs, subnetIds, securityGroups, asgNames, err := network.GetNetworkInfoForEC2Instances(r.ec2Svc, r.autoscalingSvc, nodeInstanceIds)
	if err != nil {
		return nil, err
	}

	r.log.Info("describing VPCs", zap.String("VPCs", strings.Join(vpcIDs, ",")))
	describeVPCResponse, err := r.ec2Svc.DescribeVpcs(&ec2.DescribeVpcsInput{
		VpcIds: aws.StringSlice(vpcIDs),
	})

	if err != nil || len(describeVPCResponse.Vpcs) == 0 {
		return nil, fmt.Errorf("unable to find vpc %s", strings.Join(vpcIDs, ", "))
	}

	return &network.Network{
		InstanceIDs:      nodeInstanceIds,
		SecurityGroupIDs: securityGroups,
		SubnetIDs:        subnetIds,
		ASGNames:         asgNames,
		Vpc:              describeVPCResponse.Vpcs[0],
	}, nil
}

// Reconcile reads that state of the cluster for a Ingress object and makes changes based on the state read
// and what is in the Ingress.Spec
// Automatically generate RBAC rules to allow the Controller to read and write Deployments
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=deployments/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core,resources=nodes;services;configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=nodes/status;services/status;configmaps/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=extensions,resources=ingresses,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=extensions,resources=ingresses/status,verbs=get;update;patch
func (r *ReconcileIngress) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	// Fetch the Ingress instance
	instance := &extensionsv1beta1.Ingress{}
	err := r.Get(context.TODO(), request.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Object not found, return.  Created objects are automatically garbage collected.
			// For additional cleanup logic use finalizers.
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}

	// Ignore other ingress resources
	if instance.Annotations[IngressClassAnnotation] != "apigateway" {
		return reconcile.Result{}, nil
	}

	if len(instance.GetObjectMeta().GetName()) > ingressNameLengthLimit {
		return reconcile.Result{}, fmt.Errorf("ingress name must be < %d characters", ingressNameLengthLimit)
	}

	// Delete if timestamp is set
	if instance.ObjectMeta.DeletionTimestamp.IsZero() == false {
		if finalizers.HasFinalizer(instance, FinalizerCFNStack) {
			// r.log.Info("deleting apigateway cloudformation stack", zap.String("stackName", instance.ObjectMeta.Name))
			instance, requeue, err := r.delete(instance)
			if requeue != nil {
				return *requeue, nil
			}

			if err != nil {
				return reconcile.Result{}, err
			}

			return reconcile.Result{}, r.Update(context.TODO(), instance)
		}

		return reconcile.Result{}, nil
	}

	// Check if stack exists
	stack, err := cfn.DescribeStack(r.cfnSvc, instance.ObjectMeta.Name)
	if err != nil && cfn.IsDoesNotExist(err, instance.ObjectMeta.Name) {
		r.log.Info("creating apigateway", zap.String("stackName", instance.ObjectMeta.Name))
		instance, err := r.create(instance)
		if err != nil {
			return reconcile.Result{}, err
		}

		if err := r.Update(context.TODO(), instance); err != nil {
			return reconcile.Result{}, err
		}

		return reconcile.Result{Requeue: true}, nil
	} else if err != nil {
		r.log.Error("error describing stack", zap.Error(err))
		return reconcile.Result{}, err
	}

	r.log.Info("Found Stack", zap.String("stackName", instance.ObjectMeta.Name), zap.String("StackStatus", *stack.StackStatus))

	if cfn.IsFailed(*stack.StackStatus) {
		return reconcile.Result{}, r.Update(context.TODO(), instance)
	}

	if cfn.IsComplete(*stack.StackStatus) == false {
		r.log.Info("Not complete, requeuing", zap.String("status", *stack.StackStatus))
		// increasing timout value to 30 as create/update cf stack takes time and quick update gives errors sometimes
		return reconcile.Result{RequeueAfter: 20 * time.Second}, r.Update(context.TODO(), instance)
	}

	if cfn.IsComplete(*stack.StackStatus) && shouldUpdate(stack, instance, r.apigatewaySvc) {
		r.log.Info("updating apigateway cloudformation stack", zap.String("stackName", instance.ObjectMeta.Name))
		if err := r.update(instance); err != nil {
			return reconcile.Result{}, err
		}

		return reconcile.Result{Requeue: true}, nil
	}

	outputs := cfn.StackOutputMap(stack)

	// Deploy API so changes are applied after Update
	r.log.Info("creating apigateway deployment", zap.String(cfn.OutputKeyRestApiID, outputs[cfn.OutputKeyRestApiID]), zap.String("stage", getStageName(instance)))
	if _, err := r.apigatewaySvc.CreateDeployment(&apigateway.CreateDeploymentInput{
		RestApiId: aws.String(outputs[cfn.OutputKeyRestApiID]),
		StageName: aws.String(getStageName(instance)),
	}); err != nil {
		r.log.Error("unable to deploy ApiGateway Rest API", zap.Error(err))
		return reconcile.Result{}, err
	}

	u, err := url.Parse(outputs[cfn.OutputKeyAPIGatewayEndpoint])
	if err != nil {
		r.log.Error("unable to parse url from stack output", zap.Error(err), zap.String("output", outputs[cfn.OutputKeyAPIGatewayEndpoint]))
		return reconcile.Result{}, err
	}

	err = r.attachTGToASG(instance)
	if err != nil {
		r.log.Error("unable to verify ASG after create/update", zap.Error(err))
		return reconcile.Result{}, err
	}

	r.log.Info("Stack Create/Update Complete")
	instance.Status = extensionsv1beta1.IngressStatus{
		LoadBalancer: corev1.LoadBalancerStatus{
			Ingress: []corev1.LoadBalancerIngress{
				corev1.LoadBalancerIngress{Hostname: u.Host},
			},
		},
	}

	return reconcile.Result{}, r.Status().Update(context.TODO(), instance)

}

func (r *ReconcileIngress) getASGsAndTargetGroup(instance *extensionsv1beta1.Ingress) ([]string, string, error) {
	stackName := instance.ObjectMeta.Name

	network, err := r.fetchNetworkingInfo(instance)
	if err != nil {
		r.log.Error("error fetching network information", zap.String("stackName", stackName))
		return nil, "", err
	}

	targetGroupARN, err := cfn.GetResourceID(r.cfnSvc, stackName, "TargetGroup")
	if err != nil {
		r.log.Error("error getting TargetGroupARN", zap.String("stackName", stackName))
		return nil, "", err
	}

	return network.ASGNames, targetGroupARN, nil
}

func (r *ReconcileIngress) getTargetGroupsFromASG(asgName string) ([]string, error) {
	data, err := r.autoscalingSvc.DescribeAutoScalingGroups(&autoscaling.DescribeAutoScalingGroupsInput{
		AutoScalingGroupNames: aws.StringSlice([]string{asgName}),
	})
	if err != nil {
		return nil, err
	}

	return aws.StringValueSlice(data.AutoScalingGroups[0].TargetGroupARNs), nil
}

func (r *ReconcileIngress) attachTGToASG(instance *extensionsv1beta1.Ingress) error {
	asgNames, targetGroupARN, err := r.getASGsAndTargetGroup(instance)
	if err != nil {
		return err
	}

	stackName := instance.ObjectMeta.Name

	for _, asgName := range asgNames {
		existingTargetGroupARNs, err := r.getTargetGroupsFromASG(asgName)
		if err != nil {
			r.log.Error("error describing ASG", zap.String("stackName", stackName), zap.String("asgName", asgName))
			return err
		}

		if contains(existingTargetGroupARNs, targetGroupARN) {
			r.log.Info("targetGroupARN already attached to ASG", zap.String("stackName", stackName), zap.String("asgName", asgName), zap.String("targetGroupARN", targetGroupARN))
		} else {
			r.log.Info("attaching targetGroupARN to ASG", zap.String("stackName", stackName), zap.String("asgName", asgName), zap.String("targetGroupARN", targetGroupARN))
			_, err = r.autoscalingSvc.AttachLoadBalancerTargetGroups(&autoscaling.AttachLoadBalancerTargetGroupsInput{
				AutoScalingGroupName: aws.String(asgName),
				TargetGroupARNs:      aws.StringSlice([]string{targetGroupARN}),
			})
			if err != nil {
				r.log.Error("error attaching targetGroupARN to ASG", zap.String("stackName", stackName), zap.String("asgName", asgName), zap.String("targetGroupARN", targetGroupARN))
				return err
			}
		}
	}

	return nil
}

func (r *ReconcileIngress) detachTGFromASG(instance *extensionsv1beta1.Ingress) error {
	asgNames, targetGroupARN, err := r.getASGsAndTargetGroup(instance)
	if err != nil {
		return err
	}

	stackName := instance.ObjectMeta.Name

	for _, asgName := range asgNames {
		existingTargetGroupARNs, err := r.getTargetGroupsFromASG(asgName)
		if err != nil {
			r.log.Error("error describing ASG", zap.String("stackName", stackName), zap.String("asgName", asgName))
			return err
		}

		if contains(existingTargetGroupARNs, targetGroupARN) {
			r.log.Info("detaching targetGroupARN from ASG", zap.String("stackName", stackName), zap.String("asgName", asgName), zap.String("targetGroupARN", targetGroupARN))
			_, err = r.autoscalingSvc.DetachLoadBalancerTargetGroups(&autoscaling.DetachLoadBalancerTargetGroupsInput{
				AutoScalingGroupName: aws.String(asgName),
				TargetGroupARNs:      aws.StringSlice([]string{targetGroupARN}),
			})
			if err != nil {
				r.log.Error("error detaching targetGroupARN from ASG", zap.String("stackName", stackName), zap.String("asgName", asgName), zap.String("targetGroupARN", targetGroupARN))
				return err
			}
		} else {
			r.log.Info("targetGroupARN already removed from ASG", zap.String("stackName", stackName), zap.String("asgName", asgName), zap.String("targetGroupARN", targetGroupARN))
		}
	}

	return nil
}

func contains(records []string, key string) bool {
	for _, data := range records {
		if key == data {
			return true
		}
	}
	return false
}

func (r *ReconcileIngress) delete(instance *extensionsv1beta1.Ingress) (*extensionsv1beta1.Ingress, *reconcile.Result, error) {
	stack, err := cfn.DescribeStack(r.cfnSvc, instance.ObjectMeta.Name)
	if err != nil && cfn.IsDoesNotExist(err, instance.ObjectMeta.Name) {
		r.log.Info("stack doesn't exist, removing finalizer", zap.String("stackName", instance.ObjectMeta.Name))
		instance.SetFinalizers(finalizers.RemoveFinalizer(instance, FinalizerCFNStack))
		return instance, nil, nil
	}

	if err != nil {
		r.log.Error("error describing apigateway cloudformation stack", zap.String("stackName", instance.ObjectMeta.Name), zap.Error(err))
		return nil, nil, err
	}

	if cfn.IsDeleting(*stack.StackStatus) {
		r.log.Info("retrying delete in 5 seconds", zap.String("status", *stack.StackStatus))
		return instance, &reconcile.Result{RequeueAfter: 5 * time.Second}, nil
	}

	if cfn.DeleteComplete(*stack.StackStatus) {
		r.log.Info("delete complete, removing finalizer", zap.String("stackName", instance.ObjectMeta.Name))
		instance.SetFinalizers(finalizers.RemoveFinalizer(instance, FinalizerCFNStack))
		return instance, nil, nil
	}

	// We want to retry delete even if DELETE_FAILED since removing Loadbalancer/VPCLink can be a bit finnicky
	r.log.Info(
		"deleting apigateway cloudformation stack",
		zap.String("stackName", instance.ObjectMeta.Name),
		zap.String("status", *stack.StackStatus),
	)

	err = r.detachTGFromASG(instance)
	if err != nil {
		r.log.Error("unable to verify ASG before delete", zap.Error(err))
		return nil, nil, err
	}

	if _, err := r.cfnSvc.DeleteStack(&cloudformation.DeleteStackInput{
		StackName: aws.String(instance.GetObjectMeta().GetName()),
	}); err != nil {
		r.log.Error("error deleting apigateway cloudformation stack", zap.Error(err))
		return nil, nil, err
	}

	return instance, &reconcile.Result{Requeue: true}, nil
}

func (r *ReconcileIngress) buildReverseProxyResources(instance *extensionsv1beta1.Ingress) []metav1.Object {
	resourceName := createReverseProxyResourceName(instance.Name)

	configMap := &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      resourceName,
			Namespace: instance.Namespace,
		},
		Data: map[string]string{
			"nginx.conf": buildNginxConfig(instance),
		},
	}

	replicas := int32(getNginxReplicas(instance))
	defaultMode := int32(420)

	deploy := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      resourceName,
			Namespace: instance.Namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"deployment": resourceName},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"deployment": resourceName}},
				Spec: corev1.PodSpec{
					Volumes: []corev1.Volume{
						corev1.Volume{
							Name: "config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									DefaultMode: &defaultMode,
									LocalObjectReference: corev1.LocalObjectReference{
										Name: configMap.Name,
									},
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: getNginxImage(instance),
							VolumeMounts: []corev1.VolumeMount{
								{
									MountPath: "/etc/nginx",
									Name:      "config",
								},
							},
						},
					},
				},
			},
		},
	}

	service := &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Service",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      resourceName,
			Namespace: instance.Namespace,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				corev1.ServicePort{
					Name:     "http",
					Protocol: "TCP",
					Port:     int32(getNginxServicePort(instance)),
				},
			},
			Selector:        map[string]string{"deployment": resourceName},
			SessionAffinity: corev1.ServiceAffinityNone,
			Type:            corev1.ServiceTypeNodePort,
		},
	}

	return []metav1.Object{configMap, deploy, service}
}

func (r *ReconcileIngress) updateReverseProxy(instance *extensionsv1beta1.Ingress) (*corev1.Service, error) {
	objects := r.buildReverseProxyResources(instance)
	for _, object := range objects {
		if err := controllerutil.SetControllerReference(instance, object, r.scheme); err != nil {
			return nil, err
		}

		runtimeObject := object.(runtime.Object)
		err := r.Get(context.TODO(), k8stypes.NamespacedName{Name: object.GetName(), Namespace: object.GetNamespace()}, runtimeObject)
		switch errors.IsNotFound(err) {
		case true:
			r.log.Info("creating reverse proxy resource", zap.String("gvk", runtimeObject.GetObjectKind().GroupVersionKind().String()), zap.String("name", object.GetName()))
			if err := r.Create(context.TODO(), runtimeObject); err != nil {
				return nil, err
			}
		case false:
			r.log.Info("reverse proxy resource already exists, updating", zap.String("gvk", runtimeObject.GetObjectKind().GroupVersionKind().String()), zap.String("name", object.GetName()))
			if err := r.Update(context.TODO(), runtimeObject); err != nil {
				return nil, err
			}
		}
	}

	r.log.Info("fetching proxy service details")
	svc := &corev1.Service{}
	if err := r.Get(context.TODO(), k8stypes.NamespacedName{Name: createReverseProxyResourceName(instance.Name), Namespace: instance.Namespace}, svc); err != nil {
		r.log.Error("unable to fetch proxy service", zap.Error(err))

		return nil, err
	}

	return svc, nil
}

func (r *ReconcileIngress) create(instance *extensionsv1beta1.Ingress) (*extensionsv1beta1.Ingress, error) {
	r.log.Info("creating reverse proxy")
	svc, err := r.updateReverseProxy(instance)
	if err != nil {
		r.log.Error("error creating proxy resources", zap.Error(err))
		return nil, err
	}

	// Fetch worker node networking info (grabs all nodes for now)
	network, err := r.fetchNetworkingInfo(instance)
	if err != nil {
		r.log.Error("unable to fetch networking info", zap.Error(err))
		return nil, err
	}

	cfnTemplate := cfn.BuildApiGatewayTemplateFromIngressRule(&cfn.TemplateConfig{
		Rule:             instance.Spec.Rules[0],
		Network:          network,
		NodePort:         int(svc.Spec.Ports[0].NodePort),
		Arns:             getArns(instance),
		StageName:        getStageName(instance),
		CustomDomainName: getCustomDomainName(instance),
		CertificateArn:   getCertificateArn(instance),
		APIEndpointTypes: getAPIEndpointTypes(instance),
	})

	b, err := cfnTemplate.YAML()
	if err != nil {
		return nil, err
	}

	r.log.Info("creating cloudformation stack")
	if _, err := r.cfnSvc.CreateStack(&cloudformation.CreateStackInput{
		TemplateBody: aws.String(string(b)),
		StackName:    aws.String(instance.GetObjectMeta().GetName()),
		Capabilities: aws.StringSlice([]string{"CAPABILITY_IAM"}),
		Tags: []*cloudformation.Tag{
			{
				Key:   aws.String("managedBy"),
				Value: aws.String("amazon-apigateway-ingress-controller"),
			},
		},
	}); err != nil {
		return nil, err
	}

	r.log.Info("cloudformation stack creating, setting finalizers", zap.String("StackName", instance.ObjectMeta.Name))
	instance.SetFinalizers(finalizers.AddFinalizer(instance, FinalizerCFNStack))

	return instance, nil
}

func (r *ReconcileIngress) update(instance *extensionsv1beta1.Ingress) error {
	network, err := r.fetchNetworkingInfo(instance)
	if err != nil {
		r.log.Error("unable to fetch networking info", zap.Error(err))
		return err
	}

	r.log.Info("updating proxy")
	svc, err := r.updateReverseProxy(instance)
	if err != nil {
		r.log.Error("error creating proxy resources", zap.Error(err))
		return err
	}

	cfnTemplate := cfn.BuildApiGatewayTemplateFromIngressRule(&cfn.TemplateConfig{
		Rule:             instance.Spec.Rules[0],
		Network:          network,
		Arns:             getArns(instance),
		StageName:        getStageName(instance),
		NodePort:         int(svc.Spec.Ports[0].NodePort),
		CustomDomainName: getCustomDomainName(instance),
		CertificateArn:   getCertificateArn(instance),
		APIEndpointTypes: getAPIEndpointTypes(instance),
	})
	b, err := cfnTemplate.YAML()
	if err != nil {
		return err
	}

	if _, err := r.cfnSvc.UpdateStack(&cloudformation.UpdateStackInput{
		TemplateBody: aws.String(string(b)),
		StackName:    aws.String(instance.GetObjectMeta().GetName()),
		Capabilities: aws.StringSlice([]string{"CAPABILITY_IAM"}),
		Tags: []*cloudformation.Tag{
			{
				Key:   aws.String("managedBy"),
				Value: aws.String("aws-apigateway-ingress-controller"),
			},
		},
	}); err != nil {
		r.log.Error("unable to fetch proxy service", zap.Error(err))
		return err
	}

	return nil
}
