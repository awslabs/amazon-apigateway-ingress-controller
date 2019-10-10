package ingress

const (
	// IngressClassAnnotation - if set to "apigateway" this will tell the controller to take actions to manage resources for the defined ingress
	IngressClassAnnotation = "kubernetes.io/ingress.class"
	// IngressAnnotationNodeSelector are label selectors for nodes you want to attach to the resulting network load balancer
	IngressAnnotationNodeSelector = "apigateway.ingress.kubernetes.io/node-selector"
	// IngressAnnotationClientArns is a comma delimited list of IAM arns that will be authorized to call the resulting API gateway endpoint
	IngressAnnotationClientArns = "apigateway.ingress.kubernetes.io/client-arns"
	// IngressAnnotationCustomDomainName is a custom domain name for your api gateway endpoint (requires hosted zone name and certificate arn to be defined)
	IngressAnnotationCustomDomainName = "apigateway.ingress.kubernetes.io/custom-domain-name"
	// IngressAnnotationHostedZoneName is the name of the hosted zone in this account for your custom domain name
	IngressAnnotationHostedZoneName = "apigateway.ingress.kubernetes.io/hosted-zone-name"
	// IngressAnnotationCertificateArn is the certificate ARN you wish to use for your custom domain
	IngressAnnotationCertificateArn = "apigateway.ingress.kubernetes.io/certificate-arn"
	// IngressAnnotationStageName is the name for the API gateway RestAPI stage mapped to the ingress resource
	IngressAnnotationStageName = "apigateway.ingress.kubernetes.io/stage-name"
	// IngressAnnotationNginxReplicas defines the number of nginx pods to run as the reverse proxy for your intra cluster service calls
	IngressAnnotationNginxReplicas = "apigateway.ingress.kubernetes.io/nginx-replicas"
	// IngressAnnotationNginxImage is the image to deploy for the reverse proxy
	IngressAnnotationNginxImage = "apigateway.ingress.kubernetes.io/nginx-image"
	// IngressAnnotationNginxServicePort is the port that the nginx reverse proxy service is exposed on
	IngressAnnotationNginxServicePort = "apigateway.ingress.kubernetes.io/nginx-service-port"
)
