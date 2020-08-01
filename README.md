# Amazon API Gateway Ingress Controller

## Getting Started

The default configuration assumes you are using kube2iam to manage pod permissions.
To set up a role for this controller use the following command

```sh
export INSTANCE_ROLE_ARNS=`comma delimited list of k8s worker instance ARNs`
make iam
```

To build and deploy the controller

```sh
export IMG=`some ecr repository`
export IAMROLEARN=`the iam role arn created above`

make docker-build
make docker-push
make deploy
```



## Example

```yaml
---
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  annotations:
    apigateway.ingress.kubernetes.io/client-arns: arn:aws:iam::xxx:user/xxx
    apigateway.ingress.kubernetes.io/aws-api-configs: '[]'
    apigateway.ingress.kubernetes.io/stage-name: prod
    apigateway.ingress.kubernetes.io/apigw-endpoint-type: REGIONAL
    kubernetes.io/ingress.class: apigateway
    apigateway.ingress.kubernetes.io/custom-domain-name: apigw-test.example.com
    apigateway.ingress.kubernetes.io/certificate-arn: arn:aws:acm:xxx:xxx:certificate/xxx
    apigateway.ingress.kubernetes.io/hosted-zone-name: example.com.
    apigateway.ingress.kubernetes.io/custom-domain-base-path: api
    apigateway.ingress.kubernetes.io/route53-assume-role-arn: arn:aws:iam::xxx:role/xxx
    apigateway.ingress.kubernetes.io/request-timeout-millis: "10000"
    apigateway.ingress.kubernetes.io/tls-policy: TLS_1_2
    apigateway.ingress.kubernetes.io/min-compression-size: "52428800"
    apigateway.ingress.kubernetes.io/api-key-based-usage-plans: '[{"plan_name":"Gold","description":"Gold plan","api_keys":[{"customer_id":"cus1","generate_distinct_id":true,"name":"cus1_key1"},{"customer_id":"cus2","generate_distinct_id":true,"name":"cus2_key1"}],"quota_limit":100,"quota_period":"Month","throttle_burst_limit":100,"throttle_rate_limit":100,"method_throttling_parameters":[{"path":"/api/book/","burst_limit":100,"rate_limit":100},{"path":"/api/author/","burst_limit":100,"rate_limit":100}]},{"plan_name":"Silver","description":"Silver Plan","api_keys":[{"customer_id":"cus1","generate_distinct_id":true,"name":"cus1_key2"},{"customer_id":"cus2","generate_distinct_id":true,"name":"cus2_key2"}],"quota_limit":50,"quota_period":"Month","throttle_burst_limit":50,"throttle_rate_limit":50,"method_throttling_parameters":[{"path":"/api/book/","burst_limit":50,"rate_limit":50},{"path":"/api/author/","burst_limit":50,"rate_limit":50}]}]'
    apigateway.ingress.kubernetes.io/gateway-cache-enabled: "false"
    apigateway.ingress.kubernetes.io/gateway-cache-size: "0.5"
    apigateway.ingress.kubernetes.io/public-resources: '[{"path":"/api/v1/foobar","caching_enabled":true,"method":["GET", "POST"]}]'
    apigateway.ingress.kubernetes.io/waf-enabled: "true"
    apigateway.ingress.kubernetes.io/waf-scope: REGIONAL
    apigateway.ingress.kubernetes.io/waf-rule-cf-json: '[{"Name":"RuleWithAWSManagedRules","Priority":0,"OverrideAction":{"Count":{}},"VisibilityConfig":{"SampledRequestsEnabled":true,"CloudWatchMetricsEnabled":true,"MetricName":"RuleWithAWSManagedRulesMetric"},"Statement":{"ManagedRuleGroupStatement":{"VendorName":"AWS","Name":"AWSManagedRulesCommonRuleSet","ExcludedRules":[]}}},{"Name":"RuleWithAWSManagedLinuxnRules","Priority":4,"OverrideAction":{"Count":{}},"VisibilityConfig":{"SampledRequestsEnabled":true,"CloudWatchMetricsEnabled":true,"MetricName":"RuleWithAWSManagedLinuxRulesMetric"},"Statement":{"ManagedRuleGroupStatement":{"VendorName":"AWS","Name":"AWSManagedRulesLinuxRuleSet","ExcludedRules":[]}}},{"Name":"RuleWithAWSManagedIPReputationRules","Priority":5,"OverrideAction":{"Count":{}},"VisibilityConfig":{"SampledRequestsEnabled":true,"CloudWatchMetricsEnabled":true,"MetricName":"RuleWithAWSManagedIPReputationRulesMetric"},"Statement":{"ManagedRuleGroupStatement":{"VendorName":"AWS","Name":"AWSManagedRulesAmazonIpReputationList","ExcludedRules":[]}}},{"Name":"RuleWithAWSManagedAdminProtectionRules","Priority":6,"OverrideAction":{"Count":{}},"VisibilityConfig":{"SampledRequestsEnabled":true,"CloudWatchMetricsEnabled":true,"MetricName":"RuleWithAWSManagedAdminProtectionRulesMetric"},"Statement":{"ManagedRuleGroupStatement":{"VendorName":"AWS","Name":"AWSManagedRulesAdminProtectionRuleSet","ExcludedRules":[]}}},{"Name":"RuleWithAWSManagedKnownBadInputsRules","Priority":2,"OverrideAction":{"Count":{}},"VisibilityConfig":{"SampledRequestsEnabled":true,"CloudWatchMetricsEnabled":true,"MetricName":"RuleWithAWSManagedKnownBadInputsRulesMetric"},"Statement":{"ManagedRuleGroupStatement":{"VendorName":"AWS","Name":"AWSManagedRulesKnownBadInputsRuleSet","ExcludedRules":[]}}},{"Name":"RuleWithAWSManagedSQLInjectInputsRules","Priority":3,"OverrideAction":{"Count":{}},"VisibilityConfig":{"SampledRequestsEnabled":true,"CloudWatchMetricsEnabled":true,"MetricName":"RuleWithAWSManagedSQLInjectInputsRulesMetric"},"Statement":{"ManagedRuleGroupStatement":{"VendorName":"AWS","Name":"AWSManagedRulesSQLiRuleSet","ExcludedRules":[]}}},{"Name":"BlockXssAttack","Priority":1,"Action":{"Block":{}},"VisibilityConfig":{"SampledRequestsEnabled":true,"CloudWatchMetricsEnabled":true,"MetricName":"BlockXssAttackMetric"},"Statement":{"XssMatchStatement":{"FieldToMatch":{"AllQueryArguments":{}},"TextTransformations":[{"Priority":1,"Type":"NONE"}]}}}]'
  name: api-95d8427d
  namespace: default
spec:
  rules:
  - http:
      paths:
      - backend:
          serviceName: bookservice
          servicePort: 80
        path: /api/book
      - backend:
          serviceName: authorservice
          servicePort: 80
        path: /api/author
```
