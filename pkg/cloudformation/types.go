package cloudformation

type Output struct {
	Value string
}

type Statement struct {
	Effect    string              `json:"Effect"`
	Principal map[string][]string `json:"Principal"`
	Action    []string            `json:"Action"`
	Resource  []string            `json:"Resource"`
}

type AssumeStatement struct {
	Effect    string              `json:"Effect"`
	Principal map[string][]string `json:"Principal"`
	Action    []string            `json:"Action"`
}

type AssumePolicyDocument struct {
	Version   string            `json:"Version"`
	Statement []AssumeStatement `json:"Statement"`
}

type PolicyDocument struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

type AllPrinciplesStatement struct {
	Effect    string   `json:"Effect"`
	Principal string   `json:"Principal"`
	Action    []string `json:"Action"`
	Resource  []string `json:"Resource"`
}

type AllPrinciplesPolicyDocument struct {
	Version   string                   `json:"Version"`
	Statement []AllPrinciplesStatement `json:"Statement"`
}

type UsagePlan struct {
	PlanName                   string                             `json:"plan_name"`
	Description                string                             `json:"description"`
	APIKeys                    []APIKey                           `json:"api_keys"`
	QuotaLimit                 int                                `json:"quota_limit"`
	QuotaOffset                int                                `json:"quota_offset"`
	QuotaPeriod                string                             `json:"quota_period"`
	ThrottleBurstLimit         int                                `json:"throttle_burst_limit"`
	ThrottleRateLimit          float64                            `json:"throttle_rate_limit"`
	MethodThrottlingParameters []MethodThrottlingParametersObject `json:"method_throttling_parameters"`
}

type APIKey struct {
	CustomerID         string `json:"customer_id"`
	GenerateDistinctID bool   `json:"generate_distinct_id"`
	Name               string `json:"name"`
}

type MethodThrottlingParametersObject struct {
	Path       string  `json:"path"`
	BurstLimit int     `json:"burst_limit"`
	RateLimit  float64 `json:"rate_limit"`
}

type APIResource struct {
	Path              string          `json:"path"`
	CachingEnabled    bool            `json:"caching_enabled"`
	CacheTtlInSeconds int             `json:"cache_ttl_secs"`
	Methods           []Method        `json:"method"`
	PathParams        []ConstantParam `json:"cons_path_params"`
	QueryParams       []ConstantParam `json:"cons_query_params"`
	HeaderParams      []ConstantParam `json:"cons_header_params"`
	ProxyPathParams   []Param         `json:"path_params"`
	ProxyQueryParams  []Param         `json:"query_params"`
	ProxyHeaderParams []Param         `json:"header_params"`
	Type              string          `json:"type"`
	LambdaArn         string          `json:"lambda_arn"`
}

type Method struct {
	Method                string   `json:"method,omitempty"`
	APIKeyEnabled         bool     `json:"api_key_enabled"`
	Authorization_Enabled bool     `json:"authorization_enabled"`
	Authorizator_Index    int      `json:"authorizator_index"`
	Authorization_Scopes  []string `json:"scopes"`
}

type AWSAPIDefinition struct {
	Name                  string             `json:"name,omitempty"`
	Context               string             `json:"context"`
	AuthenticationEnabled bool               `json:"authentication_enabled"`
	APIKeyEnabled         bool               `json:"api_key_enabled"`
	Authorization_Enabled bool               `json:"authorization_enabled"`
	UsagePlans            []UsagePlan        `json:"usage_plans"`
	Authorizers           []AWSAPIAuthorizer `json:"authorizers"`
	APIs                  []APIResource      `json:"apis"`
	BinaryMediaTypes      []string           `json:"binary_media_types"`
	LoggingLevel          string             `json:"logging_level"`
}

type AWSAPIAuthorizer struct {
	IdentitySource               string   `json:"id_source"`
	AuthorizerType               string   `json:"authorizer_type,omitempty"` //can be TOKEN, COGNITO_USER_POOLS or REQUEST
	AuthorizerAuthType           string   `json:"authorizer_auth_type"`
	AuthorizerName               string   `json:"authorizer_name"`
	IdentityValidationExpression string   `json:"id_validation_exp"`
	AuthorizerResultTtlInSeconds int      `json:"authorizer_result_ttl_secs"`
	AuthorizerUri                string   `json:"lambda_arn"`
	ProviderARNs                 []string `json:"provider_arns"`
}

type Param struct {
	Param        string `json:"param"`
	Required     bool   `json:"required"`
	MappingParam string `json:"mapping_param"`
}

type ConstantParam struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
