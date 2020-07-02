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
	Path              string   `json:"path"`
	CachingEnabled    bool     `json:"caching_enabled"`
	Methods           []string `json:"method"`
	ProxyPathParams   []Param  `json:"path_params"`
	ProxyQueryParams  []Param  `json:"query_params"`
	ProxyHeaderParams []Param  `json:"header_params"`
}

type Param struct {
	Param    string `json:"param"`
	Required bool   `json:"required"`
}
