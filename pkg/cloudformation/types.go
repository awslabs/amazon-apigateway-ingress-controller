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
	APIKeyCustomerID           string                             `json:"api_key_customer_id"`
	APIKeyGenerateDistinctID   bool                               `json:"api_key_generate_distinct_id"`
	APIKeyName                 string                             `json:"api_key_name"`
	QuotaLimit                 int                                `json:"quota_limit"`
	QuotaOffset                int                                `json:"quota_offset"`
	QuotaPeriod                string                             `json:"quota_period"`
	ThrottleBurstLimit         int                                `json:"throttle_burst_limit"`
	ThrottleRateLimit          float64                            `json:"throttle_rate_limit"`
	MethodThrottlingParameters []MethodThrottlingParametersObject `json:"method_throttling_parameters"`
}

type MethodThrottlingParametersObject struct {
	Path       string  `json:"path"`
	BurstLimit int     `json:"burst_limit"`
	RateLimit  float64 `json:"rate_limit"`
}
