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
