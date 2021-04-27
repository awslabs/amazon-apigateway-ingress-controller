package cloudformation

import (
	"fmt"
	"regexp"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/cloudformation/cloudformationiface"

	"github.com/aws/aws-sdk-go/aws/awserr"
)

//CompleteStatuses contains all CloudFormation status strings that we consider to be complete for a vpn
var CompleteStatuses = []string{
	cloudformation.StackStatusCreateComplete,
	cloudformation.StackStatusUpdateComplete,
	cloudformation.StackStatusDeleteComplete,
	cloudformation.StackStatusUpdateRollbackComplete,
}

//FailedStatuses contains all CloudFormation status strings that we consider to be failed for a vpn
var FailedStatuses = []string{
	cloudformation.StackStatusCreateFailed,
	cloudformation.StackStatusRollbackComplete,
	cloudformation.StackStatusRollbackFailed,
	cloudformation.StackStatusUpdateRollbackFailed,
	cloudformation.StackStatusDeleteFailed,
}

//PendingStatuses contains all CloudFormation status strings that we consider to be pending for a vpn
var PendingStatuses = []string{
	cloudformation.StackStatusCreateInProgress,
	cloudformation.StackStatusDeleteInProgress,
	cloudformation.StackStatusRollbackInProgress,
	cloudformation.StackStatusUpdateCompleteCleanupInProgress,
	cloudformation.StackStatusUpdateInProgress,
	cloudformation.StackStatusUpdateRollbackCompleteCleanupInProgress,
	cloudformation.StackStatusUpdateRollbackInProgress,
	cloudformation.StackStatusReviewInProgress,
}

// IsDeleting tests if the stack status is DELETE_IN_PROGRESS
func IsDeleting(status string) bool {
	if status == cloudformation.StackStatusDeleteInProgress {
		return true
	}

	return false
}

func DeleteComplete(status string) bool {
	if status == cloudformation.StackStatusDeleteComplete {
		return true
	}

	return false
}

// IsFailed tests if the specified string is considered a failed cloudformation stack state
func IsFailed(status string) bool {
	for _, s := range FailedStatuses {
		if s == status {
			return true
		}
	}
	return false
}

// IsComplete tests if the specified string is considered a completed cloudformation stack state
func IsComplete(status string) bool {
	for _, s := range CompleteStatuses {
		if s == status {
			return true
		}
	}
	return false
}

// IsPending tests if the specified string is considered a pending cloudformation stack state
func IsPending(status string) bool {
	for _, s := range PendingStatuses {
		if s == status {
			return true
		}
	}
	return false
}

//StackDoesNotExist Checks if the error recieved for DescribeStacks denotes if the stack is non exsistent
func StackDoesNotExist(err error) bool {
	if aErr, ok := err.(awserr.Error); ok {
		matched, _ := regexp.MatchString(`status code: 400`, aErr.Error())
		if aErr.Code() == "ValidationError" {
			return matched
		}
	}
	return false
}

func IsDoesNotExist(err error, stackName string) bool {
	if err != nil {
		if aErr, ok := err.(awserr.Error); ok {
			if aErr.Code() == "ValidationError" && aErr.Message() == fmt.Sprintf("Stack with id %s does not exist", stackName) {
				return true
			}
		}
	}
	return false
}

func DescribeStack(cfnSvc cloudformationiface.CloudFormationAPI, stackName string) (*cloudformation.Stack, error) {
	out, err := cfnSvc.DescribeStacks(&cloudformation.DescribeStacksInput{
		StackName: aws.String(stackName),
	})

	if err != nil {
		return nil, err
	}

	return out.Stacks[0], nil
}

func GetResourceID(cfnSvc cloudformationiface.CloudFormationAPI, stackName string, logicalID string) (string, error) {
	var next *string
	for {
		resources, err := cfnSvc.ListStackResources(&cloudformation.ListStackResourcesInput{
			StackName: aws.String(stackName),
			NextToken: next,
		})
		if err != nil {
			return "", err
		}

		for _, resourceSummary := range resources.StackResourceSummaries {
			if *resourceSummary.LogicalResourceId == logicalID {
				return *resourceSummary.PhysicalResourceId, nil
			}
		}

		if *resources.NextToken == "" {
			break
		} else {
			next = resources.NextToken
		}

	}
	return "", fmt.Errorf("resource %s not found", logicalID)

}

func StackOutputMap(stack *cloudformation.Stack) map[string]string {
	outputs := map[string]string{}
	for _, output := range stack.Outputs {
		outputs[*output.OutputKey] = *output.OutputValue
	}

	return outputs
}
