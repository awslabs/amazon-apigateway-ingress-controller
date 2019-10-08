package network

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/autoscaling"
	"github.com/aws/aws-sdk-go/service/autoscaling/autoscalingiface"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"strings"
)

type Network struct {
	InstanceIDs      []string
	SecurityGroupIDs []string
	SubnetIDs        []string
	ASGNames         []string
	Vpc              *ec2.Vpc
}

func getListFromMap(data map[string]bool) (uniqData []string) {
	for key := range data {
		uniqData = append(uniqData, key)
	}
	return uniqData
}

func GetNetworkInfoForEC2Instances(ec2svc ec2iface.EC2API, autoscalingSvc autoscalingiface.AutoScalingAPI, nodeInstanceIds []string) (vpcIds []string, subnetIds []string, securityGroups []string, asgNames []string, err error) {
	output, err := ec2svc.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: aws.StringSlice(nodeInstanceIds),
	})
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("Error describing instances: %s", err)
	}

	vids := map[string]bool{}
	sids := map[string]bool{}
	sgs := map[string]bool{}
	asgs := map[string]bool{}

	for _, reservation := range output.Reservations {
		for _, instance := range reservation.Instances {
			for _, tag := range instance.Tags {
				if *tag.Key == "aws:autoscaling:groupName" {
					asgs[*tag.Value] = true
				}
			}
			if *instance.SubnetId != "" {
				sids[*instance.SubnetId] = true
			}
			for _, sg := range instance.SecurityGroups {
				sgs[*sg.GroupId] = true
			}

			vids[*instance.VpcId] = true
		}
	}

	for asgName := range asgs {
		asgOutput, err := autoscalingSvc.DescribeAutoScalingGroups(&autoscaling.DescribeAutoScalingGroupsInput{
			AutoScalingGroupNames: aws.StringSlice([]string{asgName}),
		})
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("Error describing autoscaling group: %s", err)
		}

		if len(asgOutput.AutoScalingGroups) == 1 {
			asgNames = append(asgNames, asgName)

			// It is possible the ASG has more subnets to choose, when instance_count < subnets_in_ASG
			for _, sid := range strings.Split(*asgOutput.AutoScalingGroups[0].VPCZoneIdentifier, ",") {
				sids[sid] = true
			}

		}
	}

	subnetIds = getListFromMap(sids)
	securityGroups = getListFromMap(sgs)
	vpcIds = getListFromMap(vids)

	return vpcIds, subnetIds, securityGroups, asgNames, nil
}
