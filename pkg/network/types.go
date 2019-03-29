package network

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
)

type Network struct {
	InstanceIDs      []string
	SecurityGroupIDs []string
	SubnetIDs        []string
	Vpc              *ec2.Vpc
}

func GetNetworkInfoForEC2Instances(ec2svc ec2iface.EC2API, nodeInstanceIds []string) (vpcIds []string, subnetIds []string, securityGroups []string, err error) {
	output, err := ec2svc.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: aws.StringSlice(nodeInstanceIds),
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Error describing instances: %s", err)
	}

	vids := map[string]bool{}
	sids := map[string]bool{}
	sgs := map[string]bool{}

	for _, reservation := range output.Reservations {
		for _, instance := range reservation.Instances {
			if *instance.SubnetId != "" {
				sids[*instance.SubnetId] = true
			}
			for _, sg := range instance.SecurityGroups {
				sgs[*sg.GroupId] = true
			}

			vids[*instance.VpcId] = true
		}
	}

	for sid := range sids {
		subnetIds = append(subnetIds, sid)
	}

	for sg := range sgs {
		securityGroups = append(securityGroups, sg)
	}

	for id := range vids {
		vpcIds = append(vpcIds, id)
	}

	return vpcIds, subnetIds, securityGroups, nil
}
