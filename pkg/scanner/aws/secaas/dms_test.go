package secaas

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/databasemigrationservice"
	dmstypes "github.com/aws/aws-sdk-go-v2/service/databasemigrationservice/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockDMSClient struct {
	describeReplicationInstancesOutput *databasemigrationservice.DescribeReplicationInstancesOutput
	err                                error
}

func (m *mockDMSClient) DescribeReplicationInstances(ctx context.Context, params *databasemigrationservice.DescribeReplicationInstancesInput, optFns ...func(*databasemigrationservice.Options)) (*databasemigrationservice.DescribeReplicationInstancesOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.describeReplicationInstancesOutput != nil {
		return m.describeReplicationInstancesOutput, nil
	}
	return &databasemigrationservice.DescribeReplicationInstancesOutput{}, nil
}

func TestNewDMSScanner(t *testing.T) {
	cfg := aws.Config{Region: "us-west-2"}
	s := NewDMSScanner(cfg)
	assert.NotNil(t, s)
	assert.Equal(t, "DMS-SecaaS-Scanner", s.Name())
	assert.Equal(t, "us-west-2", s.region)

	mock := &mockDMSClient{}
	sClient := NewDMSScannerWithClient(mock, "ap-southeast-1")
	assert.NotNil(t, sClient)
	assert.Equal(t, "ap-southeast-1", sClient.region)
}

func TestDMSScanner_Private_PASS(t *testing.T) {
	instanceID := "dms-rep-private-01"
	instanceArn := "arn:aws:dms:us-east-1:123456789012:rep:dms-rep-private-01"
	mock := &mockDMSClient{
		describeReplicationInstancesOutput: &databasemigrationservice.DescribeReplicationInstancesOutput{
			ReplicationInstances: []dmstypes.ReplicationInstance{
				{
					ReplicationInstanceIdentifier: aws.String(instanceID),
					ReplicationInstanceArn:        aws.String(instanceArn),
					PubliclyAccessible:            false,
					VpcSecurityGroups: []dmstypes.VpcSecurityGroupMembership{
						{VpcSecurityGroupId: aws.String("sg-dms-01")},
					},
					KmsKeyId: aws.String("arn:aws:kms:us-east-1:123456789012:key/abc-123"),
				},
			},
		},
	}

	scanner := NewDMSScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, instanceID, r.ResourceID)
	assert.Equal(t, "SecaaS-DMS", r.ResourceType)
	assert.Equal(t, "us-east-1", r.Region)
	assert.Equal(t, "PASS", r.Status)
	assert.Equal(t, "INFO", r.Severity)
	assert.Equal(t, "dms_instance_no_public_access", r.RuleID)

	metrics, ok := r.Metrics.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, false, metrics["PubliclyAccessible"])

	require.Len(t, r.Nodes, 1)
	assert.Equal(t, instanceArn, r.Nodes[0].ID)

	require.Len(t, r.Edges, 2)
	assert.Equal(t, "sg-dms-01", r.Edges[0].From)
	assert.Equal(t, instanceArn, r.Edges[0].To)
	assert.Equal(t, "ATTACHED_TO", r.Edges[0].Relation)
	assert.Equal(t, instanceArn, r.Edges[1].From)
	assert.Equal(t, "arn:aws:kms:us-east-1:123456789012:key/abc-123", r.Edges[1].To)
	assert.Equal(t, "ENCRYPTED_WITH", r.Edges[1].Relation)
}

func TestDMSScanner_Public_FAIL(t *testing.T) {
	instanceID := "dms-rep-public-01"
	instanceArn := "arn:aws:dms:us-east-1:123456789012:rep:dms-rep-public-01"
	mock := &mockDMSClient{
		describeReplicationInstancesOutput: &databasemigrationservice.DescribeReplicationInstancesOutput{
			ReplicationInstances: []dmstypes.ReplicationInstance{
				{
					ReplicationInstanceIdentifier: aws.String(instanceID),
					ReplicationInstanceArn:        aws.String(instanceArn),
					PubliclyAccessible:            true,
				},
			},
		},
	}

	scanner := NewDMSScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, instanceID, r.ResourceID)
	assert.Equal(t, "SecaaS-DMS", r.ResourceType)
	assert.Equal(t, "us-east-1", r.Region)
	assert.Equal(t, "FAIL", r.Status)
	assert.Equal(t, "CRITICAL", r.Severity)
	assert.Equal(t, "dms_instance_no_public_access", r.RuleID)

	metrics, ok := r.Metrics.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, true, metrics["PubliclyAccessible"])
	assert.Equal(t, "Disable public accessibility on DMS replication instances.", metrics["Recommendation"])
}

func TestDMSScanner_Empty(t *testing.T) {
	mock := &mockDMSClient{
		describeReplicationInstancesOutput: &databasemigrationservice.DescribeReplicationInstancesOutput{
			ReplicationInstances: []dmstypes.ReplicationInstance{},
		},
	}

	scanner := NewDMSScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestDMSScanner_Error(t *testing.T) {
	mock := &mockDMSClient{
		err: errors.New("dms unavailable"),
	}

	scanner := NewDMSScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.Error(t, err)
	assert.Nil(t, results)
}

func TestDMSScanner_ResourceLimit(t *testing.T) {
	mock := &mockDMSClient{
		describeReplicationInstancesOutput: &databasemigrationservice.DescribeReplicationInstancesOutput{
			ReplicationInstances: []dmstypes.ReplicationInstance{
				{
					ReplicationInstanceIdentifier: aws.String("rep-1"),
					PubliclyAccessible:            false,
				},
				{
					ReplicationInstanceIdentifier: aws.String("rep-2"),
					PubliclyAccessible:            false,
				},
			},
		},
	}

	scanner := NewDMSScannerWithClient(mock, "us-east-1")
	ctx := context.WithValue(context.Background(), "ResourceLimit", 1)
	results, err := scanner.Scan(ctx)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "rep-1", results[0].ResourceID)
}
