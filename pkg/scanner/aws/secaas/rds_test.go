package secaas

import (
	"context"
	"testing"

	"github.com/possum-sec/possum/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/stretchr/testify/assert"
)

type mockRDSClient struct {
	describeDBInstancesFunc          func(ctx context.Context, params *rds.DescribeDBInstancesInput) (*rds.DescribeDBInstancesOutput, error)
	describeDBParametersFunc         func(ctx context.Context, params *rds.DescribeDBParametersInput) (*rds.DescribeDBParametersOutput, error)
	describeDBSnapshotsFunc          func(ctx context.Context, params *rds.DescribeDBSnapshotsInput) (*rds.DescribeDBSnapshotsOutput, error)
	describeDBSnapshotAttributesFunc func(ctx context.Context, params *rds.DescribeDBSnapshotAttributesInput) (*rds.DescribeDBSnapshotAttributesOutput, error)
}

func (m *mockRDSClient) DescribeDBInstances(ctx context.Context, params *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	if m.describeDBInstancesFunc != nil {
		return m.describeDBInstancesFunc(ctx, params)
	}
	return &rds.DescribeDBInstancesOutput{}, nil
}

func (m *mockRDSClient) DescribeDBParameters(ctx context.Context, params *rds.DescribeDBParametersInput, optFns ...func(*rds.Options)) (*rds.DescribeDBParametersOutput, error) {
	if m.describeDBParametersFunc != nil {
		return m.describeDBParametersFunc(ctx, params)
	}
	return &rds.DescribeDBParametersOutput{}, nil
}

func (m *mockRDSClient) DescribeDBSnapshots(ctx context.Context, params *rds.DescribeDBSnapshotsInput, optFns ...func(*rds.Options)) (*rds.DescribeDBSnapshotsOutput, error) {
	if m.describeDBSnapshotsFunc != nil {
		return m.describeDBSnapshotsFunc(ctx, params)
	}
	return &rds.DescribeDBSnapshotsOutput{}, nil
}

func (m *mockRDSClient) DescribeDBSnapshotAttributes(ctx context.Context, params *rds.DescribeDBSnapshotAttributesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBSnapshotAttributesOutput, error) {
	if m.describeDBSnapshotAttributesFunc != nil {
		return m.describeDBSnapshotAttributesFunc(ctx, params)
	}
	return &rds.DescribeDBSnapshotAttributesOutput{}, nil
}

func TestRDSScanner_Compliant(t *testing.T) {
	mock := &mockRDSClient{
		describeDBInstancesFunc: func(ctx context.Context, params *rds.DescribeDBInstancesInput) (*rds.DescribeDBInstancesOutput, error) {
			return &rds.DescribeDBInstancesOutput{
				DBInstances: []rdstypes.DBInstance{
					{
						DBInstanceIdentifier:    aws.String("prod-postgres"),
						DBInstanceArn:           aws.String("arn:aws:rds:us-east-1:123456789012:db:prod-postgres"),
						Engine:                  aws.String("postgres"),
						StorageEncrypted:        aws.Bool(true),
						BackupRetentionPeriod:   aws.Int32(14),
						PubliclyAccessible:      aws.Bool(false),
						AutoMinorVersionUpgrade: aws.Bool(true),
						DBParameterGroups: []rdstypes.DBParameterGroupStatus{
							{DBParameterGroupName: aws.String("custom-pg-params")},
						},
					},
				},
			}, nil
		},
		describeDBParametersFunc: func(ctx context.Context, params *rds.DescribeDBParametersInput) (*rds.DescribeDBParametersOutput, error) {
			return &rds.DescribeDBParametersOutput{
				Parameters: []rdstypes.Parameter{
					{
						ParameterName:  aws.String("rds.force_ssl"),
						ParameterValue: aws.String("1"),
					},
				},
			}, nil
		},
	}

	rdsScanner := NewRDSScannerWithClient(mock, "us-east-1")
	results, err := rdsScanner.Scan(context.Background())
	assert.NoError(t, err)
	assert.Len(t, results, 5)

	for _, r := range results {
		assert.Equal(t, "PASS", r.Status, "Expected PASS for %s", r.RuleID)
	}
}

func TestRDSScanner_NonCompliant(t *testing.T) {
	mock := &mockRDSClient{
		describeDBInstancesFunc: func(ctx context.Context, params *rds.DescribeDBInstancesInput) (*rds.DescribeDBInstancesOutput, error) {
			return &rds.DescribeDBInstancesOutput{
				DBInstances: []rdstypes.DBInstance{
					{
						DBInstanceIdentifier:    aws.String("dev-mysql"),
						DBInstanceArn:           aws.String("arn:aws:rds:us-east-1:123456789012:db:dev-mysql"),
						Engine:                  aws.String("mysql"),
						StorageEncrypted:        aws.Bool(false),
						BackupRetentionPeriod:   aws.Int32(0),
						PubliclyAccessible:      aws.Bool(true),
						AutoMinorVersionUpgrade: aws.Bool(false),
						DBParameterGroups: []rdstypes.DBParameterGroupStatus{
							{DBParameterGroupName: aws.String("default.mysql8.0")},
						},
					},
				},
			}, nil
		},
		describeDBParametersFunc: func(ctx context.Context, params *rds.DescribeDBParametersInput) (*rds.DescribeDBParametersOutput, error) {
			return &rds.DescribeDBParametersOutput{
				Parameters: []rdstypes.Parameter{
					{
						ParameterName:  aws.String("require_secure_transport"),
						ParameterValue: aws.String("OFF"),
					},
				},
			}, nil
		},
	}

	rdsScanner := NewRDSScannerWithClient(mock, "us-east-1")
	results, err := rdsScanner.Scan(context.Background())
	assert.NoError(t, err)
	assert.Len(t, results, 5)

	statusMap := make(map[string]scanner.ScanResult)
	for _, r := range results {
		statusMap[r.RuleID] = r
	}

	assert.Equal(t, "FAIL", statusMap["rds_instance_storage_encrypted"].Status)
	assert.Equal(t, "FAIL", statusMap["rds_instance_backup_enabled"].Status)
	assert.Equal(t, "FAIL", statusMap["rds_instance_transport_encrypted"].Status)

	resPublic := statusMap["rds_instance_no_public_access"]
	assert.Equal(t, "FAIL", resPublic.Status)
	assert.Equal(t, "CRITICAL", resPublic.Severity)
	metricsPublic, ok := resPublic.Metrics.(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "Disable public accessibility on the RDS instance.", metricsPublic["Recommendation"])

	resUpgrade := statusMap["rds_instance_minor_version_upgrade_enabled"]
	assert.Equal(t, "FAIL", resUpgrade.Status)
	assert.Equal(t, "LOW", resUpgrade.Severity)
	metricsUpgrade, ok := resUpgrade.Metrics.(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "Enable auto minor version upgrade for the RDS instance.", metricsUpgrade["Recommendation"])
}

func TestRDSScanner_Snapshots_PublicAccess_FAIL(t *testing.T) {
	mock := &mockRDSClient{
		describeDBSnapshotsFunc: func(ctx context.Context, params *rds.DescribeDBSnapshotsInput) (*rds.DescribeDBSnapshotsOutput, error) {
			return &rds.DescribeDBSnapshotsOutput{
				DBSnapshots: []rdstypes.DBSnapshot{
					{
						DBSnapshotIdentifier: aws.String("snap-public-01"),
						DBSnapshotArn:        aws.String("arn:aws:rds:us-east-1:123456789012:snapshot:snap-public-01"),
						DBInstanceIdentifier: aws.String("prod-postgres"),
					},
				},
			}, nil
		},
		describeDBSnapshotAttributesFunc: func(ctx context.Context, params *rds.DescribeDBSnapshotAttributesInput) (*rds.DescribeDBSnapshotAttributesOutput, error) {
			assert.Equal(t, "snap-public-01", *params.DBSnapshotIdentifier)
			return &rds.DescribeDBSnapshotAttributesOutput{
				DBSnapshotAttributesResult: &rdstypes.DBSnapshotAttributesResult{
					DBSnapshotIdentifier: aws.String("snap-public-01"),
					DBSnapshotAttributes: []rdstypes.DBSnapshotAttribute{
						{
							AttributeName:   aws.String("restore"),
							AttributeValues: []string{"all"},
						},
					},
				},
			}, nil
		},
	}

	scanner := NewRDSScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.NoError(t, err)
	assert.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, "snap-public-01", r.ResourceID)
	assert.Equal(t, "SecaaS-RDS-Snapshot", r.ResourceType)
	assert.Equal(t, "rds_snapshots_public_access", r.RuleID)
	assert.Equal(t, "FAIL", r.Status)
	assert.Equal(t, "CRITICAL", r.Severity)

	metrics, ok := r.Metrics.(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "Remove public restore access from RDS snapshots.", metrics["Recommendation"])
	assert.Equal(t, true, metrics["Public"])
}

func TestRDSScanner_Snapshots_PublicAccess_PASS(t *testing.T) {
	mock := &mockRDSClient{
		describeDBSnapshotsFunc: func(ctx context.Context, params *rds.DescribeDBSnapshotsInput) (*rds.DescribeDBSnapshotsOutput, error) {
			return &rds.DescribeDBSnapshotsOutput{
				DBSnapshots: []rdstypes.DBSnapshot{
					{
						DBSnapshotIdentifier: aws.String("snap-private-01"),
						DBSnapshotArn:        aws.String("arn:aws:rds:us-east-1:123456789012:snapshot:snap-private-01"),
						DBInstanceIdentifier: aws.String("prod-postgres"),
					},
				},
			}, nil
		},
		describeDBSnapshotAttributesFunc: func(ctx context.Context, params *rds.DescribeDBSnapshotAttributesInput) (*rds.DescribeDBSnapshotAttributesOutput, error) {
			assert.Equal(t, "snap-private-01", *params.DBSnapshotIdentifier)
			return &rds.DescribeDBSnapshotAttributesOutput{
				DBSnapshotAttributesResult: &rdstypes.DBSnapshotAttributesResult{
					DBSnapshotIdentifier: aws.String("snap-private-01"),
					DBSnapshotAttributes: []rdstypes.DBSnapshotAttribute{
						{
							AttributeName:   aws.String("restore"),
							AttributeValues: []string{"987654321098"},
						},
					},
				},
			}, nil
		},
	}

	scanner := NewRDSScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.NoError(t, err)
	assert.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, "snap-private-01", r.ResourceID)
	assert.Equal(t, "SecaaS-RDS-Snapshot", r.ResourceType)
	assert.Equal(t, "rds_snapshots_public_access", r.RuleID)
	assert.Equal(t, "PASS", r.Status)
	assert.Equal(t, "INFO", r.Severity)

	metrics, ok := r.Metrics.(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, false, metrics["Public"])
}

func TestRDSScanner_Snapshots_Error(t *testing.T) {
	mock := &mockRDSClient{
		describeDBSnapshotsFunc: func(ctx context.Context, params *rds.DescribeDBSnapshotsInput) (*rds.DescribeDBSnapshotsOutput, error) {
			return nil, assert.AnError
		},
	}

	scanner := NewRDSScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.Error(t, err)
	assert.Nil(t, results)
}

func TestRDSScanner_Snapshots_AttributesError(t *testing.T) {
	mock := &mockRDSClient{
		describeDBSnapshotsFunc: func(ctx context.Context, params *rds.DescribeDBSnapshotsInput) (*rds.DescribeDBSnapshotsOutput, error) {
			return &rds.DescribeDBSnapshotsOutput{
				DBSnapshots: []rdstypes.DBSnapshot{
					{
						DBSnapshotIdentifier: aws.String("snap-err-01"),
					},
				},
			}, nil
		},
		describeDBSnapshotAttributesFunc: func(ctx context.Context, params *rds.DescribeDBSnapshotAttributesInput) (*rds.DescribeDBSnapshotAttributesOutput, error) {
			return nil, assert.AnError
		},
	}

	scanner := NewRDSScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.Error(t, err)
	assert.Nil(t, results)
}

func TestRDSScanner_Constructor(t *testing.T) {
	cfg := aws.Config{Region: "us-east-1"}
	s := NewRDSScanner(cfg)
	assert.NotNil(t, s)
	assert.Equal(t, "RDS-SecaaS-Scanner", s.Name())
	assert.Equal(t, "us-east-1", s.region)
}
