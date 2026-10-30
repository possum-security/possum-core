package aws_test

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	scanneraws "github.com/possum-security/possum-core/pkg/scanner/aws"
)

type mockEC2DescribeRegionsAPI struct {
	output *ec2.DescribeRegionsOutput
	err    error
}

func (m *mockEC2DescribeRegionsAPI) DescribeRegions(ctx context.Context, params *ec2.DescribeRegionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.output, nil
}

func TestDiscoverEnabledRegionsWithClient(t *testing.T) {
	t.Run("successful region discovery", func(t *testing.T) {
		mock := &mockEC2DescribeRegionsAPI{
			output: &ec2.DescribeRegionsOutput{
				Regions: []ec2types.Region{
					{RegionName: aws.String("us-east-1")},
					{RegionName: aws.String("us-west-2")},
					{RegionName: aws.String("eu-west-1")},
				},
			},
		}

		regions, err := scanneraws.DiscoverEnabledRegionsWithClient(context.Background(), mock)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(regions) != 3 {
			t.Fatalf("expected 3 regions, got %d", len(regions))
		}
		if regions[0] != "eu-west-1" || regions[1] != "us-east-1" || regions[2] != "us-west-2" {
			t.Errorf("expected sorted regions, got %v", regions)
		}
	})

	t.Run("api failure falls back to default major regions", func(t *testing.T) {
		mock := &mockEC2DescribeRegionsAPI{
			err: errors.New("UnauthorizedOperation"),
		}

		regions, err := scanneraws.DiscoverEnabledRegionsWithClient(context.Background(), mock)
		if err == nil {
			t.Error("expected error to be returned on API failure")
		}
		if len(regions) == 0 {
			t.Error("expected fallback default regions")
		}
	})
}

func TestParseRegionsList(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"", nil},
		{"  ", nil},
		{"us-east-1", []string{"us-east-1"}},
		{"us-east-1, us-west-2, eu-west-1", []string{"us-east-1", "us-west-2", "eu-west-1"}},
		{"US-EAST-1, us-east-1, US-WEST-2", []string{"us-east-1", "us-west-2"}},
	}

	for _, tc := range tests {
		actual := scanneraws.ParseRegionsList(tc.input)
		if len(actual) != len(tc.expected) {
			t.Errorf("input %q: expected len %d, got %d (%v)", tc.input, len(tc.expected), len(actual), actual)
			continue
		}
		for i := range actual {
			if actual[i] != tc.expected[i] {
				t.Errorf("input %q: index %d expected %q, got %q", tc.input, i, tc.expected[i], actual[i])
			}
		}
	}
}
