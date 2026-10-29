package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// DefaultMajorRegions provides a standard fallback list of primary AWS regions.
var DefaultMajorRegions = []string{
	"us-east-1",
	"us-east-2",
	"us-west-1",
	"us-west-2",
	"eu-west-1",
	"eu-central-1",
	"ap-southeast-1",
	"ap-northeast-1",
}

// EC2DescribeRegionsAPI defines the subset of EC2 API used for region discovery.
type EC2DescribeRegionsAPI interface {
	DescribeRegions(ctx context.Context, params *ec2.DescribeRegionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error)
}

// DiscoverEnabledRegions queries the EC2 API to discover all enabled AWS regions in the account.
// If the DescribeRegions API call fails (e.g. permission denied), it returns an error and falls back to DefaultMajorRegions.
func DiscoverEnabledRegions(ctx context.Context, cfg aws.Config) ([]string, error) {
	client := ec2.NewFromConfig(cfg)
	return DiscoverEnabledRegionsWithClient(ctx, client)
}

// DiscoverEnabledRegionsWithClient allows dependency injection of the EC2 client for unit testing.
func DiscoverEnabledRegionsWithClient(ctx context.Context, client EC2DescribeRegionsAPI) ([]string, error) {
	output, err := client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		AllRegions: aws.Bool(false), // Only list enabled regions for this account
	})
	if err != nil {
		return DefaultMajorRegions, fmt.Errorf("failed to discover AWS regions via ec2:DescribeRegions (using default major regions): %w", err)
	}

	var regions []string
	for _, r := range output.Regions {
		if r.RegionName != nil && *r.RegionName != "" {
			regions = append(regions, aws.ToString(r.RegionName))
		}
	}

	if len(regions) == 0 {
		return DefaultMajorRegions, nil
	}

	sort.Strings(regions)
	return regions, nil
}

// ParseRegionsList parses a comma-separated string of region names into a clean, deduplicated slice.
func ParseRegionsList(regionsFlag string) []string {
	if strings.TrimSpace(regionsFlag) == "" {
		return nil
	}

	seen := make(map[string]struct{})
	var result []string

	for _, r := range strings.Split(regionsFlag, ",") {
		clean := strings.ToLower(strings.TrimSpace(r))
		if clean != "" {
			if _, ok := seen[clean]; !ok {
				seen[clean] = struct{}{}
				result = append(result, clean)
			}
		}
	}

	return result
}
