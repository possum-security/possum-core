package finops

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

// ECRClient defines the interface for interacting with AWS ECR.
type ECRClient interface {
	ecr.DescribeRepositoriesAPIClient
	ecr.DescribeImagesAPIClient
}

// ECRScanner checks for Untagged Docker images that are wasting storage costs.
type ECRScanner struct {
	client        ECRClient
	RetentionDays int
	FlagUntagged  bool
	region        string
}

// Ensure ECRScanner satisfies MetaScanner at compile time.
var _ scanner.MetaScanner = (*ECRScanner)(nil)

func NewECRScanner(cfg aws.Config, retentionDays int, flagUntagged bool) *ECRScanner {
	if retentionDays <= 0 {
		retentionDays = 180
	}
	return &ECRScanner{
		client:        ecr.NewFromConfig(cfg),
		RetentionDays: retentionDays,
		FlagUntagged:  flagUntagged,
		region:        cfg.Region,
	}
}

func NewECRScannerWithClient(client ECRClient, retentionDays int, flagUntagged bool) *ECRScanner {
	if retentionDays <= 0 {
		retentionDays = 180
	}
	return &ECRScanner{
		client:        client,
		RetentionDays: retentionDays,
		FlagUntagged:  flagUntagged,
	}
}

func (s *ECRScanner) Name() string {
	return "ECR-Image-Scanner"
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *ECRScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "ecr-image-scanner",
		Name:          s.Name(),
		Category:      model.CategoryFinOps,
		Scope:         model.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "ecr",
		CheckIDs:      []string{RuleECRImageUntaggedOrStale},
	}
}

func (s *ECRScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult

	repoPaginator := ecr.NewDescribeRepositoriesPaginator(s.client, &ecr.DescribeRepositoriesInput{})

	for repoPaginator.HasMorePages() {
		page, err := repoPaginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, repo := range page.Repositories {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			repoName := aws.ToString(repo.RepositoryName)

			imgPaginator := ecr.NewDescribeImagesPaginator(s.client, &ecr.DescribeImagesInput{
				RepositoryName: repo.RepositoryName,
			})

			for imgPaginator.HasMorePages() {
				imgPage, err := imgPaginator.NextPage(ctx)
				if err != nil {
					break
				}

				for _, image := range imgPage.ImageDetails {
					sizeBytes := float64(aws.ToInt64(image.ImageSizeInBytes))
					cost := (sizeBytes / (1024.0 * 1024.0 * 1024.0)) * 0.10

					isOrphaned := false
					var recommendation string

					if len(image.ImageTags) == 0 && s.FlagUntagged {
						isOrphaned = true
						recommendation = "Delete Untagged Image"
					}

					if !isOrphaned && image.ImagePushedAt != nil {
						daysOld := int(time.Since(*image.ImagePushedAt).Hours() / 24)
						if daysOld > s.RetentionDays {
							isOrphaned = true
							recommendation = fmt.Sprintf("Image is %d days old (exceeds %d-day retention)", daysOld, s.RetentionDays)
						}
					}

					metrics := map[string]interface{}{
						"RepositoryName":       repoName,
						"SizeInBytes":          sizeBytes,
						"Tags":                 image.ImageTags,
						"EstimatedMonthlyCost": cost,
					}
					if image.ImagePushedAt != nil {
						metrics["PushedAt"] = image.ImagePushedAt.Format("2006-01-02")
					}

					if isOrphaned {
						critCount, highCount := getVulnerabilityCounts(ctx, image, repoName)
						if critCount > 0 || highCount > 0 {
							cveCount := critCount
							if cveCount == 0 {
								cveCount = highCount
							}
							tagDisplay := "untagged"
							if len(image.ImageTags) > 0 {
								tagDisplay = image.ImageTags[0]
							}
							recommendation = fmt.Sprintf("Deleting orphaned image %s saves $%.2f/mo in ECR storage and eliminates %d critical CVEs.", tagDisplay, cost, cveCount)
							metrics["CriticalCVEs"] = critCount
							metrics["HighCVEs"] = highCount
							metrics["ZombieRiskBounty"] = true
						}
						metrics["Recommendation"] = recommendation
					}

					costWaste := 0.0
					if isOrphaned {
						costWaste = cost
					}

					digest := aws.ToString(image.ImageDigest)

					results = append(results, BuildFinOpsResult(FinOpsResultParams{
						ResourceID:   digest,
						ResourceType: "ECR_IMAGE",
						Region:       resolveRegion(s.region, "regional"),
						RuleID:       RuleECRImageUntaggedOrStale,
						DisplayName:  fmt.Sprintf("%s@%s", repoName, digest),
						IsOrphaned:   isOrphaned,
						Cost:         costWaste,
						Title:        "Untagged or Stale ECR Docker Image",
						Description:  fmt.Sprintf("ECR image in %s is untagged or exceeds retention window (%d days).", repoName, s.RetentionDays),
						Remediation:  fmt.Sprintf("Delete image via aws ecr batch-delete-image --repository-name %s --image-ids imageDigest=%s", repoName, digest),
						Metrics:      metrics,
					}))
				}
			}
		}
	}

	return results, nil
}

func getVulnerabilityCounts(ctx context.Context, image ecrtypes.ImageDetail, repoName string) (critCount int, highCount int) {
	if image.ImageScanFindingsSummary != nil && image.ImageScanFindingsSummary.FindingSeverityCounts != nil {
		critCount += int(image.ImageScanFindingsSummary.FindingSeverityCounts["CRITICAL"])
		highCount += int(image.ImageScanFindingsSummary.FindingSeverityCounts["HIGH"])
	}

	digest := aws.ToString(image.ImageDigest)
	var keys []string
	if digest != "" {
		keys = append(keys, digest)
	}
	for _, tag := range image.ImageTags {
		keys = append(keys, tag)
	}
	keys = append(keys, repoName)

	contextKeys := []string{"ContainerVulnerabilities", "ImageVulnerabilities", "Vulnerabilities", "SecurityFindings", "Findings"}
	for _, ck := range contextKeys {
		val := ctx.Value(ck)
		if val == nil {
			continue
		}

		switch v := val.(type) {
		case map[string]int:
			for _, k := range keys {
				if cnt, ok := v[k]; ok {
					critCount += cnt
				}
			}
		case map[string]map[string]int:
			for _, k := range keys {
				if sevMap, ok := v[k]; ok {
					critCount += sevMap["CRITICAL"]
					highCount += sevMap["HIGH"]
				}
			}
		case []model.SecurityFinding:
			for _, f := range v {
				matched := false
				for _, k := range keys {
					if strings.Contains(f.ResourceID, k) {
						matched = true
						break
					}
				}
				if matched {
					if strings.EqualFold(f.Severity, "CRITICAL") {
						critCount++
					} else if strings.EqualFold(f.Severity, "HIGH") {
						highCount++
					}
				}
			}
		}
	}

	return critCount, highCount
}
