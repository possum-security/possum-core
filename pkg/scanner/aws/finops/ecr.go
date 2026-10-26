package finops

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/amirmahdy/possum-core/pkg/model"
	"github.com/amirmahdy/possum-core/pkg/scanner"

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
}

func NewECRScanner(cfg aws.Config, retentionDays int, flagUntagged bool) *ECRScanner {
	if retentionDays <= 0 {
		retentionDays = 180
	}
	return &ECRScanner{
		client:        ecr.NewFromConfig(cfg),
		RetentionDays: retentionDays,
		FlagUntagged:  flagUntagged,
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

func (s *ECRScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult

	// First, we must get a list of all repositories
	repoPaginator := ecr.NewDescribeRepositoriesPaginator(s.client, &ecr.DescribeRepositoriesInput{})

	for repoPaginator.HasMorePages() {
		repoPage, err := repoPaginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, repo := range repoPage.Repositories {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			repoName := aws.ToString(repo.RepositoryName)

			// Now we paginate through the images in this specific repository
			imgPaginator := ecr.NewDescribeImagesPaginator(s.client, &ecr.DescribeImagesInput{
				RepositoryName: aws.String(repoName),
			})

			for imgPaginator.HasMorePages() {
				imgPage, err := imgPaginator.NextPage(ctx)
				if err != nil {
					return nil, err // In a production app, we might want to log this and continue rather than fail the whole scan
				}

				for _, image := range imgPage.ImageDetails {
					isOrphaned := false
					recommendation := ""

					// FinOps Rule 1: Untagged images are pure waste. When you push 'latest' over an existing image,
					// the old image loses its tag but stays in storage, costing money forever.
					if s.FlagUntagged && len(image.ImageTags) == 0 {
						isOrphaned = true
						recommendation = "Delete Untagged Image"
					} else {
						// FinOps Rule 2: Even if tagged, images older than 180 days are often stale CI/CD artifacts.
						if image.ImagePushedAt != nil {
							daysOld := int(time.Since(*image.ImagePushedAt).Hours() / 24)
							if daysOld > s.RetentionDays {
								isOrphaned = true
								recommendation = fmt.Sprintf("Review and Delete Stale Image (>%d days old)", s.RetentionDays)
							}
						}
					}

					sizeMB := float64(aws.ToInt64(image.ImageSizeInBytes)) / 1024 / 1024
					cost := (sizeMB / 1024) * 0.10 // $0.10/GB-month

					metrics := map[string]interface{}{
						"Repository":           repoName,
						"SizeMB":               sizeMB,
						"Tags":                 image.ImageTags,
						"EstimatedMonthlyCost": cost,
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

					results = append(results, scanner.ScanResult{
						ResourceID:   aws.ToString(image.ImageDigest),
						ResourceType: "ECR_IMAGE",
						Region:       "global",
						IsOrphaned:   isOrphaned,
						Metrics:      metrics,
					})
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
		keys = append(keys, fmt.Sprintf("%s:%s", repoName, tag))
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
		case []scanner.ScanResult:
			for _, r := range v {
				matched := false
				for _, k := range keys {
					if strings.Contains(r.ResourceID, k) {
						matched = true
						break
					}
				}
				if matched {
					if strings.EqualFold(r.Severity, "CRITICAL") {
						critCount++
					} else if strings.EqualFold(r.Severity, "HIGH") {
						highCount++
					}
				}
			}
		case map[string][]model.SecurityFinding:
			for _, k := range keys {
				if flist, ok := v[k]; ok {
					for _, f := range flist {
						if strings.EqualFold(f.Severity, "CRITICAL") {
							critCount++
						} else if strings.EqualFold(f.Severity, "HIGH") {
							highCount++
						}
					}
				}
			}
		case map[string][]scanner.ScanResult:
			for _, k := range keys {
				if rlist, ok := v[k]; ok {
					for _, r := range rlist {
						if strings.EqualFold(r.Severity, "CRITICAL") {
							critCount++
						} else if strings.EqualFold(r.Severity, "HIGH") {
							highCount++
						}
					}
				}
			}
		}
	}

	return critCount, highCount
}
