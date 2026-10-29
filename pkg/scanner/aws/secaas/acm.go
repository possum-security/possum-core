package secaas

import (
	"context"
	"fmt"
	"strings"
	"time"

	graph "github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/acm/types"
)

type ACMScanner struct {
	client *acm.Client
}

func NewACMScanner(cfg aws.Config) *ACMScanner {
	return &ACMScanner{
		client: acm.NewFromConfig(cfg),
	}
}

func (s *ACMScanner) Name() string {
	return "ACM-SecaaS-Scanner"
}

func (s *ACMScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult

	paginator := acm.NewListCertificatesPaginator(s.client, &acm.ListCertificatesInput{})
	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, cert := range page.CertificateSummaryList {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			certArn := aws.ToString(cert.CertificateArn)

			descOut, err := s.client.DescribeCertificate(ctx, &acm.DescribeCertificateInput{
				CertificateArn: cert.CertificateArn,
			})
			if err != nil {
				return nil, err
			}

			c := descOut.Certificate
			if c == nil {
				continue
			}

			issues := []string{}

			// Check if expired
			if c.Status == types.CertificateStatusExpired {
				issues = append(issues, "Certificate is expired")
			} else if c.NotAfter != nil && time.Now().After(*c.NotAfter) {
				issues = append(issues, "Certificate is past its NotAfter date")
			}

			// Check overly broad wildcard
			domainName := aws.ToString(c.DomainName)
			if isOverlyBroadWildcard(domainName) {
				issues = append(issues, "Overly broad wildcard certificate (e.g., *.com)")
			}

			// Also check SubjectAlternativeNames for overly broad wildcards
			for _, san := range c.SubjectAlternativeNames {
				if isOverlyBroadWildcard(san) {
					issues = append(issues, "Overly broad wildcard in Subject Alternative Names")
					break // avoid duplicate messages
				}
			}

			if len(issues) > 0 {
				results = append(results, scanner.ScanResult{
					ResourceID:   certArn,
					ResourceType: "SecaaS-ACM",
					Region:       extractRegion(certArn),
					Status:       "FAIL",
					IsOrphaned:   false,
					RuleID:       "acm_certificates_expiration_check",
					Severity:     "HIGH",
					Metrics: map[string]interface{}{
						"DomainName":     domainName,
						"StatusExtended": fmt.Sprintf("ACM certificate %s for domain %s is expired, expiring soon, or has an overly broad wildcard.", certArn, domainName),
						"SecurityIssues": issues,
						"Recommendation": "Revoke and replace expired or overly broad wildcard certificates.",
					},
					Nodes: []graph.Node{{ID: certArn, NodeType: "SecaaS-ACM"}},
				})
			}
		}
	}

	return results, nil
}

func isOverlyBroadWildcard(domain string) bool {
	if !strings.HasPrefix(domain, "*.") {
		return false
	}
	return strings.Count(domain, ".") == 1
}

func extractRegion(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) > 3 {
		return parts[3]
	}
	return "global"
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *ACMScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "acm-scanner",
		Name:          s.Name(),
		Category:      graph.CategorySecOps,
		Scope:         graph.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "acm",
		CheckIDs:      []string{"acm_certificates_expiration_check"},
	}
}
