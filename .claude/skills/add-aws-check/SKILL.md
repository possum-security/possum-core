---
name: add-aws-check
description: End-to-end workflow for adding a new AWS SecaaS or FinOps scanner check, rule metadata, remediation template, and unit tests in possum-core.
---

# Adding an AWS SecaaS or FinOps Check in `possum-core`

Use this skill whenever implementing a new AWS security (`SecaaS`) or cost-optimization (`FinOps`) check, registering its metadata, wiring CLI remediation, and writing unit tests.

## Architecture & Key Types

- **Core Result & Metadata Models**:
  - `model.ScanResult` (`pkg/model/result.go`) — aliased as `scanner.ScanResult` (`pkg/scanner/scanner.go`).
  - `scanner.Scanner` & `scanner.MetaScanner` (`pkg/scanner/scanner.go`) — requires `Name() string`, `Scan(ctx context.Context) ([]scanner.ScanResult, error)`, and `Meta() scanner.ScannerMeta`.
  - `finops.FinOpsResultParams` & `finops.BuildFinOpsResult` (`pkg/scanner/aws/finops/rules.go`) — canonical builder for FinOps findings.
  - `rules.CheckMetadata`, `rules.CheckRemediation`, `rules.RemediationCode`, `rules.RemediationRecommendation` (`pkg/rules/types.go`) — schema for `pkg/rules/embedded/index.json`.
  - `custom.Rule`, `custom.StructuredCondition`, `custom.ConditionNode` (`pkg/rules/custom/types.go`) — schema for declarative YAML custom rules.
  - `remediation.DeriveCLICommand` & `remediation.Generator` (`pkg/remediation/remediation.go`) — automated bash remediation script generator.

---

## Step 1: Implement the Scanner Check

### Option A: SecaaS Security Check (`pkg/scanner/aws/secaas/<service>.go`)

1. Define a minimal read-only AWS SDK v2 client interface (`<Service>Client`) for dependency injection.
2. Provide `New<Service>Scanner(cfg aws.Config)` and `New<Service>ScannerWithClient(client <Service>Client, region string)`.
3. Implement `Meta() scanner.ScannerMeta` with `Category: model.CategorySecOps` and all emitted rule IDs in `CheckIDs`.
4. Use SDK paginators, honor `ResourceLimit` from `ctx`, safely dereference SDK pointers (`aws.ToString`, `aws.ToBool`, etc.), and emit both `PASS` (`Severity: "INFO"`) and `FAIL` results.

```go
package secaas

import (
	"context"
	"fmt"

	graph "github.com/amirmahdy/possum-core/pkg/model"
	"github.com/amirmahdy/possum-core/pkg/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type KMSClient interface {
	ListKeys(ctx context.Context, params *kms.ListKeysInput, optFns ...func(*kms.Options)) (*kms.ListKeysOutput, error)
	GetKeyRotationStatus(ctx context.Context, params *kms.GetKeyRotationStatusInput, optFns ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error)
}

type KMSScanner struct {
	client KMSClient
	region string
}

func NewKMSScanner(cfg aws.Config) *KMSScanner {
	return &KMSScanner{client: kms.NewFromConfig(cfg), region: cfg.Region}
}

func NewKMSScannerWithClient(client KMSClient, region string) *KMSScanner {
	return &KMSScanner{client: client, region: region}
}

func (s *KMSScanner) Name() string { return "KMS-SecaaS-Scanner" }

func (s *KMSScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "kms-scanner",
		Name:          s.Name(),
		Category:      graph.CategorySecOps,
		Scope:         graph.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "kms",
		CheckIDs:      []string{"kms_cmk_rotation_enabled"},
	}
}

func (s *KMSScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := scanner.GetResourceLimit(ctx)
	processedCount := 0
	var results []scanner.ScanResult
	region := s.region
	if region == "" {
		region = "global"
	}

	paginator := kms.NewListKeysPaginator(s.client, &kms.ListKeysInput{})
	for paginator.HasMorePages() {
		if scanner.ShouldStop(ctx, processedCount, limit) {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, key := range page.Keys {
			if scanner.ShouldStop(ctx, processedCount, limit) {
				break
			}
			processedCount++
			keyID := aws.ToString(key.KeyId)
			keyARN := aws.ToString(key.KeyArn)

			rotOut, err := s.client.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{
				KeyId: aws.String(keyID),
			})
			if err == nil && rotOut != nil && rotOut.KeyRotationEnabled {
				results = append(results, scanner.ScanResult{
					ResourceID:   keyID,
					ResourceType: "SecaaS-KMSKey",
					Region:       region,
					Status:       graph.StatusPass,
					RuleID:       "kms_cmk_rotation_enabled",
					Severity:     graph.SeverityInfo,
					Metrics: map[string]interface{}{
						"KeyId":          keyID,
						"StatusExtended": fmt.Sprintf("KMS key %s has rotation enabled.", keyID),
					},
					Nodes: []graph.Node{{ID: keyARN, NodeType: "SecaaS-KMSKey"}},
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   keyID,
					ResourceType: "SecaaS-KMSKey",
					Region:       region,
					Status:       graph.StatusFail,
					RuleID:       "kms_cmk_rotation_enabled",
					Severity:     graph.SeverityMedium,
					Metrics: map[string]interface{}{
						"KeyId":          keyID,
						"StatusExtended": fmt.Sprintf("KMS key %s does not have rotation enabled.", keyID),
						"SecurityIssues": []string{"Key rotation disabled"},
						"Recommendation": "Enable automatic annual key rotation.",
					},
					Nodes: []graph.Node{{ID: keyARN, NodeType: "SecaaS-KMSKey"}},
				})
			}
		}
	}
	return results, nil
}
```

### Option B: FinOps Cost Optimization Check (`pkg/scanner/aws/finops/<service>.go`)

1. Add the rule ID constant in `pkg/scanner/aws/finops/rules.go` (e.g., `RuleEBSVolumeUnused = "ebs_volume_unused_attached"`).
2. Implement `MetaScanner` with `var _ scanner.MetaScanner = (*<Service>Scanner)(nil)` and `Category: model.CategoryFinOps`.
3. Use `BuildFinOpsResult(FinOpsResultParams{...})` so `Status`, `Severity`, `CostWasteMo`, and `Metrics["DisplayName"]` follow FinOps conventions automatically.

```go
results = append(results, BuildFinOpsResult(FinOpsResultParams{
	ResourceID:   volID,
	ResourceType: "EBS_VOLUME",
	Region:       aws.ToString(volume.AvailabilityZone),
	RuleID:       RuleEBSVolumeUnused,
	DisplayName:  volID,
	IsOrphaned:   isOrphaned,
	Cost:         cost,
	Title:        title,
	Description:  desc,
	Remediation:  remediation,
	Metrics:      metrics,
}))
```

---

## Step 2: Register Scanner in Factory & Meta Contract Tests

If you created a new scanner struct:
1. Add `New<Service>Scanner(cfg)` to `GetRegionalScanners` or `GetGlobalScanners` in `pkg/scanner/aws/factory.go`.
2. Add `New<Service>Scanner(dummyCfg)` to:
   - `TestSecaaS_AllScannersImplementMetaScanner` in `pkg/scanner/aws/secaas/meta_test.go` (for SecaaS), or
   - `TestFinOps_MetaScannersContract` in `pkg/scanner/aws/finops/rules_test.go` (for FinOps).

---

## Step 3: Register Rule Metadata in `pkg/rules/embedded/index.json`

Add the rule definition under `"checks"` in `pkg/rules/embedded/index.json` matching `rules.CheckMetadata` (`pkg/rules/types.go`) so `RuleCatalog.EnrichResults` enriches scan findings with titles, descriptions, remediation snippets, and compliance frameworks:

```json
"<rule_id>": {
  "CheckID": "<rule_id>",
  "CheckTitle": "Human-readable title of the check",
  "ServiceName": "<service>",
  "SubServiceName": "",
  "Severity": "medium",
  "ResourceType": "AwsResourceType",
  "Description": "Detailed description of what is evaluated.",
  "Risk": "Security or financial risk if left unaddressed.",
  "Remediation": {
    "Code": {
      "CLI": "aws <service> <action> --resource-id <id>",
      "NativeIaC": "",
      "Other": "Console remediation steps",
      "Terraform": ""
    },
    "Recommendation": {
      "Text": "Actionable remediation guidance.",
      "Url": "https://docs.aws.amazon.com/"
    }
  },
  "Categories": ["security"],
  "ComplianceFrameworks": ["cis_3.0_aws", "soc2"]
}
```

---

## Step 4: Wire CLI Remediation in `pkg/remediation/remediation.go`

If the finding can be remediated via an AWS CLI command, add a `case` in `DeriveCLICommand(r model.ScanResult) string` in `pkg/remediation/remediation.go`:

```go
case "<rule_id>":
	return fmt.Sprintf("aws <service> <subcommand> --id %s%s", r.ResourceID, regionFlag)
```

---

## Step 5: Write Unit Tests & Verify

1. Create or update `pkg/scanner/aws/<secaas|finops>/<service>_test.go` using `New<Service>ScannerWithClient` and a mock struct implementing `<Service>Client`.
2. Test both compliant (`PASS`) and non-compliant (`FAIL`) scenarios, nil field handling, and error propagation.
3. Run verification:
   ```bash
   go test -v -race ./pkg/scanner/aws/... ./pkg/rules/... ./pkg/remediation/...
   golangci-lint run ./...
   make build
   ```
