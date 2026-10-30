package aws

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/possum-security/possum-core/pkg/rules"
	"github.com/possum-security/possum-core/pkg/scanner"
	"github.com/possum-security/possum-core/pkg/scanner/aws/finops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAllScanners_RegistrationAndCatalogAlignment(t *testing.T) {
	cfg := aws.Config{Region: "us-east-1"}
	allScanners := GetAllScanners(cfg)
	require.NotEmpty(t, allScanners)

	catalog := rules.GetDefaultCatalog()
	require.NotNil(t, catalog)

	registeredIDs := make(map[string]bool)
	registeredNames := make(map[string]bool)
	advertisedChecks := make(map[string]bool)

	for _, sc := range allScanners {
		metaScanner, ok := sc.(scanner.MetaScanner)
		require.True(t, ok, "Scanner %s must implement scanner.MetaScanner", sc.Name())

		meta := metaScanner.Meta()
		assert.NotEmpty(t, meta.ID, "Scanner %s must have non-empty Meta().ID", sc.Name())
		assert.NotEmpty(t, meta.Service, "Scanner %s must have non-empty Meta().Service", sc.Name())
		assert.NotEmpty(t, meta.CheckIDs, "Scanner %s must have non-empty Meta().CheckIDs", sc.Name())

		registeredIDs[meta.ID] = true
		registeredNames[sc.Name()] = true

		for _, checkID := range meta.CheckIDs {
			advertisedChecks[checkID] = true
			chk, exists := catalog.GetCheck(checkID)
			if assert.True(t, exists, "CheckID %q from scanner %s is missing from rules.GetDefaultCatalog()", checkID, sc.Name()) {
				assert.NotEmpty(t, chk.CheckID, "CheckID %q has empty CheckID", checkID)
				assert.NotEmpty(t, chk.CheckTitle, "CheckID %q has empty CheckTitle", checkID)
				assert.NotEmpty(t, chk.ServiceName, "CheckID %q has empty ServiceName", checkID)
				assert.NotEmpty(t, chk.Severity, "CheckID %q has empty Severity", checkID)
				assert.NotEmpty(t, chk.Categories, "CheckID %q has empty Categories", checkID)
				assert.NotEmpty(t, chk.Description, "CheckID %q has empty Description", checkID)
				assert.NotEmpty(t, chk.Risk, "CheckID %q has empty Risk", checkID)
				hasRemediation := chk.Remediation.Recommendation.Text != "" || chk.Remediation.Code.CLI != "" || chk.Remediation.Code.Terraform != ""
				assert.True(t, hasRemediation, "CheckID %q has empty Remediation", checkID)
			}
		}
	}

	// Verify all 12 previously-orphaned SecaaS scanners are registered
	expectedOrphanedIDs := []string{
		"backup-scanner",
		"securityhub-scanner",
		"wafv2-scanner",
		"efs-scanner",
		"dms-scanner",
		"kafka-scanner",
		"codebuild-scanner",
		"stepfunctions-scanner",
		"eventbridge-scanner",
		"elasticache-scanner",
		"documentdb-scanner",
		"autoscaling-scanner",
	}
	for _, id := range expectedOrphanedIDs {
		assert.True(t, registeredIDs[id], "Expected scanner %q to be registered in GetAllScanners", id)
	}

	// Verify all FinOps Rule* constants exist in catalog and are advertised
	finopsRuleIDs := []string{
		finops.RuleEBSVolumeUnused,
		finops.RuleEBSSnapshotOrphaned,
		finops.RuleEC2InstanceIdle,
		finops.RuleEIPUnassigned,
		finops.RuleNATGatewayIdle,
		finops.RuleRDSInstanceIdle,
		finops.RuleELBLoadBalancerIdle,
		finops.RuleLambdaFunctionUnused,
		finops.RuleENIDetachedUnused,
		finops.RuleCloudFormationStackFailedOrAbandoned,
		finops.RuleDynamoDBProvisionedCapacityUnused,
		finops.RuleRedshiftClusterIdle,
		finops.RuleCloudFrontDistributionUnused,
		finops.RuleS3BucketLifecycleMissing,
		finops.RuleCostExplorerSpendTracked,
		finops.RuleECRImageUntaggedOrStale,
		finops.RuleECSServiceIdle,
	}
	for _, ruleID := range finopsRuleIDs {
		_, exists := catalog.GetCheck(ruleID)
		assert.True(t, exists, "FinOps rule %q must exist in rules.GetDefaultCatalog()", ruleID)
		assert.True(t, advertisedChecks[ruleID], "FinOps rule %q must be advertised in GetAllScanners CheckIDs", ruleID)
	}

	// Parse AST of all scanner files in finops/ and secaas/ to ensure every emitted RuleID is in catalog and advertised
	files, err := filepath.Glob("secaas/*.go")
	require.NoError(t, err)
	finopsFiles, err := filepath.Glob("finops/*.go")
	require.NoError(t, err)
	files = append(files, finopsFiles...)

	fset := token.NewFileSet()
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		node, err := parser.ParseFile(fset, file, nil, 0)
		require.NoError(t, err)

		ast.Inspect(node, func(n ast.Node) bool {
			kv, ok := n.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			ident, ok := kv.Key.(*ast.Ident)
			if !ok || (ident.Name != "RuleID" && ident.Name != "ruleID" && ident.Name != "checkID") {
				return true
			}
			lit, ok := kv.Value.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			ruleID := strings.Trim(lit.Value, `"`)
			if ruleID != "" {
				_, exists := catalog.GetCheck(ruleID)
				assert.True(t, exists, "Emitted RuleID %q in %s is missing from rules.GetDefaultCatalog()", ruleID, file)
				assert.True(t, advertisedChecks[ruleID], "Emitted RuleID %q in %s is missing from Meta().CheckIDs", ruleID, file)
			}
			return true
		})
	}
}
