package secaas

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner"
	"github.com/stretchr/testify/assert"
)

func TestSecaaS_AllScannersImplementMetaScanner(t *testing.T) {
	dummyCfg := aws.Config{Region: "us-east-1"}

	scanners := []scanner.MetaScanner{
		NewAccessAnalyzerScanner(dummyCfg),
		NewAccountScanner(dummyCfg),
		NewACMScanner(dummyCfg),
		NewAPIGatewayScanner(dummyCfg),
		NewAutoScalingScanner(dummyCfg),
		NewBackupScanner(dummyCfg),
		NewBedrockScanner(dummyCfg),
		NewCloudFormationScanner(dummyCfg),
		NewCloudFrontScanner(dummyCfg),
		NewCloudTrailScanner(dummyCfg),
		NewCloudWatchScanner(dummyCfg),
		NewCodeBuildScanner(dummyCfg),
		NewCognitoScanner(dummyCfg),
		NewConfigServiceScanner(dummyCfg),
		NewDMSScanner(dummyCfg),
		NewDocumentDBScanner(dummyCfg),
		NewDynamoDBScanner(dummyCfg),
		NewEC2Scanner(dummyCfg),
		NewECRSecScanner(dummyCfg),
		NewECSSecScanner(dummyCfg),
		NewEFSScanner(dummyCfg),
		NewEKSScanner(dummyCfg),
		NewElastiCacheScanner(dummyCfg),
		NewELBScanner(dummyCfg),
		NewEventBridgeScanner(dummyCfg),
		NewGlueScanner(dummyCfg),
		NewGuardDutyScanner(dummyCfg),
		NewIAMScanner(dummyCfg),
		NewKafkaScanner(dummyCfg),
		NewKMSScanner(dummyCfg),
		NewLambdaScanner(dummyCfg),
		NewMacieScanner(dummyCfg),
		NewMessagingScanner(dummyCfg),
		NewNeptuneScanner(dummyCfg),
		NewOpenSearchScanner(dummyCfg),
		NewRDSScanner(dummyCfg),
		NewRedshiftScanner(dummyCfg),
		NewRoute53Scanner(dummyCfg),
		NewS3Scanner(dummyCfg),
		NewSecretsManagerScanner(dummyCfg),
		NewSecurityHubScanner(dummyCfg),
		NewStepFunctionsScanner(dummyCfg),
		NewVPCScanner(dummyCfg),
		NewVPCAdvancedScanner(dummyCfg),
		NewWAFv2Scanner(dummyCfg),
	}

	for _, sc := range scanners {
		meta := sc.Meta()
		assert.NotEmpty(t, meta.ID, "Scanner %s has empty ID", sc.Name())
		assert.NotEmpty(t, meta.Service, "Scanner %s has empty Service", sc.Name())
		assert.NotEmpty(t, meta.CheckIDs, "Scanner %s has empty CheckIDs", sc.Name())
		assert.Equal(t, model.CategorySecOps, meta.Category, "Scanner %s has incorrect Category", sc.Name())
	}
}
