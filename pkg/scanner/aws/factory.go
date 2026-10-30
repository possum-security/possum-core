package aws

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/possum-security/possum-core/pkg/scanner"
	"github.com/possum-security/possum-core/pkg/scanner/aws/finops"
	"github.com/possum-security/possum-core/pkg/scanner/aws/secaas"
)

// GetRegionalScanners returns all resource scanners that run on a per-region basis.
func GetRegionalScanners(cfg aws.Config, ecrRetentionDays int, flagUntaggedECR bool) []scanner.Scanner {
	return []scanner.Scanner{
		finops.NewEIPScanner(cfg),
		finops.NewEBSScanner(cfg),
		finops.NewEC2Scanner(cfg),
		finops.NewRDSScanner(cfg),
		finops.NewNATGatewayScanner(cfg),
		finops.NewELBScanner(cfg),
		finops.NewECRScanner(cfg, ecrRetentionDays, flagUntaggedECR),
		finops.NewLambdaScanner(cfg),
		finops.NewECSScanner(cfg),
		finops.NewCloudFormationScanner(cfg),
		finops.NewDynamoDBScanner(cfg),
		finops.NewRedshiftScanner(cfg),
		finops.NewENIScanner(cfg),
		secaas.NewLambdaScanner(cfg),
		secaas.NewDynamoDBScanner(cfg),
		secaas.NewVPCScanner(cfg),
		secaas.NewKMSScanner(cfg),
		secaas.NewAPIGatewayScanner(cfg),
		secaas.NewRDSScanner(cfg),
		secaas.NewELBScanner(cfg),
		secaas.NewMessagingScanner(cfg),
		secaas.NewEKSScanner(cfg),
		secaas.NewCognitoScanner(cfg),
		secaas.NewCloudFormationScanner(cfg),
		secaas.NewACMScanner(cfg),
		secaas.NewVPCAdvancedScanner(cfg),
		secaas.NewCloudWatchScanner(cfg),
		secaas.NewEC2Scanner(cfg),
		secaas.NewAccessAnalyzerScanner(cfg),
		secaas.NewConfigServiceScanner(cfg),
		secaas.NewMacieScanner(cfg),
		secaas.NewGuardDutyScanner(cfg),
		secaas.NewOpenSearchScanner(cfg),
		secaas.NewECRSecScanner(cfg),
		secaas.NewECSSecScanner(cfg),
		secaas.NewSecretsManagerScanner(cfg),
		secaas.NewGlueScanner(cfg),
		secaas.NewRedshiftScanner(cfg),
		secaas.NewNeptuneScanner(cfg),
		secaas.NewBedrockScanner(cfg),
		secaas.NewSageMakerScanner(cfg),
		secaas.NewBackupScanner(cfg),
		secaas.NewSecurityHubScanner(cfg),
		secaas.NewWAFv2Scanner(cfg),
		secaas.NewEFSScanner(cfg),
		secaas.NewDMSScanner(cfg),
		secaas.NewKafkaScanner(cfg),
		secaas.NewCodeBuildScanner(cfg),
		secaas.NewStepFunctionsScanner(cfg),
		secaas.NewEventBridgeScanner(cfg),
		secaas.NewElastiCacheScanner(cfg),
		secaas.NewDocumentDBScanner(cfg),
		secaas.NewAutoScalingScanner(cfg),
	}
}

// GetGlobalScanners returns all scanners that run globally across an AWS account.
func GetGlobalScanners(cfg aws.Config) []scanner.Scanner {
	return []scanner.Scanner{
		finops.NewCostExplorerScanner(cfg, 30),
		finops.NewCloudFrontScanner(cfg),
		finops.NewS3Scanner(cfg),
		secaas.NewIAMScanner(cfg),
		secaas.NewS3Scanner(cfg),
		secaas.NewCloudTrailScanner(cfg),
		secaas.NewCloudFrontScanner(cfg),
		secaas.NewRoute53Scanner(cfg),
		secaas.NewAccountScanner(cfg),
	}
}

// GetAllScanners returns both regional and global scanners.
func GetAllScanners(cfg aws.Config) []scanner.Scanner {
	scanners := GetRegionalScanners(cfg, 180, true)
	return append(scanners, GetGlobalScanners(cfg)...)
}
