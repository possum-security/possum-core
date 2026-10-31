module github.com/possum-security/possum-core

go 1.26.5

require (
	github.com/aws/aws-sdk-go-v2 v1.47.5
	github.com/aws/aws-sdk-go-v2/config v1.33.9
	github.com/aws/aws-sdk-go-v2/credentials v1.20.9
	github.com/aws/aws-sdk-go-v2/service/accessanalyzer v1.57.5
	github.com/aws/aws-sdk-go-v2/service/account v1.42.4
	github.com/aws/aws-sdk-go-v2/service/acm v1.50.5
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.52.2
	github.com/aws/aws-sdk-go-v2/service/apigatewayv2 v1.46.2
	github.com/aws/aws-sdk-go-v2/service/autoscaling v1.79.0
	github.com/aws/aws-sdk-go-v2/service/backup v1.69.2
	github.com/aws/aws-sdk-go-v2/service/bedrock v1.74.0
	github.com/aws/aws-sdk-go-v2/service/cloudformation v1.82.1
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.75.1
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.65.5
	github.com/aws/aws-sdk-go-v2/service/cloudwatch v1.75.0
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.90.1
	github.com/aws/aws-sdk-go-v2/service/codebuild v1.78.5
	github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider v1.75.4
	github.com/aws/aws-sdk-go-v2/service/configservice v1.74.5
	github.com/aws/aws-sdk-go-v2/service/costexplorer v1.74.2
	github.com/aws/aws-sdk-go-v2/service/databasemigrationservice v1.75.2
	github.com/aws/aws-sdk-go-v2/service/docdb v1.57.4
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.72.0
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.340.0
	github.com/aws/aws-sdk-go-v2/service/ecr v1.66.5
	github.com/aws/aws-sdk-go-v2/service/ecs v1.102.0
	github.com/aws/aws-sdk-go-v2/service/efs v1.50.0
	github.com/aws/aws-sdk-go-v2/service/eks v1.104.2
	github.com/aws/aws-sdk-go-v2/service/elasticache v1.64.0
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.63.4
	github.com/aws/aws-sdk-go-v2/service/eventbridge v1.55.4
	github.com/aws/aws-sdk-go-v2/service/glue v1.172.0
	github.com/aws/aws-sdk-go-v2/service/guardduty v1.101.0
	github.com/aws/aws-sdk-go-v2/service/iam v1.64.4
	github.com/aws/aws-sdk-go-v2/service/kafka v1.65.5
	github.com/aws/aws-sdk-go-v2/service/kms v1.61.5
	github.com/aws/aws-sdk-go-v2/service/lambda v1.113.2
	github.com/aws/aws-sdk-go-v2/service/macie2 v1.59.4
	github.com/aws/aws-sdk-go-v2/service/neptune v1.53.4
	github.com/aws/aws-sdk-go-v2/service/opensearch v1.86.0
	github.com/aws/aws-sdk-go-v2/service/organizations v1.62.3
	github.com/aws/aws-sdk-go-v2/service/rds v1.131.1
	github.com/aws/aws-sdk-go-v2/service/redshift v1.71.4
	github.com/aws/aws-sdk-go-v2/service/route53 v1.70.4
	github.com/aws/aws-sdk-go-v2/service/s3 v1.114.4
	github.com/aws/aws-sdk-go-v2/service/s3control v1.79.4
	github.com/aws/aws-sdk-go-v2/service/sagemaker v1.284.1
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.50.5
	github.com/aws/aws-sdk-go-v2/service/securityhub v1.85.1
	github.com/aws/aws-sdk-go-v2/service/sfn v1.52.0
	github.com/aws/aws-sdk-go-v2/service/sns v1.47.5
	github.com/aws/aws-sdk-go-v2/service/sqs v1.52.5
	github.com/aws/aws-sdk-go-v2/service/sts v1.51.4
	github.com/aws/aws-sdk-go-v2/service/wafv2 v1.83.6
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.9
	github.com/stretchr/testify v1.12.1
	golang.org/x/sync v0.24.0
	golang.org/x/time v0.16.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.23 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.20.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.8 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.8 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.22 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.11.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.13.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.20.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.10.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.38.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.43.4 // indirect
	github.com/aws/smithy-go v1.28.7 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
)
