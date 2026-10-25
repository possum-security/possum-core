package rules

import (
	"encoding/json"
	"strings"
)

// RemediationCode encapsulates remediation code snippets.
type RemediationCode struct {
	CLI       string `json:"cli"`
	NativeIaC string `json:"native_iac"`
	Other     string `json:"other"`
	Terraform string `json:"terraform"`
}

func (c *RemediationCode) UnmarshalJSON(data []byte) error {
	var raw struct {
		CLI            string `json:"CLI"`
		NativeIaC      string `json:"NativeIaC"`
		Other          string `json:"Other"`
		Terraform      string `json:"Terraform"`
		CLISnake       string `json:"cli"`
		NativeIaCSnake string `json:"native_iac"`
		OtherSnake     string `json:"other"`
		TerraformSnake string `json:"terraform"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	c.CLI = raw.CLI
	if c.CLI == "" {
		c.CLI = raw.CLISnake
	}
	c.NativeIaC = raw.NativeIaC
	if c.NativeIaC == "" {
		c.NativeIaC = raw.NativeIaCSnake
	}
	c.Other = raw.Other
	if c.Other == "" {
		c.Other = raw.OtherSnake
	}
	c.Terraform = raw.Terraform
	if c.Terraform == "" {
		c.Terraform = raw.TerraformSnake
	}
	return nil
}

// RemediationRecommendation encapsulates remediation guidance and documentation link.
type RemediationRecommendation struct {
	Text string `json:"text"`
	Url  string `json:"url"`
}

func (r *RemediationRecommendation) UnmarshalJSON(data []byte) error {
	var raw struct {
		Text      string `json:"Text"`
		Url       string `json:"Url"`
		TextSnake string `json:"text"`
		UrlSnake  string `json:"url"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.Text = raw.Text
	if r.Text == "" {
		r.Text = raw.TextSnake
	}
	r.Url = raw.Url
	if r.Url == "" {
		r.Url = raw.UrlSnake
	}
	return nil
}

// CheckRemediation provides both manual/scripted code and recommendation details.
type CheckRemediation struct {
	Code           RemediationCode           `json:"code"`
	Recommendation RemediationRecommendation `json:"recommendation"`
}

func (cr *CheckRemediation) UnmarshalJSON(data []byte) error {
	var raw struct {
		Code           RemediationCode           `json:"Code"`
		Recommendation RemediationRecommendation `json:"Recommendation"`
		CodeSnake      RemediationCode           `json:"code"`
		RecSnake       RemediationRecommendation `json:"recommendation"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	cr.Code = raw.Code
	if cr.Code.CLI == "" && cr.Code.Terraform == "" && cr.Code.Other == "" && cr.Code.NativeIaC == "" {
		cr.Code = raw.CodeSnake
	}
	cr.Recommendation = raw.Recommendation
	if cr.Recommendation.Text == "" && cr.Recommendation.Url == "" {
		cr.Recommendation = raw.RecSnake
	}
	return nil
}

// CheckMetadata represents security check metadata.
type CheckMetadata struct {
	CheckID              string           `json:"check_id"`
	CheckTitle           string           `json:"check_title"`
	ServiceName          string           `json:"service_name"`
	SubServiceName       string           `json:"sub_service_name"`
	Severity             string           `json:"severity"`
	ResourceType         string           `json:"resource_type"`
	Description          string           `json:"description"`
	Risk                 string           `json:"risk"`
	Remediation          CheckRemediation `json:"remediation"`
	Categories           []string         `json:"categories"`
	ComplianceFrameworks []string         `json:"compliance_frameworks"`
}

func (m *CheckMetadata) UnmarshalJSON(data []byte) error {
	var raw struct {
		CheckID                   string           `json:"CheckID"`
		CheckTitle                string           `json:"CheckTitle"`
		ServiceName               string           `json:"ServiceName"`
		SubServiceName            string           `json:"SubServiceName"`
		Severity                  string           `json:"Severity"`
		ResourceType              string           `json:"ResourceType"`
		Description               string           `json:"Description"`
		Risk                      string           `json:"Risk"`
		Remediation               CheckRemediation `json:"Remediation"`
		Categories                []string         `json:"Categories"`
		ComplianceFrameworks      []string         `json:"ComplianceFrameworks"`
		CheckIDSnake              string           `json:"check_id"`
		CheckTitleSnake           string           `json:"check_title"`
		ServiceNameSnake          string           `json:"service_name"`
		SubServiceNameSnake       string           `json:"sub_service_name"`
		SeveritySnake             string           `json:"severity"`
		ResourceTypeSnake         string           `json:"resource_type"`
		DescriptionSnake          string           `json:"description"`
		RiskSnake                 string           `json:"risk"`
		RemediationSnake          CheckRemediation `json:"remediation"`
		CategoriesSnake           []string         `json:"categories"`
		ComplianceFrameworksSnake []string         `json:"compliance_frameworks"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	m.CheckID = raw.CheckID
	if m.CheckID == "" {
		m.CheckID = raw.CheckIDSnake
	}
	m.CheckTitle = raw.CheckTitle
	if m.CheckTitle == "" {
		m.CheckTitle = raw.CheckTitleSnake
	}
	m.ServiceName = raw.ServiceName
	if m.ServiceName == "" {
		m.ServiceName = raw.ServiceNameSnake
	}
	m.SubServiceName = raw.SubServiceName
	if m.SubServiceName == "" {
		m.SubServiceName = raw.SubServiceNameSnake
	}
	m.Severity = strings.ToUpper(raw.Severity)
	if m.Severity == "" {
		m.Severity = strings.ToUpper(raw.SeveritySnake)
	}
	m.ResourceType = raw.ResourceType
	if m.ResourceType == "" {
		m.ResourceType = raw.ResourceTypeSnake
	}
	m.Description = raw.Description
	if m.Description == "" {
		m.Description = raw.DescriptionSnake
	}
	m.Risk = raw.Risk
	if m.Risk == "" {
		m.Risk = raw.RiskSnake
	}
	m.Remediation = raw.Remediation
	if m.Remediation.Code.CLI == "" && m.Remediation.Code.Terraform == "" && m.Remediation.Recommendation.Text == "" {
		m.Remediation = raw.RemediationSnake
	}
	m.Categories = raw.Categories
	if len(m.Categories) == 0 {
		m.Categories = raw.CategoriesSnake
	}
	m.ComplianceFrameworks = raw.ComplianceFrameworks
	if len(m.ComplianceFrameworks) == 0 {
		m.ComplianceFrameworks = raw.ComplianceFrameworksSnake
	}
	return nil
}

// CheckFilter defines criteria for listing checks from RuleCatalog.
type CheckFilter struct {
	ServiceName  string
	Severity     string
	ResourceType string
	Search       string
	Limit        int
	Offset       int
}
