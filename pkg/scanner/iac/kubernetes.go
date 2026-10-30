package iac

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/possum-security/possum-core/pkg/model"
	"gopkg.in/yaml.v3"
)

var supportedK8sKinds = map[string]bool{
	"Pod":         true,
	"Deployment":  true,
	"StatefulSet": true,
	"DaemonSet":   true,
	"Job":         true,
	"CronJob":     true,
	"ReplicaSet":  true,
}

func isKubernetesMap(doc map[string]interface{}) bool {
	if doc == nil {
		return false
	}
	apiVer, hasAPI := doc["apiVersion"].(string)
	kind, hasKind := doc["kind"].(string)
	if !hasAPI || !hasKind || apiVer == "" || kind == "" {
		return false
	}
	if supportedK8sKinds[kind] {
		return true
	}
	if kind == "List" {
		if _, ok := doc["items"].([]interface{}); ok {
			return true
		}
	}
	return false
}

func scanKubernetesYAML(data []byte, filePath string) ([]model.ScanResult, bool, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var allResults []model.ScanResult
	foundK8s := false
	contentStr := string(data)

	for {
		var rootNode yaml.Node
		if err := dec.Decode(&rootNode); err != nil {
			if err == io.EOF {
				break
			}
			return allResults, foundK8s, err
		}

		rawVal := yamlNodeToInterface(&rootNode)
		rawDoc, ok := rawVal.(map[string]interface{})
		if !ok || !isKubernetesMap(rawDoc) {
			continue
		}

		foundK8s = true
		findings := evaluateKubernetesManifest(rawDoc, filePath, contentStr, &rootNode)
		allResults = append(allResults, findings...)
	}

	return allResults, foundK8s, nil
}

func evaluateKubernetesManifest(doc map[string]interface{}, filePath, content string, rootNode *yaml.Node) []model.ScanResult {
	var results []model.ScanResult

	kind, _ := doc["kind"].(string)
	if kind == "List" {
		if items, ok := doc["items"].([]interface{}); ok {
			for _, item := range items {
				if itemMap, ok := item.(map[string]interface{}); ok {
					results = append(results, evaluateKubernetesManifest(itemMap, filePath, content, nil)...)
				}
			}
		}
		return results
	}

	if !supportedK8sKinds[kind] {
		return nil
	}

	metaName := "default"
	if meta, ok := doc["metadata"].(map[string]interface{}); ok {
		if n, ok := meta["name"].(string); ok && n != "" {
			metaName = n
		}
	}

	resourceID := fmt.Sprintf("%s/%s", kind, metaName)
	baseLine := 1
	if rootNode != nil && rootNode.Line > 0 {
		if len(rootNode.Content) > 0 && rootNode.Content[0].Line > 0 {
			baseLine = rootNode.Content[0].Line
		} else {
			baseLine = rootNode.Line
		}
	} else {
		baseLine = findLineInContent(content, metaName, kind)
	}

	podSpec := extractK8sPodSpec(kind, doc)
	if podSpec == nil {
		return nil
	}

	// 1. Check hostNetwork: true or hostPID: true
	if toBool(podSpec["hostNetwork"]) || toBool(podSpec["hostPID"]) {
		line := baseLine
		if rootNode != nil {
			if l := findYAMLKeyLineRecursive(rootNode, "hostNetwork"); l > 0 {
				line = l
			} else if l := findYAMLKeyLineRecursive(rootNode, "hostPID"); l > 0 {
				line = l
			}
		} else {
			line = findLineInContent(content, "hostNetwork", "hostPID", metaName)
		}

		results = append(results, attachLocation(model.ScanResult{
			ResourceID:   resourceID,
			ResourceType: fmt.Sprintf("k8s_%s", strings.ToLower(kind)),
			RuleID:       "k8s_pod_host_network_or_pid",
			Title:        "Kubernetes Pod Shares Host Network or Host PID Namespace",
			Description:  fmt.Sprintf("Kubernetes %s shares hostNetwork or hostPID namespace.", resourceID),
			Remediation:  "Set hostNetwork: false and hostPID: false in the Pod specification",
			Severity:     model.SeverityHigh,
			Status:       model.StatusFail,
			Category:     model.CategorySecurity,
			EvaluatedAt:  time.Now(),
		}, filePath, line))
	}

	podSecCtx, _ := podSpec["securityContext"].(map[string]interface{})

	// 2. Check containers and initContainers
	for _, field := range []string{"containers", "initContainers"} {
		containers, ok := podSpec[field].([]interface{})
		if !ok {
			continue
		}
		for idx, cRaw := range containers {
			cMap, ok := cRaw.(map[string]interface{})
			if !ok {
				continue
			}
			cName, _ := cMap["name"].(string)
			if cName == "" {
				cName = fmt.Sprintf("container-%d", idx)
			}
			containerResID := fmt.Sprintf("%s/%s", resourceID, cName)
			containerLine := baseLine
			if rootNode != nil {
				if l := findYAMLValueLineRecursive(rootNode, "name", cName); l > 0 {
					containerLine = l
				}
			} else {
				containerLine = findLineInContent(content, cName, metaName)
			}

			secCtx, _ := cMap["securityContext"].(map[string]interface{})

			// Check k8s_container_privileged: securityContext.privileged: true
			if secCtx != nil && toBool(secCtx["privileged"]) {
				line := containerLine
				if rootNode != nil {
					if l := findYAMLKeyLineRecursive(rootNode, "privileged"); l > 0 {
						line = l
					}
				}
				results = append(results, attachLocation(model.ScanResult{
					ResourceID:   containerResID,
					ResourceType: "k8s_container",
					RuleID:       "k8s_container_privileged",
					Title:        "Kubernetes Container Runs in Privileged Mode",
					Description:  fmt.Sprintf("Container %s has securityContext.privileged set to true.", containerResID),
					Remediation:  "Set securityContext.privileged: false on the container specification",
					Severity:     model.SeverityCritical,
					Status:       model.StatusFail,
					Category:     model.CategorySecurity,
					EvaluatedAt:  time.Now(),
				}, filePath, line))
			}

			// Check k8s_container_run_as_root: securityContext.runAsNonRoot: false or runAsUser: 0
			if isK8sContainerRunAsRoot(secCtx, podSecCtx) {
				line := containerLine
				if rootNode != nil {
					if l := findYAMLKeyLineRecursive(rootNode, "runAsUser"); l > 0 {
						line = l
					} else if l := findYAMLKeyLineRecursive(rootNode, "runAsNonRoot"); l > 0 {
						line = l
					}
				}
				results = append(results, attachLocation(model.ScanResult{
					ResourceID:   containerResID,
					ResourceType: "k8s_container",
					RuleID:       "k8s_container_run_as_root",
					Title:        "Kubernetes Container Configured to Run as Root User",
					Description:  fmt.Sprintf("Container %s sets runAsNonRoot: false or runAsUser: 0.", containerResID),
					Remediation:  "Set securityContext.runAsNonRoot: true and a non-zero runAsUser UID",
					Severity:     model.SeverityHigh,
					Status:       model.StatusFail,
					Category:     model.CategorySecurity,
					EvaluatedAt:  time.Now(),
				}, filePath, line))
			}

			// Check k8s_container_missing_resource_limits: missing resources.limits
			resMap, _ := cMap["resources"].(map[string]interface{})
			var limitsMap map[string]interface{}
			if resMap != nil {
				limitsMap, _ = resMap["limits"].(map[string]interface{})
			}
			if len(limitsMap) == 0 {
				results = append(results, attachLocation(model.ScanResult{
					ResourceID:   containerResID,
					ResourceType: "k8s_container",
					RuleID:       "k8s_container_missing_resource_limits",
					Title:        "Kubernetes Container Missing CPU/Memory Resource Limits",
					Description:  fmt.Sprintf("Container %s does not define resources.limits.", containerResID),
					Remediation:  "Define resources.limits.cpu and resources.limits.memory on the container",
					Severity:     model.SeverityMedium,
					Status:       model.StatusFail,
					Category:     model.CategoryFinOps,
					EvaluatedAt:  time.Now(),
				}, filePath, containerLine))
			}
		}
	}

	return results
}

func extractK8sPodSpec(kind string, doc map[string]interface{}) map[string]interface{} {
	spec, ok := doc["spec"].(map[string]interface{})
	if !ok || spec == nil {
		return nil
	}

	switch kind {
	case "Pod":
		return spec
	case "Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet":
		if tmpl, ok := spec["template"].(map[string]interface{}); ok {
			if podSpec, ok := tmpl["spec"].(map[string]interface{}); ok {
				return podSpec
			}
		}
	case "CronJob":
		if jobTmpl, ok := spec["jobTemplate"].(map[string]interface{}); ok {
			if jobSpec, ok := jobTmpl["spec"].(map[string]interface{}); ok {
				if tmpl, ok := jobSpec["template"].(map[string]interface{}); ok {
					if podSpec, ok := tmpl["spec"].(map[string]interface{}); ok {
						return podSpec
					}
				}
			}
		}
	}
	return nil
}

func isK8sContainerRunAsRoot(containerSec, podSec map[string]interface{}) bool {
	if containerSec != nil {
		if rawNonRoot, exists := containerSec["runAsNonRoot"]; exists && rawNonRoot != nil {
			if !toBool(rawNonRoot) {
				return true
			}
		}
		if uid, hasUID := parseIntProp(containerSec, "runAsUser"); hasUID && uid == 0 {
			return true
		}
	}

	if podSec != nil {
		// If container didn't explicitly enforce non-root, check pod-level securityContext
		containerEnforcesNonRoot := containerSec != nil && toBool(containerSec["runAsNonRoot"])
		_, containerHasUID := parseIntProp(containerSec, "runAsUser")
		if !containerEnforcesNonRoot {
			if rawNonRoot, exists := podSec["runAsNonRoot"]; exists && rawNonRoot != nil && !toBool(rawNonRoot) {
				return true
			}
		}
		if !containerHasUID {
			if uid, hasUID := parseIntProp(podSec, "runAsUser"); hasUID && uid == 0 {
				return true
			}
		}
	}

	return false
}

func findYAMLKeyLineRecursive(node *yaml.Node, targetKey string) int {
	if node == nil {
		return 0
	}
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			kNode := node.Content[i]
			vNode := node.Content[i+1]
			if kNode.Value == targetKey {
				return kNode.Line
			}
			if l := findYAMLKeyLineRecursive(vNode, targetKey); l > 0 {
				return l
			}
		}
		return 0
	}
	for _, child := range node.Content {
		if l := findYAMLKeyLineRecursive(child, targetKey); l > 0 {
			return l
		}
	}
	return 0
}

func findYAMLValueLineRecursive(node *yaml.Node, key, targetVal string) int {
	if node == nil {
		return 0
	}
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			kNode := node.Content[i]
			vNode := node.Content[i+1]
			if kNode.Value == key && vNode.Value == targetVal {
				return kNode.Line
			}
			if l := findYAMLValueLineRecursive(vNode, key, targetVal); l > 0 {
				return l
			}
		}
		return 0
	}
	for _, child := range node.Content {
		if l := findYAMLValueLineRecursive(child, key, targetVal); l > 0 {
			return l
		}
	}
	return 0
}
