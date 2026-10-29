package output

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/amirmahdy/possum-core/pkg/model"
)

var idSanitizer = regexp.MustCompile(`[^a-zA-Z0-9_]`)

// MermaidFormatter renders scan findings and topology graphs in Mermaid syntax.
type MermaidFormatter struct{}

// NewMermaidFormatter creates a new Mermaid graph formatter.
func NewMermaidFormatter() *MermaidFormatter {
	return &MermaidFormatter{}
}

// Format writes Mermaid graph representation to the provided writer.
func (f *MermaidFormatter) Format(writer io.Writer, results []model.ScanResult) error {
	nodesMap := make(map[string]model.Node)
	edgesSet := make(map[string]model.Edge)

	for _, r := range results {
		// Collect explicit nodes
		for _, n := range r.Nodes {
			if n.ID != "" {
				nodesMap[n.ID] = n
			}
		}
		// Collect explicit edges
		for _, e := range r.Edges {
			if e.From != "" && e.To != "" {
				key := fmt.Sprintf("%s->%s:%s", e.From, e.To, e.Relation)
				edgesSet[key] = e
			}
		}

		// Synthesize attack path topology from findings if no explicit edges
		if len(r.Edges) == 0 && r.Status == model.StatusFail {
			resNodeID := r.ResourceID
			if resNodeID != "" {
				if _, exists := nodesMap[resNodeID]; !exists {
					nodesMap[resNodeID] = model.Node{
						ID:       resNodeID,
						NodeType: r.ResourceType,
					}
				}

				// If public-facing or critical misconfiguration
				if strings.Contains(strings.ToLower(r.RuleID), "public") || strings.Contains(strings.ToLower(r.RuleID), "open") {
					internetNode := "INTERNET"
					nodesMap[internetNode] = model.Node{ID: internetNode, NodeType: "ThreatActor"}
					edgeKey := fmt.Sprintf("%s->%s:exposes", internetNode, resNodeID)
					edgesSet[edgeKey] = model.Edge{
						From:     internetNode,
						To:       resNodeID,
						Relation: "exposes",
					}
				}
			}
		}
	}

	var sb strings.Builder
	sb.WriteString("```mermaid\n")
	sb.WriteString("flowchart TD\n")
	sb.WriteString("    %% Styling\n")
	sb.WriteString("    classDef internet fill:#ff4d4f,stroke:#cf1322,stroke-width:2px,color:#fff;\n")
	sb.WriteString("    classDef resource fill:#1890ff,stroke:#096dd9,stroke-width:1px,color:#fff;\n")
	sb.WriteString("    classDef finding fill:#faad14,stroke:#d48806,stroke-width:1px,color:#000;\n\n")

	// Render Nodes
	for id, node := range nodesMap {
		safeID := sanitizeID(id)
		label := id
		if node.NodeType != "" {
			label = fmt.Sprintf("[%s] %s", node.NodeType, id)
		}
		// Escape quotes for Mermaid
		escapedLabel := strings.ReplaceAll(label, "\"", "'")
		sb.WriteString(fmt.Sprintf("    %s[\"%s\"]\n", safeID, escapedLabel))

		if id == "INTERNET" {
			sb.WriteString(fmt.Sprintf("    class %s internet;\n", safeID))
		} else {
			sb.WriteString(fmt.Sprintf("    class %s resource;\n", safeID))
		}
	}
	sb.WriteString("\n")

	// Render Edges
	for _, edge := range edgesSet {
		fromID := sanitizeID(edge.From)
		toID := sanitizeID(edge.To)
		rel := edge.Relation
		if rel != "" {
			sb.WriteString(fmt.Sprintf("    %s -->|%s| %s\n", fromID, rel, toID))
		} else {
			sb.WriteString(fmt.Sprintf("    %s --> %s\n", fromID, toID))
		}
	}

	sb.WriteString("```\n")

	_, err := io.WriteString(writer, sb.String())
	return err
}

func sanitizeID(raw string) string {
	res := idSanitizer.ReplaceAllString(raw, "_")
	if len(res) > 40 {
		return res[len(res)-40:]
	}
	return res
}
