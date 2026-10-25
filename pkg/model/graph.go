package model

// Node represents a resource vertex in the attack topology.
type Node struct {
	ID       string                 `json:"id"`
	NodeType string                 `json:"node_type"`
	Data     map[string]interface{} `json:"data,omitempty"`
}

// Edge represents an access or network path relationship between nodes.
type Edge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Relation string `json:"relation"`
}
