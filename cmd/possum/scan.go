package main

import (
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Execute cloud security or FinOps scans",
}

func init() {
	scanCmd.AddCommand(scanAWSCmd)
}
