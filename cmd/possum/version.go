package main

import (
	"fmt"

	"github.com/possum-sec/possum/pkg/version"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version and build details of Possum CLI",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(version.String())
	},
}
