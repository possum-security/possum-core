package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/possum-sec/possum/pkg/cloudclient"
	"github.com/spf13/cobra"
)

var (
	cloudLoginKey     string
	cloudLoginURL     string
	cloudLoginAccount string
)

var cloudCmd = &cobra.Command{
	Use:   "cloud",
	Short: "Manage connection to Possum SecaaS Platform",
}

var cloudLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate and save API credentials for Possum Cloud",
	RunE: func(cmd *cobra.Command, args []string) error {
		key := cloudLoginKey
		url := cloudLoginURL
		account := cloudLoginAccount

		reader := bufio.NewReader(os.Stdin)

		if key == "" {
			fmt.Print("Enter your Possum API Key (e.g., pos_live_...): ")
			input, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			key = strings.TrimSpace(input)
		}

		if key == "" {
			return fmt.Errorf("API key cannot be empty")
		}

		if url == "" {
			url = "https://app.possum.io"
		}

		if account == "" {
			fmt.Print("Optional - Target Cloud Account ID (press enter to skip): ")
			input, _ := reader.ReadString('\n')
			account = strings.TrimSpace(input)
		}

		cfg := &cloudclient.Config{
			APIKey:    key,
			APIURL:    url,
			AccountID: account,
		}

		if err := cloudclient.SaveConfig(cfg); err != nil {
			return fmt.Errorf("failed to save cloud credentials: %w", err)
		}

		fmt.Println("✅ Successfully connected to Possum Cloud.")
		fmt.Printf("Endpoint: %s\n", url)
		if account != "" {
			fmt.Printf("Account:  %s\n", account)
		}
		fmt.Println("\nYou can now pass '--cloud' to any scan command to sync results:")
		fmt.Println("  possum scan aws --region us-east-1 --cloud")
		return nil
	},
}

var cloudStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "View current Possum Cloud connection settings",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := cloudclient.LoadConfig()
		if err != nil {
			return err
		}

		path, _ := cloudclient.ConfigFilePath()
		fmt.Println("Possum Cloud Connection:")
		fmt.Printf("  Config File: %s\n", path)
		fmt.Printf("  API URL:     %s\n", cfg.APIURL)
		if cfg.AccountID != "" {
			fmt.Printf("  Account ID:  %s\n", cfg.AccountID)
		}

		if cfg.APIKey != "" {
			masked := cfg.APIKey
			if len(masked) > 8 {
				masked = masked[:4] + "..." + masked[len(masked)-4:]
			}
			fmt.Printf("  API Key:     %s (authenticated)\n", masked)
		} else {
			fmt.Println("  API Key:     Not configured. Run 'possum cloud login'")
		}

		return nil
	},
}

var cloudLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Clear stored Possum Cloud credentials",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := cloudclient.ClearConfig(); err != nil {
			return err
		}
		fmt.Println("✅ Successfully disconnected from Possum Cloud.")
		return nil
	},
}

func init() {
	cloudLoginCmd.Flags().StringVar(&cloudLoginKey, "key", "", "Possum SecaaS API key")
	cloudLoginCmd.Flags().StringVar(&cloudLoginURL, "url", "https://app.possum.io", "Possum SecaaS API base URL")
	cloudLoginCmd.Flags().StringVar(&cloudLoginAccount, "account", "", "Target cloud account ID")

	cloudCmd.AddCommand(cloudLoginCmd)
	cloudCmd.AddCommand(cloudStatusCmd)
	cloudCmd.AddCommand(cloudLogoutCmd)
}
