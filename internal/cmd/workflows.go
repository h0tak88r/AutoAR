package cmd

import (
	"fmt"
	"os"

	"github.com/h0tak88r/AutoAR/internal/modules/db"
	"github.com/h0tak88r/AutoAR/internal/modules/fastlook"
	"github.com/h0tak88r/AutoAR/internal/modules/subdomain"
	"github.com/spf13/cobra"
)

var (
	fastlookRunCmd = &cobra.Command{
		Use:   "fastlook",
		Short: "Quick reconnaissance workflow",
		RunE: func(cmd *cobra.Command, args []string) error {
			domain, _ := cmd.Flags().GetString("domain")
			if domain == "" {
				return fmt.Errorf("domain is required")
			}

			scanID := os.Getenv("AUTOAR_CURRENT_SCAN_ID")
			finalStatus := "completed"
			if scanID == "" {
				scanID = fmt.Sprintf("fastlook-%d", os.Getpid())
				_ = db.Init()
				_ = db.CreateScan(&db.ScanRecord{
					ScanID:   scanID,
					ScanType: "fastlook",
					Target:   domain,
					Status:   "running",
				})
				os.Setenv("AUTOAR_CURRENT_SCAN_ID", scanID)
				defer func() {
					_ = db.UpdateScanStatus(scanID, finalStatus)
					os.Unsetenv("AUTOAR_CURRENT_SCAN_ID")
				}()
			}

			_, err := fastlook.RunFastlook(domain, nil)
			if err != nil {
				finalStatus = "failed"
				_ = db.UpdateScanStatus(scanID, "failed")
			}
			return err
		},
	}

	subdomainRunCmd = &cobra.Command{
		Use:   "subdomain",
		Short: "Deep-dive scan on a single subdomain",
		RunE: func(cmd *cobra.Command, args []string) error {
			sub, _ := cmd.Flags().GetString("subdomain")
			if sub == "" {
				return fmt.Errorf("subdomain is required")
			}
			_, err := subdomain.RunSubdomain(sub)
			return err
		},
	}
)

func init() {
	rootCmd.AddCommand(fastlookRunCmd)
	rootCmd.AddCommand(subdomainRunCmd)

	fastlookRunCmd.Flags().StringP("domain", "d", "", "Target domain")
	fastlookRunCmd.MarkFlagRequired("domain")

	subdomainRunCmd.Flags().StringP("subdomain", "s", "", "Target subdomain")
	subdomainRunCmd.MarkFlagRequired("subdomain")
}
