package cmd

import (
	"github.com/h0tak88r/AutoAR/internal/scanner/backup"
	"github.com/h0tak88r/AutoAR/internal/scanner/jwt"
	"github.com/h0tak88r/AutoAR/internal/scanner/s3"
	"github.com/h0tak88r/AutoAR/internal/scanner/zerodays"
	"github.com/spf13/cobra"
)

var (
	backupCmd = &cobra.Command{
		Use:   "backup",
		Short: "Scan for backup files",
		RunE: func(cmd *cobra.Command, args []string) error {
			domain, _ := cmd.Flags().GetString("domain")
			ensureDB()
			setupCurrentScan("backup", domain)
			_, err := backup.Run(backup.Options{Domain: domain, Method: "all", Threads: 50})
			return err
		},
	}

	s3Cmd = &cobra.Command{
		Use:   "s3",
		Short: "S3 bucket enumeration and scanning",
	}

	s3ScanCmd = &cobra.Command{
		Use:   "scan",
		Short: "Scan a specific bucket",
		RunE: func(cmd *cobra.Command, args []string) error {
			bucket, _ := cmd.Flags().GetString("bucket")
			ensureDB()
			setupCurrentScan("s3", bucket)
			return s3.Run(s3.Options{Action: "scan", Bucket: bucket})
		},
	}

	jwtCmd = &cobra.Command{
		Use:   "jwt",
		Short: "JWT token security analysis",
		RunE: func(cmd *cobra.Command, args []string) error {
			token, _ := cmd.Flags().GetString("token")
			ensureDB()
			setupCurrentScan("jwt-analysis", "jwt")
			_, err := jwt.RunScan([]string{token})
			return err
		},
	}

	zerodaysCmd = &cobra.Command{
		Use:   "zerodays",
		Short: "Scan for recent Zero-Day vulnerabilities",
		RunE: func(cmd *cobra.Command, args []string) error {
			domain, _ := cmd.Flags().GetString("domain")
			ensureDB()
			setupCurrentScan("zerodays", domain)
			_, err := zerodays.Run(zerodays.Options{Domain: domain})
			return err
		},
	}

	zerodaysScanCmd = &cobra.Command{
		Use:   "scan",
		Short: "Scan a target for zero-day vulnerabilities",
		RunE: func(cmd *cobra.Command, args []string) error {
			domain, _ := cmd.Flags().GetString("domain")
			subdomain, _ := cmd.Flags().GetString("subdomain")
			threads, _ := cmd.Flags().GetInt("threads")
			silent, _ := cmd.Flags().GetBool("silent")

			target := domain
			if target == "" {
				target = subdomain
			}

			ensureDB()
			setupCurrentScan("zerodays", target)

			opts := zerodays.Options{
				Domain:    domain,
				Subdomain: subdomain,
				Threads:   threads,
				Silent:    silent,
			}
			_, err := zerodays.Run(opts)
			return err
		},
	}
)

func init() {
	rootCmd.AddCommand(backupCmd)
	rootCmd.AddCommand(s3Cmd)
	s3Cmd.AddCommand(s3ScanCmd)
	rootCmd.AddCommand(jwtCmd)
	rootCmd.AddCommand(zerodaysCmd)
	zerodaysCmd.AddCommand(zerodaysScanCmd)

	backupCmd.Flags().StringP("domain", "d", "", "Target domain")
	s3ScanCmd.Flags().StringP("bucket", "b", "", "Bucket name")
	jwtCmd.Flags().StringP("token", "t", "", "JWT token")
	zerodaysCmd.Flags().StringP("domain", "d", "", "Target domain")
	zerodaysScanCmd.Flags().StringP("domain", "d", "", "Target domain")
	zerodaysScanCmd.Flags().StringP("subdomain", "s", "", "Target subdomain")
	zerodaysScanCmd.Flags().IntP("threads", "t", 50, "Number of threads")
	zerodaysScanCmd.Flags().Bool("silent", false, "Silent mode")
}
