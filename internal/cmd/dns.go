package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/h0tak88r/AutoAR/internal/modules/cf1016"
	"github.com/h0tak88r/AutoAR/internal/modules/db"
	"github.com/h0tak88r/AutoAR/internal/modules/dns"
	"github.com/spf13/cobra"
)

var dnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "DNS-related security operations",
}

var dnsTakeoverCmd = &cobra.Command{
	Use:   "takeover",
	Short: "Comprehensive DNS takeover scan",
	RunE: func(cmd *cobra.Command, args []string) error {
		domain, _ := cmd.Flags().GetString("domain")
		subdomain, _ := cmd.Flags().GetString("subdomain")
		liveHosts, _ := cmd.Flags().GetString("live-hosts")

		if domain == "" {
			return fmt.Errorf("domain (-d) is required")
		}

		ensureDB()
		_, finalize := setupCurrentScanManaged("dns-takeover", domain)

		opts := dns.TakeoverOptions{
			Domain:        domain,
			Subdomain:     subdomain,
			LiveHostsFile: liveHosts,
		}

		err := dns.TakeoverWithOptions(opts)
		finalize(err)
		return err
	},
}

var dnsCF1016Cmd = &cobra.Command{
	Use:   "cf1016",
	Short: "Cloudflare 1016 dangling DNS scan",
	RunE: func(cmd *cobra.Command, args []string) error {
		domain, _ := cmd.Flags().GetString("domain")
		subdomain, _ := cmd.Flags().GetString("subdomain")
		threads, _ := cmd.Flags().GetInt("threads")

		if domain == "" && subdomain == "" {
			return fmt.Errorf("domain (-d) or subdomain (-s) is required")
		}

		ensureDB()
		target := domain
		if target == "" {
			target = subdomain
		}
		_, finalize := setupCurrentScanManaged("dns-cf1016", target)

		opts := cf1016.Options{
			Domain:         domain,
			SubdomainsFile: "", // Will be inferred in Run if empty
			Threads:        threads,
			Timeout:        10 * time.Second,
		}

		if subdomain != "" {
			// Create a temp file with just this subdomain
			tmpFile, err := os.CreateTemp("", "cf1016-sub-*.txt")
			if err != nil {
				return err
			}
			defer os.Remove(tmpFile.Name())
			if _, err := tmpFile.WriteString(subdomain + "\n"); err != nil {
				return err
			}
			tmpFile.Close()
			opts.SubdomainsFile = tmpFile.Name()
		}

		_, err := cf1016.Run(opts)
		finalize(err)
		return err
	},
}

var dnsDanglingIPCmd = &cobra.Command{
	Use:   "dangling-ip",
	Short: "Scan for dangling IP records",
	RunE: func(cmd *cobra.Command, args []string) error {
		domain, _ := cmd.Flags().GetString("domain")
		if domain == "" {
			return fmt.Errorf("domain (-d) is required")
		}

		ensureDB()
		_, finalize := setupCurrentScanManaged("dns-dangling-ip", domain)

		err := dns.DanglingIP(domain)
		finalize(err)
		return err
	},
}

var dnsCNAMECmd = &cobra.Command{
	Use:   "cnames",
	Short: "Scan for CNAME-based takeover vulnerabilities",
	RunE: func(cmd *cobra.Command, args []string) error {
		domain, _ := cmd.Flags().GetString("domain")
		if domain == "" {
			return fmt.Errorf("domain (-d) is required")
		}

		ensureDB()
		_, finalize := setupCurrentScanManaged("dns-cname", domain)

		err := dns.CNAME(domain)
		finalize(err)
		return err
	},
}

var dnsNSCmd = &cobra.Command{
	Use:   "ns",
	Short: "Scan for NS-based takeover vulnerabilities",
	RunE: func(cmd *cobra.Command, args []string) error {
		domain, _ := cmd.Flags().GetString("domain")
		if domain == "" {
			return fmt.Errorf("domain (-d) is required")
		}

		ensureDB()
		_, finalize := setupCurrentScanManaged("dns-ns", domain)

		err := dns.NS(domain)
		finalize(err)
		return err
	},
}

var dnsAzureAWSCmd = &cobra.Command{
	Use:   "azure-aws",
	Short: "Scan for Azure and AWS specific takeovers",
	RunE: func(cmd *cobra.Command, args []string) error {
		domain, _ := cmd.Flags().GetString("domain")
		if domain == "" {
			return fmt.Errorf("domain (-d) is required")
		}

		ensureDB()
		_, finalize := setupCurrentScanManaged("dns-azure-aws", domain)

		err := dns.AzureAWS(domain)
		finalize(err)
		return err
	},
}

var dnsReaperCmd = &cobra.Command{
	Use:   "dnsreaper",
	Short: "Run DNSReaper scan (requires Docker)",
	RunE: func(cmd *cobra.Command, args []string) error {
		domain, _ := cmd.Flags().GetString("domain")
		if domain == "" {
			return fmt.Errorf("domain (-d) is required")
		}

		ensureDB()
		_, finalize := setupCurrentScanManaged("dns-dnsreaper", domain)

		err := dns.DNSReaper(domain)
		finalize(err)
		return err
	},
}

func init() {
	rootCmd.AddCommand(dnsCmd)
	dnsCmd.AddCommand(dnsTakeoverCmd)
	dnsCmd.AddCommand(dnsCF1016Cmd)
	dnsCmd.AddCommand(dnsDanglingIPCmd)
	dnsCmd.AddCommand(dnsCNAMECmd)
	dnsCmd.AddCommand(dnsNSCmd)
	dnsCmd.AddCommand(dnsAzureAWSCmd)
	dnsCmd.AddCommand(dnsReaperCmd)

	// Persist flags across subcommands
	dnsCmd.PersistentFlags().StringP("domain", "d", "", "Target domain")

	// Specific flags
	dnsTakeoverCmd.Flags().StringP("subdomain", "s", "", "Single subdomain to scan")
	dnsTakeoverCmd.Flags().StringP("live-hosts", "l", "", "Path to live hosts file")

	dnsCF1016Cmd.Flags().StringP("subdomain", "s", "", "Single subdomain to scan")
	dnsCF1016Cmd.Flags().IntP("threads", "t", 100, "Number of threads")
}

// Helper to ensure database is initialized for standalone CLI runs
func ensureDB() {
	_ = db.Init()
	_ = db.InitSchema()
}

// setupCurrentScanManaged creates/reuses a current scan and returns a finalizer.
// The returned finalize callback updates DB status and unsets AUTOAR_CURRENT_SCAN_ID
// only if this command created the scan context.
func setupCurrentScanManaged(scanType, target string) (string, func(error)) {
	ensureDB()
	scanID := os.Getenv("AUTOAR_CURRENT_SCAN_ID")
	created := false
	if scanID == "" {
		scanID = fmt.Sprintf("%s-%d", scanType, os.Getpid())
		os.Setenv("AUTOAR_CURRENT_SCAN_ID", scanID)
		created = true
		_ = db.CreateScan(&db.ScanRecord{
			ScanID:   scanID,
			ScanType: scanType,
			Target:   target,
			Status:   "running",
		})
	}

	finalize := func(runErr error) {
		if runErr != nil {
			_ = db.UpdateScanStatus(scanID, "failed")
		} else {
			_ = db.UpdateScanStatus(scanID, "completed")
		}
		if created {
			os.Unsetenv("AUTOAR_CURRENT_SCAN_ID")
		}
	}
	return scanID, finalize
}
