package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/h0tak88r/AutoAR/internal/modules/dns"
	"github.com/h0tak88r/AutoAR/internal/modules/cf1016"
	"github.com/h0tak88r/AutoAR/internal/modules/db"
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
		setupCurrentScan("dns-takeover", domain)

		opts := dns.TakeoverOptions{
			Domain:        domain,
			Subdomain:     subdomain,
			LiveHostsFile: liveHosts,
		}

		return dns.TakeoverWithOptions(opts)
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
		setupCurrentScan("dns-cf1016", target)

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
		setupCurrentScan("dns-dangling-ip", domain)

		return dns.DanglingIP(domain)
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
		setupCurrentScan("dns-cname", domain)

		return dns.CNAME(domain)
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
		setupCurrentScan("dns-ns", domain)

		return dns.NS(domain)
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
		setupCurrentScan("dns-azure-aws", domain)

		return dns.AzureAWS(domain)
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
		setupCurrentScan("dns-dnsreaper", domain)

		return dns.DNSReaper(domain)
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

// Helper to setup current scan environment and DB record
func setupCurrentScan(scanType, target string) {
	scanID := os.Getenv("AUTOAR_CURRENT_SCAN_ID")
	if scanID == "" {
		scanID = fmt.Sprintf("%s-%d", scanType, os.Getpid())
		os.Setenv("AUTOAR_CURRENT_SCAN_ID", scanID)
		_ = db.CreateScan(&db.ScanRecord{
			ScanID:   scanID,
			ScanType: scanType,
			Target:   target,
			Status:   "running",
		})
		// We don't defer UpdateScanStatus here because the command might run in background 
		// or be part of a bigger workflow. But for standalone CLI it's better than nothing.
	}
}
