package cmd

import (
	"fmt"

	"github.com/h0tak88r/AutoAR/internal/modules/cnames"
	"github.com/h0tak88r/AutoAR/internal/modules/livehosts"
	"github.com/h0tak88r/AutoAR/internal/modules/ports"
	"github.com/h0tak88r/AutoAR/internal/modules/recon"
	"github.com/h0tak88r/AutoAR/internal/modules/subdomains"
	"github.com/h0tak88r/AutoAR/internal/modules/tech"
	"github.com/h0tak88r/AutoAR/internal/modules/urls"
	"github.com/spf13/cobra"
)

var (
	reconRunCmd = &cobra.Command{
		Use:   "run",
		Short: "Run full recon pipeline (subdomains, livehosts, tech, cnames)",
		RunE: func(cmd *cobra.Command, args []string) error {
			domain, _ := cmd.Flags().GetString("domain")
			if domain == "" {
				return fmt.Errorf("domain is required")
			}

			ensureDB()
			_, finalize := setupCurrentScanManaged("recon", domain)

			_, err := recon.RunFullRecon(domain, 100)
			finalize(err)
			return err
		},
	}

	subdomainsCmd = &cobra.Command{
		Use:   "subdomains",
		Short: "Enumerate subdomains",
		RunE: func(cmd *cobra.Command, args []string) error {
			domain, _ := cmd.Flags().GetString("domain")
			if domain == "" {
				return fmt.Errorf("domain is required")
			}
			_, finalize := setupCurrentScanManaged("subdomains", domain)
			_, err := subdomains.EnumerateSubdomains(domain, 100)
			finalize(err)
			return err
		},
	}

	livehostsCmd = &cobra.Command{
		Use:   "livehosts",
		Short: "Filter live hosts",
		RunE: func(cmd *cobra.Command, args []string) error {
			domain, _ := cmd.Flags().GetString("domain")
			if domain == "" {
				return fmt.Errorf("domain is required")
			}
			_, finalize := setupCurrentScanManaged("livehosts", domain)
			_, err := livehosts.FilterLiveHosts(domain, 100, true)
			finalize(err)
			return err
		},
	}

	cnamesCmd = &cobra.Command{
		Use:   "cnames",
		Short: "Collect CNAME records",
		RunE: func(cmd *cobra.Command, args []string) error {
			domain, _ := cmd.Flags().GetString("domain")
			if domain == "" {
				return fmt.Errorf("domain is required")
			}
			_, finalize := setupCurrentScanManaged("cnames", domain)
			_, err := cnames.CollectCNAMEs(domain)
			finalize(err)
			return err
		},
	}

	techCmd = &cobra.Command{
		Use:   "tech",
		Short: "Detect technologies",
		RunE: func(cmd *cobra.Command, args []string) error {
			domain, _ := cmd.Flags().GetString("domain")
			if domain == "" {
				return fmt.Errorf("domain is required")
			}
			_, finalize := setupCurrentScanManaged("tech", domain)
			_, err := tech.DetectTech(domain, 100)
			finalize(err)
			return err
		},
	}

	portsCmd = &cobra.Command{
		Use:   "ports",
		Short: "Scan for open ports",
		RunE: func(cmd *cobra.Command, args []string) error {
			domain, _ := cmd.Flags().GetString("domain")
			if domain == "" {
				return fmt.Errorf("domain is required")
			}
			_, finalize := setupCurrentScanManaged("ports", domain)
			_, err := ports.ScanPorts(domain, 100)
			finalize(err)
			return err
		},
	}

	urlsCmd = &cobra.Command{
		Use:   "urls",
		Short: "Collect URLs and JS files",
		RunE: func(cmd *cobra.Command, args []string) error {
			domain, _ := cmd.Flags().GetString("domain")
			if domain == "" {
				return fmt.Errorf("domain is required")
			}
			_, finalize := setupCurrentScanManaged("urls", domain)
			_, err := urls.CollectURLs(domain, 100, false)
			finalize(err)
			return err
		},
	}
)

func init() {
	reconCmd := &cobra.Command{
		Use:   "recon",
		Short: "Reconnaissance operations",
	}
	rootCmd.AddCommand(reconCmd)

	subcmds := []*cobra.Command{reconRunCmd, subdomainsCmd, livehostsCmd, cnamesCmd, techCmd, portsCmd, urlsCmd}
	for _, sc := range subcmds {
		sc.Flags().StringP("domain", "d", "", "Target domain")
		sc.MarkFlagRequired("domain")
		reconCmd.AddCommand(sc)
	}

	// For backward compatibility, also add some directly to root if needed
	// but the user seems to want a cleaner structure.
}
