package cmd

import (
	"github.com/spf13/cobra"
	"github.com/h0tak88r/AutoAR/internal/modules/subdomains"
	"github.com/h0tak88r/AutoAR/internal/modules/livehosts"
	"github.com/h0tak88r/AutoAR/internal/modules/cnames"
	"github.com/h0tak88r/AutoAR/internal/modules/tech"
	"github.com/h0tak88r/AutoAR/internal/modules/ports"
	"github.com/h0tak88r/AutoAR/internal/modules/urls"
)

var (
	subdomainsCmd = &cobra.Command{
		Use:   "subdomains",
		Short: "Enumerate subdomains",
		RunE: func(cmd *cobra.Command, args []string) error {
			domain, _ := cmd.Flags().GetString("domain")
			_, err := subdomains.EnumerateSubdomains(domain, 100)
			return err
		},
	}

	livehostsCmd = &cobra.Command{
		Use:   "livehosts",
		Short: "Filter live hosts",
		RunE: func(cmd *cobra.Command, args []string) error {
			domain, _ := cmd.Flags().GetString("domain")
			_, err := livehosts.FilterLiveHosts(domain, 100, true)
			return err
		},
	}

	cnamesCmd = &cobra.Command{
		Use:   "cnames",
		Short: "Collect CNAME records",
		RunE: func(cmd *cobra.Command, args []string) error {
			domain, _ := cmd.Flags().GetString("domain")
			_, err := cnames.CollectCNAMEs(domain)
			return err
		},
	}

	techCmd = &cobra.Command{
		Use:   "tech",
		Short: "Detect technologies",
		RunE: func(cmd *cobra.Command, args []string) error {
			domain, _ := cmd.Flags().GetString("domain")
			_, err := tech.DetectTech(domain, 100)
			return err
		},
	}

	portsCmd = &cobra.Command{
		Use:   "ports",
		Short: "Scan for open ports",
		RunE: func(cmd *cobra.Command, args []string) error {
			domain, _ := cmd.Flags().GetString("domain")
			_, err := ports.ScanPorts(domain, 100)
			return err
		},
	}

	urlsCmd = &cobra.Command{
		Use:   "urls",
		Short: "Collect URLs and JS files",
		RunE: func(cmd *cobra.Command, args []string) error {
			domain, _ := cmd.Flags().GetString("domain")
			_, err := urls.CollectURLs(domain, 100, false)
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

	subcmds := []*cobra.Command{subdomainsCmd, livehostsCmd, cnamesCmd, techCmd, portsCmd, urlsCmd}
	for _, sc := range subcmds {
		sc.Flags().StringP("domain", "d", "", "Target domain")
		sc.MarkFlagRequired("domain")
		reconCmd.AddCommand(sc)
	}

	// Also support the original flat structure for compatibility
	// (e.g., autoar subdomains get -d domain)
	// For now let's just use the 'recon' grouping for new modularity
}
