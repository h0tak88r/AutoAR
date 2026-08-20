package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/h0tak88r/AutoAR/internal/scanner/firebase"
	"github.com/spf13/cobra"
)

var firebaseCmd = &cobra.Command{
	Use:   "firebase",
	Short: "Firebase misconfiguration scanner (read-only exposure tests)",
}

var firebaseScanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Fingerprint Firebase on live hosts and test Realtime DB / Firestore / Storage for unauthenticated exposure",
	RunE: func(cmd *cobra.Command, args []string) error {
		domain, _ := cmd.Flags().GetString("domain")
		subdomain, _ := cmd.Flags().GetString("subdomain")
		listFile, _ := cmd.Flags().GetString("live-hosts")
		threads, _ := cmd.Flags().GetInt("threads")

		if domain == "" && subdomain == "" && listFile == "" {
			return fmt.Errorf("domain (-d), subdomain (-s), or hosts file (-l) is required")
		}

		ensureDB()
		target := domain
		if target == "" {
			target = subdomain
		}
		if target == "" {
			target = listFile
		}
		_, finalize := setupCurrentScanManaged("firebase", target)

		opts := firebase.Options{
			Domain:        domain,
			LiveHostsFile: listFile,
			Threads:       threads,
			Timeout:       15 * time.Second,
		}

		// Single host (-s) with no list → write a one-line temp file.
		if subdomain != "" && listFile == "" {
			tmpFile, err := os.CreateTemp("", "firebase-host-*.txt")
			if err != nil {
				finalize(err)
				return err
			}
			defer os.Remove(tmpFile.Name())
			if _, err := tmpFile.WriteString(subdomain + "\n"); err != nil {
				finalize(err)
				return err
			}
			tmpFile.Close()
			opts.LiveHostsFile = tmpFile.Name()
		}

		_, err := firebase.Run(opts)
		finalize(err)
		return err
	},
}

func init() {
	rootCmd.AddCommand(firebaseCmd)
	firebaseCmd.AddCommand(firebaseScanCmd)

	firebaseScanCmd.Flags().StringP("domain", "d", "", "Target domain (uses stored/live subdomains, else enumerates)")
	firebaseScanCmd.Flags().StringP("subdomain", "s", "", "Single host to scan")
	// NOTE: no "-l" shorthand — it's the global --log-level (rootCmd persistent flag).
	firebaseScanCmd.Flags().String("live-hosts", "", "Path to a file of hosts (one per line)")
	firebaseScanCmd.Flags().IntP("threads", "t", 20, "Concurrency")
}
