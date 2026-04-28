package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/sirupsen/logrus"
	"github.com/h0tak88r/AutoAR/internal/utils"
	"github.com/h0tak88r/AutoAR/internal/version"
)

var rootCmd = &cobra.Command{
	Use:   "autoar",
	Short: "AutoAR - Autonomous Attack Reconnaissance & Security Scanner",
	Long: `AutoAR is a powerful, automated security scanning and reconnaissance tool 
designed for advanced attack surface discovery and vulnerability detection.`,
	Version: version.Version,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Initialize global flags and configuration here
	rootCmd.PersistentFlags().StringP("log-level", "l", "info", "Set log level (debug, info, warn, error)")
	
	cobra.OnInitialize(func() {
		logLevel, _ := rootCmd.Flags().GetString("log-level")
		setupLogger(logLevel)
	})
}

func setupLogger(level string) {
	config := utils.DefaultLogConfig()
	config.Level = level
	if err := utils.InitLogger(config); err != nil {
		logrus.Errorf("Failed to initialize logger: %v", err)
	}
}
