package cmd

import (
	"log"

	"github.com/h0tak88r/AutoAR/internal/scanner/checktools"
	"github.com/h0tak88r/AutoAR/internal/scanner/setup"
	"github.com/spf13/cobra"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Install required dependencies",
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Println("Starting AutoAR setup...")
		return setup.Run()
	},
}

var checkToolsCmd = &cobra.Command{
	Use:   "check-tools",
	Short: "Check if all required tools are installed",
	RunE: func(cmd *cobra.Command, args []string) error {
		return checktools.Run()
	},
}

func init() {
	rootCmd.AddCommand(setupCmd)
	rootCmd.AddCommand(checkToolsCmd)
}
