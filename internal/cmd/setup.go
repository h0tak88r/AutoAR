package cmd

import (
	"log"

	"github.com/spf13/cobra"
	"github.com/h0tak88r/AutoAR/internal/modules/setup"
	"github.com/h0tak88r/AutoAR/internal/modules/checktools"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Install required dependencies",
	Run: func(cmd *cobra.Command, args []string) {
		log.Println("Starting AutoAR setup...")
		_ = setup.Run()
	},
}

var checkToolsCmd = &cobra.Command{
	Use:   "check-tools",
	Short: "Check if all required tools are installed",
	Run: func(cmd *cobra.Command, args []string) {
		_ = checktools.Run()
	},
}

func init() {
	rootCmd.AddCommand(setupCmd)
	rootCmd.AddCommand(checkToolsCmd)
}
