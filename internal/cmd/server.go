package cmd

import (
	"github.com/h0tak88r/AutoAR/internal/app"
	"github.com/spf13/cobra"
)

var apiCmd = &cobra.Command{
	Use:   "api",
	Short: "Start the REST API server",
	RunE: func(cmd *cobra.Command, args []string) error {
		return app.StartAPI()
	},
}

func init() {
	rootCmd.AddCommand(apiCmd)
}
