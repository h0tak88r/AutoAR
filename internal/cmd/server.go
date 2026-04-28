package cmd

import (
	"log"

	"github.com/h0tak88r/AutoAR/internal/app"
	"github.com/spf13/cobra"
)

var apiCmd = &cobra.Command{
	Use:   "api",
	Short: "Start the REST API server",
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Println("Starting AutoAR API Server...")
		return app.StartAPI()
	},
}

var botCmd = &cobra.Command{
	Use:   "bot",
	Short: "Start the Discord bot",
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Println("Starting AutoAR Discord Bot...")
		// Note: Bot currently starts its own internal API for subprocesses
		// This is handled inside app.StartBoth or similar if needed
		// For now, we call app's coordinate StartBoth if it's the main entry
		return app.StartBoth() 
	},
}

var bothCmd = &cobra.Command{
	Use:   "both",
	Short: "Start both the API server and Discord bot",
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Println("Starting AutoAR API and Bot...")
		return app.StartBoth()
	},
}

func init() {
	rootCmd.AddCommand(apiCmd)
	rootCmd.AddCommand(botCmd)
	rootCmd.AddCommand(bothCmd)
}
