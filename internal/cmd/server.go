package cmd

import (
	"log"

	"github.com/h0tak88r/AutoAR/internal/modules/gobot"
	"github.com/spf13/cobra"
)

var apiCmd = &cobra.Command{
	Use:   "api",
	Short: "Start the REST API server",
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Println("Starting AutoAR API Server...")
		return gobot.StartAPI()
	},
}

var botCmd = &cobra.Command{
	Use:   "bot",
	Short: "Start the Discord bot",
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Println("Starting AutoAR Discord Bot...")
		return gobot.StartBot()
	},
}

var bothCmd = &cobra.Command{
	Use:   "both",
	Short: "Start both the API server and Discord bot",
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Println("Starting AutoAR API and Bot...")
		return gobot.StartBoth()
	},
}

func init() {
	rootCmd.AddCommand(apiCmd)
	rootCmd.AddCommand(botCmd)
	rootCmd.AddCommand(bothCmd)
}
