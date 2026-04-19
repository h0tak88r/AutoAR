package cmd

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/h0tak88r/AutoAR/internal/modules/gobot"
)

var apiCmd = &cobra.Command{
	Use:   "api",
	Short: "Start the REST API server",
	Run: func(cmd *cobra.Command, args []string) {
		log.Println("Starting AutoAR API Server...")
		gobot.StartAPI()
	},
}

var botCmd = &cobra.Command{
	Use:   "bot",
	Short: "Start the Discord bot",
	Run: func(cmd *cobra.Command, args []string) {
		log.Println("Starting AutoAR Discord Bot...")
		gobot.StartBot()
	},
}

var bothCmd = &cobra.Command{
	Use:   "both",
	Short: "Start both the API server and Discord bot",
	Run: func(cmd *cobra.Command, args []string) {
		log.Println("Starting AutoAR API and Bot...")
		
		// Run in goroutines or sequentially depending on implementation
		go gobot.StartAPI()
		go gobot.StartBot()

		// Wait for interruption
		sc := make(chan os.Signal, 1)
		signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
		<-sc
		log.Println("Shutting down...")
	},
}

func init() {
	rootCmd.AddCommand(apiCmd)
	rootCmd.AddCommand(botCmd)
	rootCmd.AddCommand(bothCmd)
}
