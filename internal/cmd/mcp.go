package cmd

import (
	"fmt"
	"os"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/mcp"
	"github.com/spf13/cobra"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Start the MCP server for AI assistant scan exploration",
	Long: `Start a Model Context Protocol (MCP) server over stdio.

This allows AI assistants (Claude Code, Cursor, etc.) to discover and explore
scan results, findings, and files from the AutoAR platform.

Tools exposed:
  list_scans      - List recent scans
  get_scan        - Get scan details by ID
  list_scan_files - List result files for a scan
  get_file_content - Read file content
  list_findings   - Get parsed findings for a scan
  search_findings - Search across all scans`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Initialize the database
		if err := db.Init(); err != nil {
			fmt.Fprintf(os.Stderr, "[autoar-mcp] database init error: %v\n", err)
			return fmt.Errorf("database init: %w", err)
		}
		if err := db.EnsureSchema(); err != nil {
			fmt.Fprintf(os.Stderr, "[autoar-mcp] database schema error: %v\n", err)
			return fmt.Errorf("database schema: %w", err)
		}

		fmt.Fprintf(os.Stderr, "[autoar-mcp] starting MCP server...\n")
		server := mcp.NewServer()
		return server.Run()
	},
}

func init() {
	rootCmd.AddCommand(mcpCmd)
}
