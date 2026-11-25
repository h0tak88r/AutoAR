package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/h0tak88r/AutoAR/internal/bbcatalog"
	"github.com/spf13/cobra"
)

// catalogSyncCmd runs one bbcatalog.Sync() pass and prints the summary as
// JSON. It exists so the API server can run the sync as a DISPOSABLE CHILD
// process (bbcatalog.RunSyncChild / SyncAsync): bbscope (used for platform
// program enumeration) calls log.Fatal on any HTTP error — including 401s on
// stale tokens and rate-limit responses — which os.Exit(1)s whatever process
// loads it. A fatal in the child costs a retry; a fatal in the API server
// killed every running scan.
var catalogSyncCmd = &cobra.Command{
	Use:   "catalog-sync",
	Short: "Run one program-catalog sync pass (child-process safe)",
	// The parent logs the tail of this output: keep the error as the last line.
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		res, err := bbcatalog.Sync()
		if err != nil {
			res.Errors = append(res.Errors, err.Error())
		}
		out, _ := json.Marshal(res)
		if path, _ := cmd.Flags().GetString("out"); path != "" {
			if werr := os.WriteFile(path, out, 0o600); werr != nil && err == nil {
				err = werr
			}
		} else {
			fmt.Println(string(out))
		}
		return err
	},
}

func init() {
	catalogSyncCmd.Flags().String("out", "", "write the JSON summary to this file instead of stdout")
	rootCmd.AddCommand(catalogSyncCmd)
}
