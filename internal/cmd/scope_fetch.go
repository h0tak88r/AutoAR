package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	scopemod "github.com/h0tak88r/AutoAR/internal/scanner/scope"
	"github.com/spf13/cobra"
)

// scopeFetchCmd is the disposable child behind POST /api/scope/fetch. It
// reads scope.Options as JSON on stdin (credentials never go on the command
// line), runs bbscope's FetchScope, and writes a scope.FetchResult as JSON to
// --out. bbscope may log.Fatal / panic on HTTP errors and malformed upstream
// data; here that kills only this child, never the API server.
var scopeFetchCmd = &cobra.Command{
	Use:    "scope-fetch",
	Short:  "Fetch platform scope as JSON (internal: child process for the API)",
	Hidden: true,
	// The parent logs the tail of this output: keep the error as the last line.
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		var opts scopemod.Options
		if err := json.NewDecoder(io.LimitReader(os.Stdin, 1<<20)).Decode(&opts); err != nil {
			return fmt.Errorf("scope-fetch: decode options from stdin: %w", err)
		}
		var res scopemod.FetchResult
		progs, ferr := scopemod.FetchScope(opts)
		res.Programs = progs
		if ferr != nil {
			res.Error = ferr.Error()
		}
		out, err := json.Marshal(res)
		if err != nil {
			return err
		}
		if path, _ := cmd.Flags().GetString("out"); path != "" {
			return os.WriteFile(path, out, 0o600)
		}
		_, err = os.Stdout.Write(append(out, '\n'))
		return err
	},
}

func init() {
	scopeFetchCmd.Flags().String("out", "", "write the JSON result to this file instead of stdout")
	rootCmd.AddCommand(scopeFetchCmd)
}
