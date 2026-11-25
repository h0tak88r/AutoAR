package cmd

import (
	"fmt"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/spf13/cobra"
)

// dbCmd — database maintenance commands. Currently: backup. The README has
// long documented `autoar db backup [--upload-r2]`; this makes it real (the
// db.BackupDatabase implementation existed but nothing invoked it).
var dbCmd = &cobra.Command{
	Use:   "db",
	Short: "Database maintenance (backup)",
}

var dbBackupUploadR2 bool

var dbBackupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Create a database backup (and optionally upload it to Cloudflare R2)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := db.Init(); err != nil {
			return fmt.Errorf("failed to initialize database: %w", err)
		}
		path, r2URL, err := db.BackupDatabase(dbBackupUploadR2)
		if err != nil {
			return err
		}
		fmt.Printf("Backup created: %s\n", path)
		if r2URL != "" {
			fmt.Printf("Uploaded to R2: %s\n", r2URL)
		} else if dbBackupUploadR2 {
			fmt.Println("R2 upload skipped (R2 storage not enabled or upload failed — see logs)")
		}
		return nil
	},
}

func init() {
	dbBackupCmd.Flags().BoolVar(&dbBackupUploadR2, "upload-r2", false, "Also upload the backup to Cloudflare R2")
	dbCmd.AddCommand(dbBackupCmd)
	rootCmd.AddCommand(dbCmd)
}
