package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/h0tak88r/AutoAR/internal/modules/apkx"
)

var (
	apkxCmd = &cobra.Command{
		Use:   "apkx",
		Short: "Mobile application analysis (APK/IPA)",
	}

	apkxScanCmd = &cobra.Command{
		Use:   "scan",
		Short: "Scan an APK or IPA file/package",
		RunE: func(cmd *cobra.Command, args []string) error {
			input, _ := cmd.Flags().GetString("input")
			pkg, _ := cmd.Flags().GetString("package")
			platform, _ := cmd.Flags().GetString("platform")
			mitm, _ := cmd.Flags().GetBool("mitm")

			ensureDB()

			if pkg != "" {
				setupCurrentScan(pkg, "apkx")
				_, err := apkx.RunFromPackage(apkx.PackageOptions{
					Package:  pkg,
					Platform: platform,
					MITM:     mitm,
				})
				return err
			}

			if input == "" {
				return fmt.Errorf("either --input or --package is required")
			}

			setupCurrentScan(input, "apkx")
			_, err := apkx.Run(apkx.Options{
				InputPath: input,
				MITM:      mitm,
			})
			return err
		},
	}
)

func init() {
	rootCmd.AddCommand(apkxCmd)
	apkxCmd.AddCommand(apkxScanCmd)

	apkxScanCmd.Flags().StringP("input", "i", "", "Path to APK/IPA file")
	apkxScanCmd.Flags().StringP("package", "p", "", "Android package name or iOS bundle ID")
	apkxScanCmd.Flags().String("platform", "android", "Platform (android/ios) for package downloads")
	apkxScanCmd.Flags().Bool("mitm", false, "Enable MITM patching")
}
