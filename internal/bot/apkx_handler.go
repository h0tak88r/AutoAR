package bot

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"io"
	"net/http"

	"github.com/bwmarrin/discordgo"
	"github.com/h0tak88r/AutoAR/internal/r2storage"
	"github.com/h0tak88r/AutoAR/internal/scanner/apkx"
)

// handleApkXScan handles the /apkx_scan command
func handleApkXScan(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	var attachment *discordgo.MessageAttachment
	var pkgName string
	mitm := false

	for _, opt := range options {
		switch opt.Name {
		case "file":
			if attachID, ok := opt.Value.(string); ok {
				attachment = i.ApplicationCommandData().Resolved.Attachments[attachID]
			}
		case "package":
			pkgName = opt.StringValue()
		case "mitm":
			mitm = opt.BoolValue()
		}
	}

	if attachment == nil && pkgName == "" {
		respond(s, i, "❌ Please provide either an APK file or a package name.", true)
		return
	}

	respond(s, i, "⏳ Initializing APK analysis...", false)

	go func() {
		var localPath string
		var err error

		if attachment != nil {
			localPath = filepath.Join(os.TempDir(), attachment.Filename)
			if err := downloadFile(attachment.URL, localPath); err != nil {
				UpdateInteractionContent(s, i, fmt.Sprintf("❌ Failed to download attachment: %v", err))
				return
			}
			defer os.Remove(localPath)
		} else {
			UpdateInteractionContent(s, i, "🚧 Package download is currently restricted in Lite mode. Please upload the APK file.")
			return
		}

		UpdateInteractionContent(s, i, "🚀 Analyzing APK and applying patches...")

		res, err := apkx.Run(apkx.Options{
			InputPath: localPath,
			MITM:      mitm,
		})

		if err != nil {
			UpdateInteractionContent(s, i, fmt.Sprintf("❌ Analysis failed: %v", err))
			return
		}

		// Upload to R2 if enabled
		originalURL := ""
		mitmURL := ""

		if r2storage.IsEnabled() {
			UpdateInteractionContent(s, i, "📦 Uploading results to R2...")
			if res.OriginalAPK != "" {
				originalURL, _ = r2storage.UploadFile(res.OriginalAPK, filepath.Base(res.OriginalAPK), false)
			}
			if res.MITMPatchedAPK != "" {
				mitmURL, _ = r2storage.UploadFile(res.MITMPatchedAPK, filepath.Base(res.MITMPatchedAPK), false)
			}
		}

		msg := fmt.Sprintf("✅ **APK Analysis Complete** (%s)\n\n", res.Duration.Truncate(time.Second))
		if originalURL != "" {
			msg += fmt.Sprintf("🔗 **Original APK:** %s\n", originalURL)
		}
		if mitmURL != "" {
			msg += fmt.Sprintf("🛡️ **MITM Patched APK:** %s\n", mitmURL)
		}
		if originalURL == "" && mitmURL == "" {
			msg += "⚠️ R2 storage is not configured. Artifacts were processed but not uploaded."
		}

		UpdateInteractionContent(s, i, msg)
	}()
}

func handleApkXScanPackage(s *discordgo.Session, i *discordgo.InteractionCreate) {
	handleApkXScan(s, i)
}

func handleApkXScanIOS(s *discordgo.Session, i *discordgo.InteractionCreate) {
	respond(s, i, "🚧 iOS analysis is currently disabled in Lite mode.", true)
}

func downloadFile(url string, filepath string) error {
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	_, err = io.Copy(out, resp.Body)
	return err
}
