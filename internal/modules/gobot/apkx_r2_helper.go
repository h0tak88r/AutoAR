package gobot

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/bwmarrin/discordgo"
	apkxmod "github.com/h0tak88r/AutoAR/v3/internal/modules/apkx"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/r2storage"
)

// uploadFileBasedScanToR2 uploads APK scan results to R2 and adds R2 link fields
// This is used for file-based scans (Option A: keeps file attachments + adds R2 links)
// Returns the R2 URLs for caching
func uploadFileBasedScanToR2(res *apkxmod.Result, filename, tempPath string, mitm bool, fields *[]*discordgo.MessageEmbedField) (htmlURL, jsonURL, originalURL, mitmURL string) {
	if res == nil || res.ReportDir == "" {
		return
	}
	
	if !r2storage.IsEnabled() || os.Getenv("USE_R2_STORAGE") != "true" {
		return
	}
	
	resultsDir := getResultsDir()
	apkPrefix := strings.TrimPrefix(res.ReportDir, resultsDir+"/")
	if apkPrefix == res.ReportDir {
		apkPrefix = "apkx/" + filepath.Base(res.ReportDir)
	}
	
	log.Printf("[INFO] Uploading file-based scan to R2: %s", res.ReportDir)
	r2URLs, uploadErr := r2storage.UploadResultsDirectory(apkPrefix, res.ReportDir, false)
	if uploadErr != nil {
		log.Printf("[WARN] R2 upload failed: %v", uploadErr)
		return
	}
	
	log.Printf("[OK] Uploaded %d files to R2", len(r2URLs))
	
	// Add R2 link fields for HTML and JSON
	for localPath, url := range r2URLs {
		if strings.HasSuffix(localPath, "security-report.html") {
			htmlURL = url
			*fields = append(*fields, &discordgo.MessageEmbedField{
				Name:  "📄 HTML Report (R2)",
				Value: fmt.Sprintf("🔗 [View Report](%s)", url),
			})
		} else if strings.HasSuffix(localPath, "results.json") {
			jsonURL = url
			*fields = append(*fields, &discordgo.MessageEmbedField{
				Name:  "📋 JSON Results (R2)",
				Value: fmt.Sprintf("🔗 [Download](%s)", url),
			})
		}
	}
	
	// Upload and link original APK
	if tempPath != "" {
		if _, statErr := os.Stat(tempPath); statErr == nil {
			if apkURL, _, _ := r2storage.UploadFileIfNotExists(tempPath, filename); apkURL != "" {
				originalURL = apkURL
				*fields = append(*fields, &discordgo.MessageEmbedField{
					Name:  "📱 Original APK (R2)",
					Value: fmt.Sprintf("🔗 [Download](%s)", apkURL),
				})
			}
		}
	}
	
	// Upload and link MITM APK
	if mitm && res.MITMPatchedAPK != "" {
		if _, statErr := os.Stat(res.MITMPatchedAPK); statErr == nil {
			if mURL, _, _ := r2storage.UploadFileIfNotExists(res.MITMPatchedAPK, filepath.Base(res.MITMPatchedAPK)); mURL != "" {
				mitmURL = mURL
				*fields = append(*fields, &discordgo.MessageEmbedField{
					Name:  "🔓 MITM Patched APK (R2)",
					Value: fmt.Sprintf("🔗 [Download](%s)", mitmURL),
				})
			}
		}
	}
	return
}
