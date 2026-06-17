package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/tools/apkmitm"
)

// maxAPKUpload caps the uploaded APK size for the MITM patch endpoint.
const maxAPKUpload = 600 << 20 // 600 MiB

// apiAPKMitm patches an uploaded APK for HTTPS interception — it makes the app
// trust user-installed CAs and disables certificate pinning (apk-mitm style),
// re-signs it with a debug key, and streams the patched APK back as a download.
// The patching runs apktool + uber-apk-signer server-side and can take a few
// minutes for large apps.
func apiAPKMitm(c *gin.Context) {
	// Fail fast (and clearly) if the server toolchain is missing — e.g. when not
	// running inside the Docker image that bundles apktool + uber-apk-signer.
	if err := apkmitm.CheckTools(); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "APK MITM tooling unavailable: " + err.Error()})
		return
	}

	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxAPKUpload)
	file, err := c.FormFile("apk")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no APK uploaded (expected multipart field 'apk')"})
		return
	}
	if !strings.HasSuffix(strings.ToLower(file.Filename), ".apk") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file must be a .apk"})
		return
	}

	work, err := os.MkdirTemp("", "apkmitm-*")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create work directory"})
		return
	}
	defer os.RemoveAll(work)

	in := filepath.Join(work, "input.apk")
	if err := c.SaveUploadedFile(file, in); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save upload: " + err.Error()})
		return
	}

	out, err := apkmitm.Patch(in, work)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "patch failed: " + err.Error()})
		return
	}

	// Stream the patched APK back (written synchronously before the deferred cleanup).
	base := strings.TrimSuffix(filepath.Base(file.Filename), filepath.Ext(file.Filename))
	c.FileAttachment(out, base+"-patched.apk")
}
