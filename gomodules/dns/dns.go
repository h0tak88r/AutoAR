package dns

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/h0tak88r/AutoAR/gomodules/utils"
)

// helper to locate the dns_takeover.sh script
func scriptPath() string {
	root := utils.GetRootDir()
	return filepath.Join(root, "modules", "dns_takeover.sh")
}

func runScript(action, domain string) error {
	if domain == "" {
		return fmt.Errorf("domain is required")
	}
	path := scriptPath()
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("dns_takeover.sh not found at %s: %w", path, err)
	}

	cmd := exec.Command(path, action, "-d", domain)
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("dns %s failed for %s: %w", action, domain, err)
	}
	return nil
}

// Takeover runs the comprehensive DNS takeover workflow (equivalent to `dns takeover` / `dns all`).
func Takeover(domain string) error { return runScript("takeover", domain) }

// CNAME runs the CNAME-focused DNS takeover workflow.
func CNAME(domain string) error { return runScript("cname", domain) }

// NS runs the NS-focused DNS takeover workflow.
func NS(domain string) error { return runScript("ns", domain) }

// AzureAWS runs the Azure/AWS cloud takeover detection workflow.
func AzureAWS(domain string) error { return runScript("azure-aws", domain) }

// DNSReaper runs only the DNSReaper workflow.
func DNSReaper(domain string) error { return runScript("dnsreaper", domain) }
