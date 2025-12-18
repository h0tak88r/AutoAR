package ipatoolclient

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/99designs/keyring"
	"github.com/juju/persistent-cookiejar"
	"github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/majd/ipatool/v2/pkg/keychain"
	ipmachine "github.com/majd/ipatool/v2/pkg/util/machine"
	ipos "github.com/majd/ipatool/v2/pkg/util/operatingsystem"
)

// Client is a thin wrapper around ipatool's AppStore library that exposes
// a simple "download IPA by bundle identifier" API for AutoAR.
//
// It uses:
//   - A file-based keychain stored under $HOME/.autoar-ipatool
//   - A persistent cookie jar in the same directory
//   - Credentials from environment variables:
//       IPATOOL_EMAIL
//       IPATOOL_PASSWORD
//       (optional) IPATOOL_AUTH_CODE
//       (required) IPATOOL_KEYCHAIN_PASSPHRASE
type Client struct {
	store appstore.AppStore
}

// NewFromEnv constructs a new Client using the current environment.
func NewFromEnv() (*Client, error) {
	osImpl := ipos.New()
	mach := ipmachine.New(ipmachine.Args{OS: osImpl})

	homeDir := mach.HomeDirectory()
	if homeDir == "" {
		return nil, fmt.Errorf("failed to determine home directory for ipatool keychain")
	}

	configDir := filepath.Join(homeDir, ".autoar-ipatool")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create ipatool config directory: %w", err)
	}

	jar, err := cookiejar.New(&cookiejar.Options{
		Filename: filepath.Join(configDir, "cookies.jar"),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %w", err)
	}

	passphrase := os.Getenv("IPATOOL_KEYCHAIN_PASSPHRASE")
	if strings.TrimSpace(passphrase) == "" {
		// Debug: Check if the variable exists but is empty
		if _, exists := os.LookupEnv("IPATOOL_KEYCHAIN_PASSPHRASE"); exists {
			return nil, fmt.Errorf("IPATOOL_KEYCHAIN_PASSPHRASE is set but empty (check for whitespace or empty value in Dokploy)")
		}
		// List available IPATOOL_* env vars for debugging
		var foundVars []string
		for _, env := range os.Environ() {
			if strings.HasPrefix(env, "IPATOOL_") {
				key := strings.Split(env, "=")[0]
				foundVars = append(foundVars, key)
			}
		}
		if len(foundVars) > 0 {
			return nil, fmt.Errorf("IPATOOL_KEYCHAIN_PASSPHRASE is required but not found. Found IPATOOL_* vars: %v. Please ensure IPATOOL_KEYCHAIN_PASSPHRASE is set in Dokploy environment variables and the container has been restarted", foundVars)
		}
		return nil, fmt.Errorf("IPATOOL_KEYCHAIN_PASSPHRASE is required but not found. Please set it in Dokploy environment variables and restart the container")
	}

	ring, err := keyring.Open(keyring.Config{
		AllowedBackends: []keyring.BackendType{
			keyring.FileBackend,
		},
		ServiceName: "autoar-ipatool",
		FileDir:     configDir,
		FilePasswordFunc: func(prompt string) (string, error) {
			return passphrase, nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open keyring: %w", err)
	}

	kc := keychain.New(keychain.Args{Keyring: ring})

	store := appstore.NewAppStore(appstore.Args{
		Keychain:        kc,
		CookieJar:       jar,
		OperatingSystem: osImpl,
		Machine:         mach,
	})

	return &Client{store: store}, nil
}

// ensureAccount returns a valid App Store account, logging in with credentials
// from the environment if necessary.
func (c *Client) ensureAccount(ctx context.Context) (appstore.Account, error) {
	// First try to load an existing account from keychain.
	// If successful, we can use the stored session without requiring 2FA again.
	if info, err := c.store.AccountInfo(); err == nil {
		log.Printf("[ipatool] Using existing authenticated session from keychain")
		return info.Account, nil
	}

	email := strings.TrimSpace(os.Getenv("IPATOOL_EMAIL"))
	password := os.Getenv("IPATOOL_PASSWORD")
	authCode := strings.ReplaceAll(os.Getenv("IPATOOL_AUTH_CODE"), " ", "")

	if email == "" || password == "" {
		return appstore.Account{}, fmt.Errorf("IPATOOL_EMAIL and IPATOOL_PASSWORD are required to login to the App Store")
	}

	// Check if auth code is needed
	if authCode == "" {
		// Try login without auth code first (in case 2FA is not required or session exists)
		out, err := c.store.Login(appstore.LoginInput{
			Email:    email,
			Password: password,
			AuthCode: "",
		})
		if err == nil {
			log.Printf("[ipatool] Successfully authenticated without 2FA code")
			return out.Account, nil
		}
		
		// If login failed, check if it's a 2FA error
		errStr := err.Error()
		if strings.Contains(strings.ToLower(errStr), "auth code") || 
		   strings.Contains(strings.ToLower(errStr), "verification code") ||
		   strings.Contains(strings.ToLower(errStr), "two-factor") ||
		   strings.Contains(strings.ToLower(errStr), "2fa") {
			return appstore.Account{}, fmt.Errorf("2FA code required! Here's how to get it:\n\n1. Check your iPhone/iPad/Mac (trusted device) - Apple just sent a 6-digit code\n2. Look for a notification or popup saying 'Apple ID sign-in request'\n3. The code will appear on your device screen (or in Settings > [Your Name] > Sign-In & Security > Get Verification Code)\n4. Copy that 6-digit code\n5. Set IPATOOL_AUTH_CODE in Dokploy with that code\n6. Retry the command - the session will be saved after successful login\n\nNote: The code is sent WHEN you run the command, not before. After first successful login, you won't need 2FA again until the session expires.\n\nOriginal error: %w", err)
		}
		return appstore.Account{}, fmt.Errorf("ipatool login failed: %w", err)
	}

	// Login with auth code
	out, err := c.store.Login(appstore.LoginInput{
		Email:    email,
		Password: password,
		AuthCode: authCode,
	})
	if err != nil {
		return appstore.Account{}, fmt.Errorf("ipatool login failed: %w", err)
	}

	log.Printf("[ipatool] Successfully authenticated with 2FA. Session saved to keychain - 2FA won't be required again until session expires.")
	return out.Account, nil
}

// DownloadIPAByBundleID downloads an iOS app (IPA) for the given bundle
// identifier into outputDir and returns the absolute path to the IPA file.
//
// This mirrors the high-level behavior of "ipatool download -b <bundle>".
func (c *Client) DownloadIPAByBundleID(ctx context.Context, bundleID, outputDir string) (string, error) {
	bundleID = strings.TrimSpace(bundleID)
	if bundleID == "" {
		return "", fmt.Errorf("bundle identifier is required")
	}

	acc, err := c.ensureAccount(ctx)
	if err != nil {
		return "", err
	}

	// Lookup app by bundle ID.
	lookupOut, err := c.store.Lookup(appstore.LookupInput{
		Account:  acc,
		BundleID: bundleID,
	})
	if err != nil {
		return "", fmt.Errorf("failed to look up app %q: %w", bundleID, err)
	}
	app := lookupOut.App

	// Attempt download; handle common error conditions similarly to the CLI.
	tryDownload := func(account appstore.Account) (appstore.DownloadOutput, error) {
		return c.store.Download(appstore.DownloadInput{
			Account:    account,
			App:        app,
			OutputPath: outputDir,
		})
	}

	out, err := tryDownload(acc)
	if err != nil {
		// License missing: try to purchase (free apps only) then download again.
		if errors.Is(err, appstore.ErrLicenseRequired) {
			if pErr := c.store.Purchase(appstore.PurchaseInput{
				Account: acc,
				App:     app,
			}); pErr != nil {
				return "", fmt.Errorf("failed to purchase app license: %w", pErr)
			}
			out, err = tryDownload(acc)
		}
	}

	if err != nil {
		// Password token expired: try to re-login and download again.
		if errors.Is(err, appstore.ErrPasswordTokenExpired) {
			log.Printf("[ipatool] Session expired, attempting re-login...")
			// Re-login using stored email/password on the account.
			// Try without auth code first (session might still be valid)
			loginOut, lErr := c.store.Login(appstore.LoginInput{
				Email:    acc.Email,
				Password: acc.Password,
				AuthCode: "",
			})
			if lErr != nil {
				// If that fails, try with auth code from environment
				authCode := strings.ReplaceAll(os.Getenv("IPATOOL_AUTH_CODE"), " ", "")
				if authCode != "" {
					log.Printf("[ipatool] Re-login without auth code failed, trying with 2FA code...")
					loginOut, lErr = c.store.Login(appstore.LoginInput{
						Email:    acc.Email,
						Password: acc.Password,
						AuthCode: authCode,
					})
				}
				if lErr != nil {
					return "", fmt.Errorf("re-login after token expiry failed. If 2FA is required, set IPATOOL_AUTH_CODE with a fresh 6-digit code: %w", lErr)
				}
			}
			acc = loginOut.Account
			log.Printf("[ipatool] Re-login successful, retrying download...")
			out, err = tryDownload(acc)
		}
	}

	if err != nil {
		return "", fmt.Errorf("failed to download IPA for %q: %w", bundleID, err)
	}

	// Always replicate SINF so the package is usable with tools expecting
	// ipatool's behavior.
	if err := c.store.ReplicateSinf(appstore.ReplicateSinfInput{
		Sinfs:       out.Sinfs,
		PackagePath: out.DestinationPath,
	}); err != nil {
		return "", fmt.Errorf("failed to replicate SINF: %w", err)
	}

	return out.DestinationPath, nil
}

