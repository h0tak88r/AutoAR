package jwthack

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// ScanOptions controls how a JWT scan is performed.
type ScanOptions struct {
	Token            string
	WordlistPath     string
	MaxCrackAttempts int
	SkipCrack        bool
	SkipPayloads     bool
}

// Issue represents a single finding from the scan.
type Issue struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// ScanResult captures the decoded token and any identified issues.
type ScanResult struct {
	TokenType    string                 `json:"token_type"`   // JWT, JWE, Unknown
	Algorithm    string                 `json:"algorithm"`
	Header       map[string]interface{} `json:"header,omitempty"`
	Claims       map[string]interface{} `json:"claims,omitempty"`
	Issues       []Issue                `json:"issues,omitempty"`
	CrackedSecret string                `json:"cracked_secret,omitempty"`
}

// Scan performs a lightweight security analysis of a JWT token.
// It decodes the header/payload, flags common issues (alg=none, missing/expired exp, etc.),
// and optionally attempts HMAC secret cracking using a wordlist.
func Scan(opts ScanOptions) (*ScanResult, error) {
	token := strings.TrimSpace(opts.Token)
	if token == "" {
		return nil, fmt.Errorf("token is required")
	}

	parts := strings.Split(token, ".")
	res := &ScanResult{}
	if len(parts) == 3 {
		res.TokenType = "JWT"
	} else if len(parts) == 5 {
		res.TokenType = "JWE"
		// For JWE we only report type; deeper crypto analysis is out-of-scope for now.
		return res, nil
	} else {
		res.TokenType = "Unknown"
		return res, nil
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		res.Issues = append(res.Issues, Issue{Type: "invalid_header", Description: fmt.Sprintf("failed to base64url-decode header: %v", err)})
		return res, nil
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		res.Issues = append(res.Issues, Issue{Type: "invalid_header_json", Description: fmt.Sprintf("header is not valid JSON: %v", err)})
		return res, nil
	}
	res.Header = header

	alg, _ := header["alg"].(string)
	res.Algorithm = alg
	if alg == "" {
		res.Issues = append(res.Issues, Issue{Type: "missing_alg", Description: "JWT header is missing 'alg' field"})
	}
	if strings.EqualFold(alg, "none") {
		res.Issues = append(res.Issues, Issue{Type: "alg_none", Description: "Token uses 'none' algorithm which is insecure"})
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		res.Issues = append(res.Issues, Issue{Type: "invalid_payload", Description: fmt.Sprintf("failed to base64url-decode payload: %v", err)})
		return res, nil
	}
	var claims map[string]interface{}
	if len(payloadBytes) > 0 {
		if err := json.Unmarshal(payloadBytes, &claims); err != nil {
			res.Issues = append(res.Issues, Issue{Type: "invalid_payload_json", Description: fmt.Sprintf("payload is not valid JSON: %v", err)})
		} else if !opts.SkipPayloads {
			res.Claims = claims
		}
	}

	// Time-based claims
	now := time.Now().Unix()
	if expVal, ok := claims["exp"]; ok {
		if ts, ok := asInt64(expVal); ok {
			if ts < now {
				res.Issues = append(res.Issues, Issue{Type: "expired", Description: "Token is expired", Details: map[string]interface{}{"exp": ts}})
			}
		}
	} else {
		res.Issues = append(res.Issues, Issue{Type: "no_exp", Description: "Token has no 'exp' (expiration) claim"})
	}

	if nbfVal, ok := claims["nbf"]; ok {
		if ts, ok := asInt64(nbfVal); ok {
			if ts > now {
				res.Issues = append(res.Issues, Issue{Type: "not_yet_valid", Description: "Token is not yet valid (nbf in the future)", Details: map[string]interface{}{"nbf": ts}})
			}
		}
	}

	// Optional HMAC secret cracking for HS* algorithms
	if !opts.SkipCrack && opts.WordlistPath != "" && strings.HasPrefix(strings.ToUpper(alg), "HS") {
		secret, attempts, err := crackHMACSecret(parts, alg, opts.WordlistPath, opts.MaxCrackAttempts)
		if err != nil {
			res.Issues = append(res.Issues, Issue{Type: "crack_error", Description: fmt.Sprintf("error during HMAC cracking: %v", err)})
		} else if secret != "" {
			res.CrackedSecret = secret
			res.Issues = append(res.Issues, Issue{Type: "weak_secret", Description: "HMAC secret was found via wordlist", Details: map[string]interface{}{"attempts": attempts}})
		}
	}

	return res, nil
}

// asInt64 attempts to normalise various JSON number representations into an int64.
func asInt64(v interface{}) (int64, bool) {
	switch val := v.(type) {
	case float64:
		return int64(val), true
	case int64:
		return val, true
	case int:
		return int64(val), true
	case string:
		// Try to parse string representation of integer timestamp
		if val == "" {
			return 0, false
		}
		var n int64
		_, err := fmt.Sscan(val, &n)
		if err == nil {
			return n, true
		}
	}
	return 0, false
}

// crackHMACSecret tries to recover the HMAC secret for HS256/HS384/HS512
// using a wordlist. It returns the discovered secret (if any), the number
// of attempts made, and any error encountered.
func crackHMACSecret(parts []string, alg, wordlistPath string, max int) (string, int, error) {
	if len(parts) != 3 {
		return "", 0, fmt.Errorf("expected JWT with 3 parts for cracking")
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", 0, fmt.Errorf("failed to decode signature: %w", err)
	}

	file, err := os.Open(wordlistPath)
	if err != nil {
		return "", 0, fmt.Errorf("failed to open wordlist: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	message := parts[0] + "." + parts[1]
	attempts := 0

	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word == "" {
			continue
		}
		attempts++
		if max > 0 && attempts > max {
			break
		}

		mac, err := computeHMAC(message, word, alg)
		if err != nil {
			continue
		}
		if hmac.Equal(mac, sigBytes) {
			return word, attempts, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", attempts, fmt.Errorf("error reading wordlist: %w", err)
	}

	return "", attempts, nil
}

// computeHMAC computes HMAC for message with the given secret and algorithm.
func computeHMAC(message, secret, alg string) ([]byte, error) {
	switch strings.ToUpper(alg) {
	case "HS256":
		h := hmac.New(sha256.New, []byte(secret))
		h.Write([]byte(message))
		return h.Sum(nil), nil
	case "HS384":
		h := hmac.New(sha512.New384, []byte(secret))
		h.Write([]byte(message))
		return h.Sum(nil), nil
	case "HS512":
		h := hmac.New(sha512.New, []byte(secret))
		h.Write([]byte(message))
		return h.Sum(nil), nil
	default:
		return nil, fmt.Errorf("unsupported HMAC algorithm: %s", alg)
	}
}
