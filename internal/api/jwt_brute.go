package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"hash"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/gin-gonic/gin"
)

// defaultJWTSecrets is the bundled common-secret wordlist used by the JWT
// brute-force endpoint when the caller does not opt out. It is embedded so the
// feature works without depending on the external Wordlists submodule.
//
//go:embed jwt_secrets.txt
var defaultJWTSecrets string

// maxJWTCandidates caps how many secrets a single brute request will try, so a
// huge pasted wordlist can't pin the CPU indefinitely.
const maxJWTCandidates = 100_000

// maxJWTTokenLen caps the pasted token: every candidate HMACs the whole signing
// input, so a multi-MB "token" multiplied the work per candidate.
const maxJWTTokenLen = 8 << 10

// jwtBruteBusy serializes brute-force requests: each one saturates the CPU
// cores, and concurrent requests multiplied that across the whole box.
var jwtBruteBusy atomic.Bool

type jwtBruteRequest struct {
	Token string `json:"token"`
	// Secrets is an optional caller-supplied list (newline- or comma-separated)
	// tried in addition to (or instead of) the bundled default list.
	Secrets string `json:"secrets"`
	// UseDefault toggles the bundled wordlist. Defaults to true when omitted.
	UseDefault *bool `json:"use_default"`
}

// apiJWTBrute attempts to recover the HMAC secret of a pasted JWT by trying a
// wordlist of candidate secrets. Only HS256/HS384/HS512 (symmetric HMAC) tokens
// can be cracked this way — asymmetric algorithms (RS*/ES*/PS*/EdDSA) are
// rejected with a clear message. Cracking happens in parallel across CPU cores.
func apiJWTBrute(c *gin.Context) {
	// Cap the request body so a giant pasted wordlist can't exhaust memory.
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16<<20) // 16 MiB
	var req jwtBruteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	token := strings.TrimSpace(req.Token)
	if len(token) > maxJWTTokenLen {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token too long (max 8 KB)"})
		return
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "not a valid JWT (expected header.payload.signature)"})
		return
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JWT header encoding"})
		return
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JWT header JSON"})
		return
	}

	alg := strings.ToUpper(strings.TrimSpace(header.Alg))
	var newHash func() hash.Hash
	switch alg {
	case "HS256":
		newHash = sha256.New
	case "HS384":
		newHash = sha512.New384
	case "HS512":
		newHash = sha512.New
	default:
		c.JSON(http.StatusOK, gin.H{
			"found": false,
			"alg":   header.Alg,
			"error": "only HMAC algorithms (HS256/HS384/HS512) can be brute-forced; this token uses \"" + header.Alg + "\"",
		})
		return
	}

	wantSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JWT signature encoding"})
		return
	}
	signingInput := []byte(parts[0] + "." + parts[1])

	if !jwtBruteBusy.CompareAndSwap(false, true) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "another JWT brute-force is already running — try again when it finishes"})
		return
	}
	defer jwtBruteBusy.Store(false)

	candidates, truncated := buildJWTSecretCandidates(req, maxJWTCandidates)

	// Stop hashing when the client goes away instead of finishing the list.
	ctx := c.Request.Context()
	found, secret, tried := bruteForceJWTSecret(ctx, signingInput, wantSig, newHash, candidates)
	if ctx.Err() != nil {
		return // client disconnected; nobody is waiting for the answer
	}

	resp := gin.H{"alg": header.Alg, "tried": tried, "found": found}
	if found {
		resp["secret"] = secret
	}
	if truncated {
		resp["truncated"] = true
		resp["max_candidates"] = maxJWTCandidates
	}
	c.JSON(http.StatusOK, resp)
}

// buildJWTSecretCandidates merges the bundled wordlist (unless disabled) with any
// caller-supplied secrets, de-duplicating and always including the empty secret.
// At most max candidates are kept (truncated reports a longer input) — the
// cap is applied while parsing, so a huge pasted list is never fully expanded.
func buildJWTSecretCandidates(req jwtBruteRequest, max int) (out []string, truncated bool) {
	seen := make(map[string]struct{})
	out = make([]string, 0, 512)
	if max < 1 {
		max = 1
	}
	add := func(s string) {
		if _, ok := seen[s]; ok {
			return
		}
		if len(out) >= max {
			truncated = true
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	add("") // empty-key check (CVE-2018-1000531 class) — first, so the cap never drops it

	useDefault := req.UseDefault == nil || *req.UseDefault
	if useDefault {
		for _, line := range strings.Split(defaultJWTSecrets, "\n") {
			t := strings.TrimSpace(strings.TrimRight(line, "\r"))
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			add(t)
		}
	}

	if strings.TrimSpace(req.Secrets) != "" {
		normalized := strings.NewReplacer(",", "\n").Replace(req.Secrets)
		for _, line := range strings.Split(normalized, "\n") {
			if truncated {
				break
			}
			if t := strings.TrimSpace(line); t != "" {
				add(t)
			}
		}
	}
	return out, truncated
}

// bruteForceJWTSecret recomputes the HMAC signature for each candidate secret in
// parallel and returns the first match. Workers always drain the job channel
// (skipping work once a match is found or ctx is done) so the producer can
// never deadlock; the producer stops feeding as soon as ctx is cancelled.
func bruteForceJWTSecret(ctx context.Context, signingInput, wantSig []byte, newHash func() hash.Hash, candidates []string) (bool, string, int) {
	workers := runtime.NumCPU()
	if workers < 2 {
		workers = 2
	}

	jobs := make(chan string, 2048)
	var found atomic.Bool
	var tried atomic.Int64
	var secret atomic.Value
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cand := range jobs {
				if found.Load() || ctx.Err() != nil {
					continue // drain remaining jobs without hashing
				}
				tried.Add(1)
				mac := hmac.New(newHash, []byte(cand))
				mac.Write(signingInput)
				if hmac.Equal(mac.Sum(nil), wantSig) {
					if !found.Swap(true) {
						secret.Store(cand)
					}
				}
			}
		}()
	}

feed:
	for _, cand := range candidates {
		if found.Load() {
			break
		}
		select {
		case jobs <- cand:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()

	s, _ := secret.Load().(string)
	return found.Load(), s, int(tried.Load())
}
