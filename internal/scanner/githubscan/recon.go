package githubscan

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/h0tak88r/AutoAR/internal/logger"
)

// ─── Repo recon pass ──────────────────────────────────────────────────────────
// TruffleHog finds SECRETS; this pass pre-chews everything else the AI hunter
// would otherwise grep for by hand during source-code recon:
//
//   endpoints        absolute URLs + API/admin/debug/internal paths referenced in code
//   infra            DB connection strings, private IPs, internal hostnames (.internal/.corp/.local, cluster.local)
//   cloud            S3 buckets, Azure blobs, GCP buckets/service accounts
//   debug-admin      debug flags, actuator/phpinfo/.env references, admin panels
//   comments         TODO/FIXME/HACK/XXX lines that mention security-relevant words
//   tech-stack       framework + version from manifests (package.json, go.mod, requirements.txt, composer.json, pom.xml)
//   auth             OAuth/OIDC/SAML/JWT endpoints and issuers
//   emails           email addresses
//   hostnames        non-CDN hostnames referenced in code (subdomain recon)
//   sourcemaps       sourceMappingURL references (original-source exposure)
//
// Output: recon.md (human/AI digest, the file a hunter reads FIRST) and
// recon.json (same data, machine-readable) in the scan's results dir.
// Bounded: per-category caps, binary/large/vendor dirs skipped, walk timeboxed.

const (
	reconCloneTimeout = 3 * time.Minute
	reconFileMaxBytes = 2 << 20 // skip files >2MB
	reconPerCatCap    = 150     // max matches per category
	reconLineKeep     = 240     // max bytes of a matched line kept
	reconSkipDirs     = ".git,node_modules,vendor,dist,build,.next,target,__pycache__,.terraform,bin,obj"
	reconMaxFileBytes = 8 << 20 // total bytes read per file before truncating content
)

// reconRule is one categorized regex.
type reconRule struct {
	re *regexp.Regexp
}

var (
	reURL        = regexp.MustCompile(`https?://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,200}`)
	rePath       = regexp.MustCompile(`["'` + "`" + `](/[a-zA-Z0-9_./-]*(?:api|admin|internal|debug|actuator|swagger|graphql|backup|config|management|console|portal|private|test|staging)[a-zA-Z0-9_./-]*)["'` + "`" + `]`)
	reDBConn     = regexp.MustCompile(`(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql|jdbc:[a-z]+)://[^\s"'` + "`" + `]{4,160}`)
	rePrivIP     = regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`)
	reIntHost    = regexp.MustCompile(`[a-zA-Z0-9._-]+\.(?:internal|local|corp|lan|svc\.cluster\.local|intranet)`)
	reS3         = regexp.MustCompile(`[a-z0-9][a-z0-9.-]{2,60}\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com|s3://[a-z0-9][a-z0-9.-]{2,60}`)
	reAzureGCP   = regexp.MustCompile(`[a-z0-9-]{3,60}\.blob\.core\.windows\.net|[a-z0-9-]{3,60}\.storage\.googleapis\.com|[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com`)
	reDebugFlag  = regexp.MustCompile(`(?i)(?:DEBUG\s*[=:]\s*true|debug\s*=\s*true|spring\.profiles\.active\s*=\s*dev|app\.debug\s*=\s*true|phpinfo\(\))`)
	reDotEnv     = regexp.MustCompile(`["'` + "`" + `][^"'` + "`" + `]*\.env[^"'` + "`" + `]*["'` + "`" + `]|process\.env\.[A-Z_]{3,}`)
	reComments   = regexp.MustCompile(`(?i)(?://|#|/\*)\s*(?:TODO|FIXME|HACK|XXX|NOTE|WARNING)\b.{0,200}`)
	reCommentHot = regexp.MustCompile(`(?i)password|secret|token|credential|api[-_]?key|internal|production|prod only|do not|don't|remove before|temporary|workaround`)
	reOAuth      = regexp.MustCompile(`https?://[^\s"'` + "`" + `]*(?:oauth|oidc|authorize|access_token|/token|/callback|saml|sso|/.well-known/openid|/.well-known/jwks)[^\s"'` + "`" + `]{0,120}`)
	reJWTiss     = regexp.MustCompile(`["'` + "`" + `]https?://[^\s"'` + "`" + `]{4,120}(?:auth0\.com|okta\.com|azurewebsites|windows\.net|vercel\.app/auth)[^\s"'` + "`" + `]{0,60}["'` + "`" + `]`)
	reEmail      = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	reSourceMap  = regexp.MustCompile(`sourceMappingURL=[^\s*'"]+\.map|["'` + "`" + `][^\s"'` + "`" + `]*\.js\.map["'` + "`" + `]`)
	reHostname   = regexp.MustCompile(`[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,60}\.)+[a-zA-Z]{2,24}`)
	reGoModule   = regexp.MustCompile(`(?m)^module\s+(\S+)`)
	rePkgLine    = regexp.MustCompile(`(?m)^([a-zA-Z0-9@/._-]{2,80})[=<>~!]{1,3}([0-9][0-9a-zA-Z.+*_!-]{0,40})`)
)

// reconCategories drives the scan: category -> rules.
var reconCategories = map[string][]reconRule{
	"endpoints":   {{re: reURL}, {re: rePath}},
	"infra":       {{re: reDBConn}, {re: rePrivIP}, {re: reIntHost}},
	"cloud":       {{re: reS3}, {re: reAzureGCP}},
	"debug-admin": {{re: reDebugFlag}, {re: reDotEnv}},
	"comments":    {{re: reComments}},
	"auth":        {{re: reOAuth}, {re: reJWTiss}},
	"emails":      {{re: reEmail}},
	"sourcemaps":  {{re: reSourceMap}},
	"hostnames":   {{re: reHostname}},
}

// reconCommentHot filters the comments category: a TODO is only interesting
// when it also mentions a security-relevant word.
var reconCommentHotRE = reCommentHot

// reconSkipDirSet is the directory basename skip-list.
var reconSkipDirSet = func() map[string]bool {
	m := map[string]bool{}
	for _, d := range strings.Split(reconSkipDirs, ",") {
		m[strings.TrimSpace(d)] = true
	}
	return m
}()

// reconHostnameExtra returns non-CDN hostnames from a line, filtered against a
// public-host denylist so the "hostnames" category stays recon-useful.
var (
	reconHostnameDeny = regexp.MustCompile(`(?i)github\.com|githubusercontent|npmjs\.org|yarnpkg\.com|golang\.org|googleapis\.com/licenses|w3\.org|schema\.org|apache\.org|opensource\.org|gnu\.org|example\.com|localhost|jquery|bootstrapcdn|jsdelivr|unpkg\.com|cloudflare\.com|gstatic\.com|googleapis\.com/fonts|gravatar|wikipedia\.org|stackoverflow|mozilla\.org|readthedocs|mit\.edu|apache\.license`)
)

// reconScanFile runs the rules over one file and appends matches.
func reconScanFile(relPath, content string, into map[string]map[string]bool) {
	if strings.ContainsRune(content[:min2(len(content), 4096)], 0) {
		return // binary
	}
	scanner := bufio.NewScanner(strings.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), reconLineKeep*4)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		if len(line) > reconLineKeep {
			line = line[:reconLineKeep]
		}
		for cat, rules := range reconCategories {
			for _, r := range rules {
				if len(into[cat]) >= reconPerCatCap {
					continue
				}
				for _, m := range r.re.FindAllString(line, -1) {
					m = strings.TrimSpace(m)
					if m == "" || len(m) < 5 {
						continue
					}
					if cat == "comments" && !reconCommentHotRE.MatchString(m) {
						continue
					}
					if cat == "hostnames" && (len(m) < 7 || reconHostnameDeny.MatchString(m)) {
						continue
					}
					key := relPath + " :: " + m
					if len(into[cat]) < reconPerCatCap {
						into[cat][key] = true
					}
				}
			}
		}
	}
	_ = lineNo
}

func min2(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ReconScan walks a checked-out repo tree and writes recon.md + recon.json.
// Returns the number of findings and the digest path.
func ReconScan(repoDir, outDir string) (int, string, error) {
	into := map[string]map[string]bool{}
	for cat := range reconCategories {
		into[cat] = map[string]bool{}
	}

	// Manifest tech-stack first (structured reads, not line regexes).
	stack := reconTechStack(repoDir)

	deadline := time.Now().Add(2 * time.Minute)
	err := filepath.Walk(repoDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if info != nil && info.IsDir() && reconSkipDirSet[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if time.Now().After(deadline) {
			return filepath.SkipAll
		}
		// Walk reports Lstat info: a symlink's size is its own, so a hostile
		// repo's a.js -> /dev/zero or -> /proc/self/environ would pass the size
		// check and then be followed by the read. Only regular files are read.
		if !info.Mode().IsRegular() || info.Size() > reconFileMaxBytes {
			return nil
		}
		data, rerr := readRegularFile(path, reconFileMaxBytes)
		if rerr != nil || len(data) == 0 {
			return nil
		}
		if len(data) > reconMaxFileBytes {
			data = data[:reconMaxFileBytes]
		}
		rel, rerr := filepath.Rel(repoDir, path)
		if rerr != nil {
			rel = path
		}
		reconScanFile(rel, string(data), into)
		return nil
	})
	if err != nil {
		logger.GetLogger().Infof("[REPO-RECON] walk error (partial results kept): %v", err)
	}

	total := 0
	for _, m := range into {
		total += len(m)
	}
	total += len(stack)

	// --- write digest -----------------------------------------------------
	mdPath := filepath.Join(outDir, "recon.md")
	var b strings.Builder
	b.WriteString("# Repo recon digest — pre-chewed for manual review\n\n")
	b.WriteString("> Generated by AutoAR repo recon pass. Categories are capped; " +
		"this is a starting map, not an exhaustive inventory.\n\n")
	if len(stack) > 0 {
		b.WriteString("## Tech stack (from manifests)\n")
		for _, s := range stack {
			b.WriteString("- " + s + "\n")
		}
		b.WriteString("\n")
	}
	for _, cat := range []string{"endpoints", "infra", "cloud", "debug-admin", "auth", "comments", "emails", "hostnames", "sourcemaps"} {
		items := into[cat]
		if len(items) == 0 {
			continue
		}
		fmt.Fprintf(&b, "## %s (%d)\n", cat, len(items))
		for k := range items {
			b.WriteString("- " + k + "\n")
		}
		b.WriteString("\n")
	}
	if err := os.WriteFile(mdPath, []byte(b.String()), 0o644); err != nil {
		return total, "", err
	}

	// --- write machine-readable copy -------------------------------------
	jsonPath := filepath.Join(outDir, "recon.json")
	doc := map[string]interface{}{"stack": stack, "findings": into}
	if jb, jerr := json.MarshalIndent(doc, "", " "); jerr == nil {
		_ = os.WriteFile(jsonPath, jb, 0o644)
	}

	logger.GetLogger().Infof("[REPO-RECON] %d finding(s) -> %s", total, mdPath)
	return total, mdPath, nil
}

// reconTechStack pulls framework+version facts from the usual manifests.
func reconTechStack(repoDir string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if s != "" && !seen[s] && len(out) < 80 {
			seen[s] = true
			out = append(out, s)
		}
	}

	if data, err := readRegularFile(filepath.Join(repoDir, "package.json"), reconFileMaxBytes); err == nil {
		var pkg struct {
			Name         string            `json:"name"`
			Version      string            `json:"version"`
			Dependencies map[string]string `json:"dependencies"`
			DevDeps      map[string]string `json:"devDependencies"`
		}
		if json.Unmarshal(data, &pkg) == nil {
			if pkg.Name != "" {
				add("package: " + pkg.Name + " " + pkg.Version)
			}
			// Surface the runtime/framework deps, not every utility.
			for _, k := range []string{"express", "next", "react", "vue", "angular", "@angular/core", "svelte", "nuxt", "fastify", "nestjs", "@nestjs/core", "django", "laravel/framework", "electron"} {
				for src, deps := range map[string]map[string]string{"deps": pkg.Dependencies, "dev": pkg.DevDeps} {
					if v, ok := deps[k]; ok {
						add("npm: " + k + " " + v + " (" + src + ")")
					}
				}
			}
			n := 0
			for k, v := range pkg.Dependencies {
				if n >= 12 {
					break
				}
				add("dep: " + k + " " + v)
				n++
			}
		}
	}
	if data, err := readRegularFile(filepath.Join(repoDir, "go.mod"), reconFileMaxBytes); err == nil {
		if m := reGoModule.FindStringSubmatch(string(data)); m != nil {
			add("go module: " + m[1])
		}
		for _, m := range rePkgLine.FindAllStringSubmatch(string(data), -1) {
			if strings.HasPrefix(m[1], "github.com/") || strings.HasPrefix(m[1], "golang.org/") {
				add("go dep: " + m[1] + " " + m[2])
				if len(out) >= 80 {
					break
				}
			}
		}
	}
	for _, f := range []string{"requirements.txt", "Pipfile", "composer.json", "Gemfile"} {
		if _, err := os.Stat(filepath.Join(repoDir, f)); err == nil {
			add("manifest present: " + f)
		}
	}
	return out
}

// readRegularFile reads at most max bytes of path, refusing anything that is not
// a regular file — symlinks, devices, FIFOs — and a path swapped between the
// Lstat and the open (the opened file must be the Lstat'ed one).
func readRegularFile(path string, max int64) ([]byte, error) {
	li, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !li.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !os.SameFile(li, fi) {
		return nil, fmt.Errorf("%s: changed while opening", path)
	}
	return io.ReadAll(io.LimitReader(f, max))
}

// shallowClone clones repoURL depth-1 into dest. Returns the exec error.
// core.symlinks=false checks symlinks out as plain files holding the link
// text, so nothing in the clone can point outside it; only the https transport
// is allowed (no file:// clones of the server's own repos, no ext::).
func shallowClone(repoURL, dest string) error {
	if err := os.RemoveAll(dest); err != nil {
		logger.GetLogger().Infof("[REPO-RECON] could not clear %s: %v", dest, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), reconCloneTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git",
		"-c", "core.symlinks=false", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
		"clone", "--depth", "1", "--single-branch", "--", repoURL, dest)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git clone: %v: %s", err, clip(strings.TrimSpace(string(out)), 200))
	}
	return nil
}

// clip bounds a string for log output.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
