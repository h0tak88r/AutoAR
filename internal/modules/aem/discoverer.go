package aem

import (
	"encoding/json"
	"io"
	"log"
	"strings"
	"sync"
)

// DiscoveryMethod is a function that checks if a URL is an AEM instance
type DiscoveryMethod func(baseURL string, client *HTTPClient) bool

var (
	discoveryMethods []DiscoveryMethod
	discoveryMutex   sync.Mutex
)

// RegisterDiscoveryMethod registers a discovery method
func RegisterDiscoveryMethod(method DiscoveryMethod) {
	discoveryMutex.Lock()
	defer discoveryMutex.Unlock()
	discoveryMethods = append(discoveryMethods, method)
}

// DiscoverAEMInstance checks if a URL is an AEM instance using all registered methods
func DiscoverAEMInstance(baseURL string, client *HTTPClient) bool {
	// Preflight check
	if !preflight(baseURL, client) {
		return false
	}

	discoveryMutex.Lock()
	methods := make([]DiscoveryMethod, len(discoveryMethods))
	copy(methods, discoveryMethods)
	discoveryMutex.Unlock()

	for _, method := range methods {
		if method(baseURL, client) {
			return true
		}
	}

	return false
}

// preflight checks if URL is accessible
func preflight(baseURL string, client *HTTPClient) bool {
	_, err := client.Get(baseURL, nil)
	return err == nil
}

// Initialize discovery methods
func init() {
	RegisterDiscoveryMethod(byLoginPage)
	RegisterDiscoveryMethod(byCSRFToken)
	RegisterDiscoveryMethod(byGeometrixxPage)
	RegisterDiscoveryMethod(byGetServlet)
	RegisterDiscoveryMethod(byBinReceive)
	RegisterDiscoveryMethod(byLoginStatusServlet)
	RegisterDiscoveryMethod(byBgTestServlet)
	RegisterDiscoveryMethod(byCRX)
	RegisterDiscoveryMethod(byGQLServlet)
	RegisterDiscoveryMethod(byCSSJS)
	RegisterDiscoveryMethod(bySirenAPI)
	RegisterDiscoveryMethod(byPostServlet)
}

// byLoginPage checks for AEM login page
func byLoginPage(baseURL string, client *HTTPClient) bool {
	url := NormalizeURL(baseURL, "/libs/granite/core/content/login.html")
	resp, err := client.Get(url, nil)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		body, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(body), "Welcome to Adobe Experience Manager") {
			return true
		}
	}
	return false
}

// byCSRFToken checks for CSRF token endpoint
func byCSRFToken(baseURL string, client *HTTPClient) bool {
	url := NormalizeURL(baseURL, "/libs/granite/csrf/token.json")
	resp, err := client.Get(url, nil)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		ct := ContentType(resp.Header.Get("Content-Type"))
		if ct == "application/json" {
			body, _ := io.ReadAll(resp.Body)
			if strings.Contains(string(body), `"token"`) {
				return true
			}
		}
	}
	return false
}

// byGeometrixxPage checks for Geometrixx demo page
func byGeometrixxPage(baseURL string, client *HTTPClient) bool {
	url := NormalizeURL(baseURL, "/content/geometrixx/en.html")
	resp, err := client.Get(url, nil)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		body, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(body), "Geometrixx has been selling") {
			return true
		}
	}
	return false
}

// byGetServlet checks for DefaultGetServlet
func byGetServlet(baseURL string, client *HTTPClient) bool {
	paths := []string{
		"/", "/content", "/content/dam", "/bin", "/etc", "/var",
	}
	suffixes := []string{
		".json", ".1.json", ".childrenlist.json", ".childrenlist.html", ".ext.json",
		".children.json", "...4.2.1...json", ".json/a.css", ".json/a.html", ".json/a.png",
		".json/a.ico", ".json;%0aa.css", ".json;%0aa.html", ".json;%0aa.png",
		".json;%0aa.ico", ".json?a.css", ".json?a.ico", ".json?a.html",
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
				bodyStr := string(body)
				resp.Body.Close()

				if strings.Contains(bodyStr, `"jcr:primaryType":`) ||
					strings.Contains(bodyStr, "data-coral-columnview-path") {
					return true
				}

				// Try to parse as JSON
				var jsonData interface{}
				if err := json.Unmarshal(body, &jsonData); err == nil {
					if m, ok := jsonData.(map[string]interface{}); ok {
						if _, exists := m["jcr:primaryType"]; exists {
							return true
						}
						if parent, ok := m["parent"].(map[string]interface{}); ok {
							if _, exists := parent["resourceType"]; exists {
								return true
							}
						}
					}
					if arr, ok := jsonData.([]interface{}); ok && len(arr) > 0 {
						if item, ok := arr[0].(map[string]interface{}); ok {
							if _, exists := item["type"]; exists {
								return true
							}
						}
					}
				}
			}
		}
	}
	return false
}

// byBinReceive checks for /bin/receive endpoint
func byBinReceive(baseURL string, client *HTTPClient) bool {
	paths := []string{
		"/bin/receive?sling:authRequestLogin=1",
		"/bin/receive.servlet?sling:authRequestLogin=1",
	}
	suffixes := []string{".css", ".html", ".js", ".ico", ".png", ".gif", ".1.json", "...4.2.1...json"}

	for _, path := range paths {
		for _, suffix := range suffixes {
			url := NormalizeURL(baseURL, path+suffix)
			resp, err := client.Get(url, nil)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode == 401 {
				wwwAuth := strings.ToLower(resp.Header.Get("WWW-Authenticate"))
				if strings.Contains(wwwAuth, "day") || strings.Contains(wwwAuth, "sling") ||
					strings.Contains(wwwAuth, "aem") || strings.Contains(wwwAuth, "communique") ||
					strings.Contains(wwwAuth, "adobe") {
					return true
				}
			}
		}
	}
	return false
}

// byLoginStatusServlet checks for LoginStatusServlet
func byLoginStatusServlet(baseURL string, client *HTTPClient) bool {
	paths := []string{
		"/system/sling/loginstatus",
		"///system///sling///loginstatus",
	}
	suffixes := []string{".json", ".css", ".png", ".gif", ".html", ".ico", ".json/a.1.json",
		".json;%0aa.css", ".json;%0aa.html", ".json;%0aa.ico"}

	for _, path := range paths {
		for _, suffix := range suffixes {
			url := NormalizeURL(baseURL, path+suffix)
			resp, err := client.Get(url, nil)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode == 200 {
				body, _ := io.ReadAll(resp.Body)
				if strings.Contains(string(body), "authenticated=") {
					return true
				}
			}
		}
	}
	return false
}

// byBgTestServlet checks for background test servlet
func byBgTestServlet(baseURL string, client *HTTPClient) bool {
	paths := []string{
		"/system/bgservlets/test",
		"///system///bgservlets///test",
	}
	suffixes := []string{".json", ".css", ".png", "ico", ".gif", ".html", ".json/a.1.json",
		".json;%0aa.css", ".json;%0aa.html", ".json;%0aa.ico"}

	for _, path := range paths {
		for _, suffix := range suffixes {
			url := NormalizeURL(baseURL, path+suffix)
			resp, err := client.Get(url, nil)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode == 200 {
				body, _ := io.ReadAll(resp.Body)
				if strings.Contains(string(body), "All done.") && strings.Contains(string(body), "Cycle") {
					return true
				}
			}
		}
	}
	return false
}

// byCRX checks for CRX interfaces
func byCRX(baseURL string, client *HTTPClient) bool {
	paths := []string{
		"/crx/de/index.jsp",
		"/crx/explorer/browser/index.jsp",
		"/crx/packmgr/index.jsp",
	}
	suffixes := []string{"", ";%0aa.css", ";%0aa.html", ";%0aa.ico", ";%0aa.png", "?a.css", "?a.html",
		"?a.png", "?a.ico", "/a.html", "/a.css", "/a.js", "/a.ico", "/a.png"}

	for _, path := range paths {
		for _, suffix := range suffixes {
			url := NormalizeURL(baseURL, path+suffix)
			resp, err := client.Get(url, nil)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode == 200 {
				body, _ := io.ReadAll(resp.Body)
				bodyStr := string(body)
				if strings.Contains(bodyStr, "CRXDE Lite") || strings.Contains(bodyStr, "Content Explorer") ||
					strings.Contains(bodyStr, "CRX Package Manager") {
					return true
				}
			}
		}
	}
	return false
}

// byGQLServlet checks for GQL servlet
func byGQLServlet(baseURL string, client *HTTPClient) bool {
	paths := []string{
		"/bin/wcm/search/gql.servlet.json?query=type:base%20limit:..1&pathPrefix=",
		"/bin/wcm/search/gql.json?query=type:base%20limit:..1&pathPrefix=",
		"///bin///wcm///search///gql.servlet.json?query=type:base%20limit:..1&pathPrefix=",
		"///bin///wcm///search///gql.json?query=type:base%20limit:..1&pathPrefix=",
	}

	for _, path := range paths {
		url := NormalizeURL(baseURL, path)
		resp, err := client.Get(url, nil)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(resp.Body)
			var jsonData map[string]interface{}
			if err := json.Unmarshal(body, &jsonData); err == nil {
				if _, exists := jsonData["hits"]; exists {
					return true
				}
			}
		}
	}
	return false
}

// byCSSJS checks for AEM-specific CSS/JS files
func byCSSJS(baseURL string, client *HTTPClient) bool {
	paths := []string{
		"/etc/clientlibs/wcm/foundation/main.css",
		"/etc/clientlibs/social/connect.js",
		"/etc/clientlibs/foundation/main.css",
		"/etc/clientlibs/mobile/user.js",
		"/etc/clientlibs/screens/player/bootloader/js/bootloader.js",
		"/system/sling.js",
	}

	for _, path := range paths {
		url := NormalizeURL(baseURL, path)
		resp, err := client.Get(url, nil)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(resp.Body)
			bodyStr := string(body)
			if strings.Contains(bodyStr, "ADOBE CONFIDENTIAL") || strings.Contains(bodyStr, "JCR repository") {
				return true
			}
		}
	}
	return false
}

// bySirenAPI checks for Siren API
func bySirenAPI(baseURL string, client *HTTPClient) bool {
	paths := []string{
		"/api/content.json",
		"/api/content.json.css",
		"/api/content.json.js",
		"/api/content.json.ico",
		"/api/content.json.png",
	}

	for _, path := range paths {
		url := NormalizeURL(baseURL, path)
		resp, err := client.Get(url, nil)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(resp.Body)
			if strings.Contains(string(body), `"links":`) {
				return true
			}
		}
	}
	return false
}

// byPostServlet checks for POST servlet
func byPostServlet(baseURL string, client *HTTPClient) bool {
	paths := []string{"/", "/content", "/content/dam"}
	suffixes := []string{".json", ".1.json", ".json/a.css", ".json/a.html", ".json/a.ico", ".json/a.png",
		".json/a.gif", ".json/a.1.json", ".json;%0aa.css", ".json;%0aa.html", ".json;%0aa.js",
		".json;%0aa.png", ".json;%0aa.ico", "...4.2.1...json", "?a.ico", "?a.html", "?a.css", "?a.png"}

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
			defer resp.Body.Close()

			if resp.StatusCode == 200 {
				body, _ := io.ReadAll(resp.Body)
				bodyStr := string(body)
				if strings.Contains(bodyStr, "Null Operation Status:") || strings.Contains(bodyStr, "Parent Location") {
					return true
				}
			}
		}
	}
	return false
}

// DiscoverAEMFromURLs discovers AEM instances from a list of URLs
func DiscoverAEMFromURLs(urls []string, client *HTTPClient, workers int) []string {
	if workers <= 0 {
		workers = 50
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	results := make(chan string, len(urls))
	var mu sync.Mutex
	discovered := make(map[string]bool)

	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}

		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if DiscoverAEMInstance(url, client) {
				mu.Lock()
				if !discovered[url] {
					discovered[url] = true
					results <- url
				}
				mu.Unlock()
			}
		}(u)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var found []string
	for url := range results {
		found = append(found, url)
		log.Printf("[AEM] Discovered AEM instance: %s", url)
	}

	return found
}

