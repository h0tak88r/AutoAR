package wpconfusion

import (
	"testing"
)

func TestIsAllowedSlugValid(t *testing.T) {
	if !isAllowedSlug("my-custom-plugin") {
		t.Error("isAllowedSlug(my-custom-plugin) should be true")
	}
	if !isAllowedSlug("random-slug") {
		t.Error("isAllowedSlug(random-slug) should be true")
	}
}

func TestIsAllowedSlugReserved(t *testing.T) {
	reservedTests := []string{"about", "admin", "browse", "category", "developers",
		"developer", "featured", "filter", "new", "page", "plugins", "popular",
		"post", "search", "tag", "updated", "upload", "wp-admin", "jquery", "wordpress",
		"akismet-anti-spam", "site-kit-by-google", "yoast-seo", "woo",
		"wp-media-folder", "wp-file-download", "wp-table-manager"}
	for _, slug := range reservedTests {
		t.Run(slug, func(t *testing.T) {
			if isAllowedSlug(slug) {
				t.Errorf("isAllowedSlug(%q) should be false (reserved)", slug)
			}
		})
	}
}

func TestIsAllowedSlugReservedCaseInsensitive(t *testing.T) {
	if isAllowedSlug("ADMIN") {
		t.Error("isAllowedSlug(ADMIN) should be false (reserved, case-insensitive)")
	}
	if isAllowedSlug("WordPress") {
		t.Error("isAllowedSlug(WordPress) should be false (reserved, case-insensitive)")
	}
}

func TestIsAllowedSlugTrademarkedPrefix(t *testing.T) {
	if isAllowedSlug("google-analytics-pro") {
		t.Error("isAllowedSlug(google-...) should be false (trademarked prefix)")
	}
	if isAllowedSlug("facebook-pixel") {
		t.Error("isAllowedSlug(facebook-pixel) should be false (trademarked via fbook)")
	}
	if isAllowedSlug("amazon-s3-uploader") {
		t.Error("isAllowedSlug(amazon-s3-uploader) should be false (trademarked prefix)")
	}
}

func TestIsAllowedSlugTrademarkedPrefixCaseInsensitive(t *testing.T) {
	if isAllowedSlug("GOOGLE-analytics") {
		t.Error("isAllowedSlug(GOOGLE-analytics) should be false (trademarked, case-insensitive)")
	}
}

func TestIsAllowedSlugNotTrademarkedWithoutDash(t *testing.T) {
	// "adobe" requires "adobe-" (with dash), so "adobe" alone is allowed
	if !isAllowedSlug("adobe") {
		t.Error("isAllowedSlug(adobe) should be true (trademark requires prefix with dash)")
	}
}

func TestIsAllowedSlugEmpty(t *testing.T) {
	if !isAllowedSlug("") {
		t.Error("isAllowedSlug('') should be true (not reserved, not trademarked)")
	}
}

func TestCheckPaidPluginsMatch(t *testing.T) {
	paidTests := []string{"woocommerce", "elementor", "divi", "wpml", "gravityforms",
		"advanced-custom-fields-pro", "wp-rocket", "ithemes-security"}
	for _, plugin := range paidTests {
		t.Run(plugin, func(t *testing.T) {
			if !checkPaidPlugins(plugin) {
				t.Errorf("checkPaidPlugins(%q) should be true", plugin)
			}
		})
	}
}

func TestCheckPaidPluginsContains(t *testing.T) {
	if !checkPaidPlugins("my-woocommerce-addon") {
		t.Error("checkPaidPlugins() should match via Contains")
	}
	if !checkPaidPlugins("premium-elementor-widgets") {
		t.Error("checkPaidPlugins() should match via Contains")
	}
}

func TestCheckPaidPluginsCaseInsensitive(t *testing.T) {
	if !checkPaidPlugins("WooCommerce") {
		t.Error("checkPaidPlugins(WooCommerce) should be true (case-insensitive)")
	}
}

func TestCheckPaidPluginsNonPaid(t *testing.T) {
	if checkPaidPlugins("my-free-plugin") {
		t.Error("checkPaidPlugins(my-free-plugin) should be false")
	}
	if checkPaidPlugins("") {
		t.Error("checkPaidPlugins('') should be false")
	}
}
