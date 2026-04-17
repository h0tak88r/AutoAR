// Package utils — webhook stubs.
//
// Discord webhook sending has been removed from the scan pipeline.
// When the Discord bot is active it handles all notifications directly via the
// bot API.  The functions below are kept as no-ops so that existing call sites
// continue to compile without modification.
package utils

// SendWebhookLog is a no-op stub — webhook delivery has been removed.
func SendWebhookLog(_ string) error { return nil }

// SendWebhookLogAsync is a no-op stub — webhook delivery has been removed.
func SendWebhookLogAsync(_ string) {}

// SendWebhookEmbed is a no-op stub — webhook delivery has been removed.
func SendWebhookEmbed(_, _ string, _ int, _ []map[string]interface{}) error { return nil }

// SendWebhookFile is a no-op stub — webhook delivery has been removed.
func SendWebhookFile(_, _ string) error { return nil }

// SendWebhookFileAsync is a no-op stub — webhook delivery has been removed.
func SendWebhookFileAsync(_, _ string) {}
