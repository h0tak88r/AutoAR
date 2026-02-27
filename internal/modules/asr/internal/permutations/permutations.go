package permutations

import (
	"fmt"
	"log"
	"strings"
)

// Generator handles subdomain permutations
type Generator struct {
	permutations []string
}

// NewGenerator creates a new permutations generator
func NewGenerator(permList []string) *Generator {
	return &Generator{
		permutations: permList,
	}
}

// maxPermutationInput is the maximum number of subdomains to generate permutations for.
// Generating permutations from very large lists causes OOM kills.
const maxPermutationInput = 5000

// Generate generates permutations for a list of subdomains
func (g *Generator) Generate(subdomains []string, domain string) []string {
	// Cap input size to prevent OOM kills on wildcard domains
	if len(subdomains) > maxPermutationInput {
		log.Printf("[WARN] Permutations input capped from %d to %d subdomains to prevent OOM. Use a more targeted wordlist or disable permutations for large scans.", len(subdomains), maxPermutationInput)
		subdomains = subdomains[:maxPermutationInput]
	}

	results := make(map[string]bool)

	for _, sub := range subdomains {
		// Strip the main domain to get the prefix
		prefix := strings.TrimSuffix(sub, "."+domain)
		if prefix == sub {
			continue // Not a subdomain of the target?
		}

		for _, perm := range g.permutations {
			// prefix-perm.domain
			results[fmt.Sprintf("%s-%s.%s", prefix, perm, domain)] = true
			// perm-prefix.domain
			results[fmt.Sprintf("%s-%s.%s", perm, prefix, domain)] = true
			// prefix.perm.domain
			results[fmt.Sprintf("%s.%s.%s", prefix, perm, domain)] = true
			// perm.prefix.domain
			results[fmt.Sprintf("%s.%s.%s", perm, prefix, domain)] = true
		}
	}

	var final []string
	for s := range results {
		final = append(final, s)
	}

	return final
}
