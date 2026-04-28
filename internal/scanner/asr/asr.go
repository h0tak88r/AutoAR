package asr

import (
	"context"
	"fmt"
	"log"
)

// Options holds ASR scan options
type Options struct {
	Domain    string
	Mode      int
	Threads   int
	Wordlist  string
	Resolvers string
	Progress  func(string)
}

// Run executes the ASR scan based on the selected mode
func Run(ctx context.Context, opts Options) error {
	if opts.Mode < 1 || opts.Mode > 5 {
		return fmt.Errorf("invalid mode: %d (must be 1-5)", opts.Mode)
	}

	if opts.Progress == nil {
		opts.Progress = func(msg string) {
			log.Printf("[ASR] %s", msg)
		}
	}

	opts.Progress(fmt.Sprintf("Starting mode %d for %s", opts.Mode, opts.Domain))

	switch opts.Mode {
	case 1:
		return RunMode1(ctx, opts)
	case 2:
		return RunMode2(ctx, opts)
	case 3:
		return RunMode3(ctx, opts)
	case 4:
		return RunMode4(ctx, opts)
	case 5:
		return RunMode5(ctx, opts)
	}

	return nil
}

func deduplicate(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
