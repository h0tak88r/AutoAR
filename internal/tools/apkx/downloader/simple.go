package downloader

// SimpleConfig is a simple configuration struct.
type SimpleConfig struct {
	PackageName string
	Source      string
}

// NewSimpleConfig creates a new SimpleConfig.
func NewSimpleConfig(packageName, source string) SimpleConfig {
	return SimpleConfig{
		PackageName: packageName,
		Source:      source,
	}
}

