// Package utils provides shared, cross-cutting utilities for AutoAR:
// structured logging, HTTP client pooling, rate-limiting, concurrent uploads,
// scan-context tracking, pattern matching, and more.
//
// Logging
//
// All packages should use the global [Log] instance (or the safe accessor
// [GetLogger]) rather than the stdlib log package. Call [InitLogger] once at
// startup to configure the log level, file rotation, and format.
package utils

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	// Log is the global logrus logger instance, shared across all packages.
	// It is nil until [InitLogger] is called; use [GetLogger] for safe access.
	Log *logrus.Logger
)

// LogConfig holds configuration for the rotating file logger.
type LogConfig struct {
	Level      string // debug, info, warn, error
	FilePath   string // destination log file (rotated by lumberjack); "-" disables file logging
	MaxSize    int    // max megabytes per log file before rotation
	MaxAge     int    // max days to retain old log files
	MaxBackups int    // max number of old log files to keep
	Compress   bool   // gzip-compress rotated files
	JSONFormat bool   // true → JSON to file; false → coloured text to stdout+file
}

// DefaultLogConfig returns a production-ready LogConfig with 100 MB rotation,
// 7-day retention, and JSON output to "autoar-bot.log".
func DefaultLogConfig() LogConfig {
	return LogConfig{
		Level:      "info",
		FilePath:   "autoar-bot.log",
		MaxSize:    100,
		MaxAge:     7,
		MaxBackups: 3,
		Compress:   true,
		JSONFormat: false,
	}
}

// LogConfigFromEnv returns logging configuration using LOG_* environment values.
func LogConfigFromEnv(defaultFile string) LogConfig {
	config := DefaultLogConfig()
	if defaultFile != "" {
		config.FilePath = defaultFile
	}

	config.Level = GetEnv("LOG_LEVEL", config.Level)
	config.FilePath = GetEnv("LOG_FILE", config.FilePath)
	config.MaxSize = getEnvInt("LOG_MAX_SIZE", config.MaxSize)
	config.MaxAge = getEnvInt("LOG_MAX_AGE", config.MaxAge)
	config.MaxBackups = getEnvInt("LOG_MAX_BACKUPS", config.MaxBackups)
	config.Compress = getEnvBool("LOG_COMPRESS", config.Compress)
	config.JSONFormat = getEnvBool("LOG_JSON", config.JSONFormat)

	return config
}

// InitLogger configures and activates the global [Log] instance.
// When JSONFormat is true, structured JSON is written to the rotating file only.
// When false, coloured text is written to both stdout and the file.
// Returns an error if the log directory cannot be created.
func InitLogger(config LogConfig) error {
	logger := logrus.New()

	level, err := logrus.ParseLevel(strings.ToLower(strings.TrimSpace(config.Level)))
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	if config.JSONFormat {
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
		})
	} else {
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02 15:04:05",
			ForceColors:     isTerminal(os.Stdout),
		})
	}

	writer, err := buildLogWriter(config)
	if err != nil {
		return err
	}
	logger.SetOutput(writer)

	Log = logger
	Log.WithFields(logrus.Fields{
		"level":       level.String(),
		"file":        config.FilePath,
		"json":        config.JSONFormat,
		"max_size":    config.MaxSize,
		"max_age":     config.MaxAge,
		"max_backups": config.MaxBackups,
		"compress":    config.Compress,
	}).Info("Logger initialized")

	return nil
}

// GetLogger returns the global logger, initialising a default one if needed.
// Safe to call before [InitLogger]; the returned instance writes to stdout
// until the full logger is configured.
func GetLogger() *logrus.Logger {
	if Log == nil {
		_ = InitLogger(LogConfig{
			Level:      "info",
			FilePath:   "-",
			JSONFormat: false,
		})
	}
	return Log
}

// CloseLogger flushes and closes the underlying log file, if any.
// Call this from a shutdown hook to avoid truncated log entries.
// Kept for compatibility; lumberjack does not require an explicit close.
func CloseLogger() {}

func buildLogWriter(config LogConfig) (io.Writer, error) {
	if config.FilePath == "" || config.FilePath == "-" {
		return os.Stdout, nil
	}

	logDir := filepath.Dir(config.FilePath)
	if logDir != "." && logDir != "" {
		if err := os.MkdirAll(logDir, 0o755); err != nil {
			return nil, err
		}
	}

	fileWriter := &lumberjack.Logger{
		Filename:   config.FilePath,
		MaxSize:    config.MaxSize,
		MaxAge:     config.MaxAge,
		MaxBackups: config.MaxBackups,
		Compress:   config.Compress,
		LocalTime:  true,
	}

	if config.JSONFormat {
		return fileWriter, nil
	}
	return io.MultiWriter(os.Stdout, fileWriter), nil
}

func getEnvInt(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func getEnvBool(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return value
}

func isTerminal(file *os.File) bool {
	info, err := file.Stat()
	return err == nil && (info.Mode()&os.ModeCharDevice) != 0
}
