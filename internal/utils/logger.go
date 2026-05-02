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
	// Log is the global logger instance.
	Log *logrus.Logger
)

// LogConfig holds logging configuration.
type LogConfig struct {
	Level      string // debug, info, warn, error
	FilePath   string // Path to log file; "-" disables file logging
	MaxSize    int    // Max size in MB before rotation
	MaxAge     int    // Max days to keep old logs
	MaxBackups int    // Max number of old logs to keep
	Compress   bool   // Compress old logs
	JSONFormat bool   // Use JSON format
}

// DefaultLogConfig returns default logging configuration.
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

// InitLogger initializes the global logger with optional file rotation.
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

// GetLogger returns the global logger instance. If not initialized, it returns
// a console logger so early startup paths still produce useful diagnostics.
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

// CloseLogger is kept for compatibility with callers that want an explicit
// shutdown hook. Lumberjack does not require closing.
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
