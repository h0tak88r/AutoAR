package utils

import (
	"io"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	// Log is the global logger instance
	Log *logrus.Logger
)

// LogConfig holds logging configuration
type LogConfig struct {
	Level       string // debug, info, warn, error
	FilePath    string // Path to log file
	MaxSize     int    // Max size in MB before rotation
	MaxAge      int    // Max days to keep old logs
	MaxBackups  int    // Max number of old logs to keep
	Compress    bool   // Compress old logs
	JSONFormat  bool   // Use JSON format for file logs
}

// DefaultLogConfig returns default logging configuration
func DefaultLogConfig() LogConfig {
	return LogConfig{
		Level:      "info",
		FilePath:   "autoar-bot.log",
		MaxSize:    100,
		MaxAge:     7,
		MaxBackups: 3,
		Compress:   true,
		JSONFormat: true,
	}
}

// InitLogger initializes the global logger with file rotation
func InitLogger(config LogConfig) error {
	Log = logrus.New()

	// Set log level
	level, err := logrus.ParseLevel(config.Level)
	if err != nil {
		level = logrus.InfoLevel
	}
	Log.SetLevel(level)

	// Create log file directory if it doesn't exist
	logDir := filepath.Dir(config.FilePath)
	if logDir != "." && logDir != "" {
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return err
		}
	}

	// Configure log rotation
	fileWriter := &lumberjack.Logger{
		Filename:   config.FilePath,
		MaxSize:    config.MaxSize,
		MaxAge:     config.MaxAge,
		MaxBackups: config.MaxBackups,
		Compress:   config.Compress,
		LocalTime:  true,
	}

	// Use JSON formatter for file logs, text for console
	if config.JSONFormat {
		Log.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02 15:04:05",
		})
		// Write JSON to file only
		Log.SetOutput(fileWriter)
	} else {
		// Text format with colors for console
		Log.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02 15:04:05",
			ForceColors:     true,
		})
		// Write to both file and console
		multiWriter := io.MultiWriter(os.Stdout, fileWriter)
		Log.SetOutput(multiWriter)
	}

	Log.WithFields(logrus.Fields{
		"level":       config.Level,
		"file":        config.FilePath,
		"max_size":    config.MaxSize,
		"max_age":     config.MaxAge,
		"max_backups": config.MaxBackups,
		"compress":    config.Compress,
		"json_format": config.JSONFormat,
	}).Info("Logger initialized")

	return nil
}

// GetLogger returns the global logger instance
// If not initialized, returns a default logger
func GetLogger() *logrus.Logger {
	if Log == nil {
		Log = logrus.New()
		Log.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
	}
	return Log
}

// Close closes the log file
func CloseLogger() {
	if Log != nil {
		if closer, ok := Log.Out.(io.Closer); ok {
			closer.Close()
		}
	}
}
