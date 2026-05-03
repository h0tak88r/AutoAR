package utils

import (
	"github.com/h0tak88r/AutoAR/internal/logger"
	"github.com/sirupsen/logrus"
)

// Log is the global logrus logger instance.
// Note: This is a copy of logger.Log for backward compatibility.
var Log *logrus.Logger

// Re-export types and functions for backward compatibility

type LogConfig = logger.LogConfig

func DefaultLogConfig() LogConfig {
	return logger.DefaultLogConfig()
}

func LogConfigFromEnv(defaultFile string) LogConfig {
	return logger.LogConfigFromEnv(defaultFile)
}

func InitLogger(config LogConfig) error {
	err := logger.InitLogger(config)
	Log = logger.Log
	return err
}

func GetLogger() *logrus.Logger {
	l := logger.GetLogger()
	Log = l
	return l
}

func CloseLogger() {
	// lumberjack doesn't need explicit close
}
