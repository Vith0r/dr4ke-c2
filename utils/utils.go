package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var (
	logFile     *os.File
	logger      *log.Logger
	logCallback func(level, message string) // Callback para streaming de logs
)

func InitializeLogger() error {
	logDir := "logs"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %v", err)
	}

	logPath := filepath.Join(logDir, fmt.Sprintf("server_%s.log", time.Now().Format("2006-01-02")))
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %v", err)
	}

	logFile = file
	logger = log.New(file, "", log.LstdFlags)
	return nil
}

func CloseLogger() error {
	if logFile != nil {
		return logFile.Close()
	}
	return nil
}

func LogOutput(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)

	if logger != nil {
		logger.Println(msg)
	}

	log.Println(msg)

	if logCallback != nil {
		level := ExtractLogLevel(msg)
		logCallback(level, msg)
	}
}

func GetStackTrace() string {
	const depth = 32
	var pcs [depth]uintptr
	n := runtime.Callers(3, pcs[:])
	var sb strings.Builder

	frames := runtime.CallersFrames(pcs[:n])
	for {
		frame, more := frames.Next()
		sb.WriteString(fmt.Sprintf("\n\t%s:%d", frame.File, frame.Line))
		if !more {
			break
		}
	}
	return sb.String()
}

func RecoverWithLog() {
	if r := recover(); r != nil {
		LogOutput("[PANIC] Recovered from panic: %v", r)
		LogOutput("[PANIC] Stack trace: %s", GetStackTrace())
	}
}

func SafeClose(closer interface{ Close() error }, resourceName string) {
	if closer != nil {
		if err := closer.Close(); err != nil {
			LogOutput("[ERROR] Failed to close %s: %v", resourceName, err)
		}
	}
}

func IsDirectory(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

func EnsureDirectoryExists(path string) error {
	if !IsDirectory(path) {
		if err := os.MkdirAll(path, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", path, err)
		}
	}
	return nil
}

func GetFileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("failed to get file info: %v", err)
	}
	return info.Size(), nil
}

func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func FormatInt(n int) (string, error) {
	if n == 0 {
		return "0", nil
	}

	if n == math.MinInt {
		return fmt.Sprintf("%d", math.MinInt), nil
	}

	return fmt.Sprintf("%d", n), nil
}

func GenerateSecureToken(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("invalid token length: must be greater than 0")
	}

	if length < 32 {
		length = 32
	}

	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}

	token := hex.EncodeToString(b)
	return token, nil
}

func SetLogCallback(callback func(level, message string)) {
	logCallback = callback
}

func ExtractLogLevel(message string) string {
	if strings.Contains(message, "[FATAL]") {
		return "FATAL"
	} else if strings.Contains(message, "[ERROR]") {
		return "ERROR"
	} else if strings.Contains(message, "[WARNING]") {
		return "WARNING"
	} else if strings.Contains(message, "[INFO]") {
		return "INFO"
	} else if strings.Contains(message, "[PANIC]") {
		return "PANIC"
	}
	return "INFO"
}
