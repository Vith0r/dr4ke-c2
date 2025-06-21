package builder

import (
	"dr4ke-c2/server/utils"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type DirectoryManager struct{}

func NewDirectoryManager() *DirectoryManager {
	return &DirectoryManager{}
}

func (dm *DirectoryManager) copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

func (dm *DirectoryManager) copyModuleFiles(tempDir string) error {
	templateDir := filepath.Join("builder", "template")
	files := []string{"go.mod", "go.sum"}

	for _, file := range files {
		src := filepath.Join(templateDir, file)
		dst := filepath.Join(tempDir, file)
		if err := dm.copyFile(src, dst); err != nil {
			return fmt.Errorf("failed to copy %s: %v", file, err)
		}
		utils.LogOutput("[BUILDER] Copied %s to build directory", file)
	}

	return nil
}

func (dm *DirectoryManager) PrepareBuildEnvironment(options BuildOptions) (string, error) {
	if err := os.MkdirAll(options.OutputDirectory, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %v", err)
	}
	tempDir, err := ioutil.TempDir("", "dr4ke-build-")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary directory: %v", err)
	}
	utils.LogOutput("[BUILDER] Created temporary build directory: %s", tempDir)
	if err := dm.copyModuleFiles(tempDir); err != nil {
		os.RemoveAll(tempDir)
		return "", err
	}

	return tempDir, nil
}

func (dm *DirectoryManager) GetOutputPath(options BuildOptions) string {
	outputPath := filepath.Join(options.OutputDirectory, options.OutputName)

	if options.OutputFormat == "dll" {
		if runtime.GOOS == "windows" && !strings.HasSuffix(outputPath, ".dll") {
			outputPath += ".dll"
		}
	} else {
		if runtime.GOOS == "windows" && !strings.HasSuffix(outputPath, ".exe") {
			outputPath += ".exe"
		}
	}

	return outputPath
}
