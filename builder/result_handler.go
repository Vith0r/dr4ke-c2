package builder

import (
	"dr4ke-c2/server/utils"
	"fmt"
)

type ResultHandler struct{}

func NewResultHandler() *ResultHandler {
	return &ResultHandler{}
}
func (rh *ResultHandler) CreateSuccessResult(outputPath string, buildTime int64, stdout, stderr string) BuildResult {
	return BuildResult{
		Success:    true,
		OutputPath: outputPath,
		BuildTime:  buildTime,
		Stdout:     stdout,
		Stderr:     stderr,
	}
}
func (rh *ResultHandler) CreateErrorResult(err error, stdout, stderr string) BuildResult {
	errorMessage := fmt.Sprintf("build failed: %v\nStdout:\n%s\nStderr:\n%s", err, stdout, stderr)
	utils.LogOutput("[BUILDER] Build failed with error: %v", err)
	return BuildResult{
		Success:      false,
		ErrorMessage: errorMessage,
		Stdout:       stdout,
		Stderr:       stderr,
	}
}
