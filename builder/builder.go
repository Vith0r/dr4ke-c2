package builder

import (
	"log"
	"os"
	"time"
)

type Builder struct {
	validator     *Validator
	dirManager    *DirectoryManager
	resultHandler *ResultHandler
}

func NewBuilder() *Builder {
	return &Builder{
		validator:     NewValidator(),
		dirManager:    NewDirectoryManager(),
		resultHandler: NewResultHandler(),
	}
}
func (b *Builder) BuildPayload(options BuildOptions) (BuildResult, error) {
	startTime := time.Now()
	log.Printf("[BUILDER] Received build request with options: %+v", options)
	if err := b.validator.ValidateOptions(options); err != nil {
		return BuildResult{}, err
	}
	b.validator.SetDefaultOptions(&options)
	tempDir, err := b.dirManager.PrepareBuildEnvironment(options)
	if err != nil {
		return BuildResult{}, err
	}
	defer os.RemoveAll(tempDir)
	if err := PrepareTemplate(tempDir, options); err != nil {
		return BuildResult{}, err
	}
	log.Printf("[BUILDER] Template prepared successfully in temporary directory: %s", tempDir)
	outputPath := b.dirManager.GetOutputPath(options)
	log.Printf("[BUILDER] Building client from source in: %s", tempDir)
	log.Printf("[BUILDER] Output path: %s", outputPath)
	stdout, stderr, err := runBuildCommand(tempDir, outputPath, options)
	if err != nil {
		return b.resultHandler.CreateErrorResult(err, stdout, stderr), err
	}
	result := b.resultHandler.CreateSuccessResult(
		outputPath,
		time.Since(startTime).Milliseconds(),
		stdout,
		stderr,
	)
	log.Printf("[BUILDER] Build successful! Output path: %s, Build time: %dms", result.OutputPath, result.BuildTime)
	return result, nil
}
