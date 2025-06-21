package builder

import "fmt"

type Validator struct{}

func NewValidator() *Validator {
	return &Validator{}
}
func (v *Validator) ValidateOptions(options BuildOptions) error {
	if options.ServerURL == "" {
		return fmt.Errorf("server URL is required")
	}
	if options.AuthToken == "" {
		return fmt.Errorf("authentication token is required")
	}
	if options.OutputFormat != "" && options.OutputFormat != "exe" && options.OutputFormat != "dll" {
		return fmt.Errorf("output format must be 'exe' or 'dll'")
	}
	return nil
}
func (v *Validator) SetDefaultOptions(options *BuildOptions) {
	if options.OutputName == "" {
		options.OutputName = "dr4ke-client"
	}
	if options.OutputDirectory == "" {
		options.OutputDirectory = "builds"
	}
	if options.OutputFormat == "" {
		options.OutputFormat = "exe"
	}
}
