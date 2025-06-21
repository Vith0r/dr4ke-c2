package builder

type BuildOptions struct {
	ServerURL       string  `json:"serverUrl"`
	AuthToken       string  `json:"authToken"`
	DebugMode       bool    `json:"debugMode"`
	HideConsole     bool    `json:"hideConsole"`
	UACMode         bool    `json:"uacMode"`
	StripDebug      bool    `json:"stripDebug"`
	PumpEnabled     bool    `json:"pumpEnabled"`
	PumpSize        float64 `json:"pumpSize"`
	PumpUnit        string  `json:"pumpUnit"`
	OutputName      string  `json:"outputName"`
	OutputDirectory string  `json:"outputDirectory"`
	OutputFormat    string  `json:"outputFormat"`
}
type BuildResult struct {
	Success      bool   `json:"success"`
	OutputPath   string `json:"outputPath"`
	ErrorMessage string `json:"errorMessage"`
	BuildTime    int64  `json:"buildTime"`
	Stdout       string `json:"stdout,omitempty"`
	Stderr       string `json:"stderr,omitempty"`
}
