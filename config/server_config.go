package config

type ServerConfig struct {
	Port            string `json:"port"`
	Host            string `json:"host"`
	StaticFilesPath string `json:"staticFilesPath"`
	ClientLimit     int    `json:"clientLimit"`
	ReadTimeout     int    `json:"readTimeout"`
	WriteTimeout    int    `json:"writeTimeout"`
	IdleTimeout     int    `json:"idleTimeout"`
	ServerKey       string `json:"serverKey"`
}

func NewDefaultServerConfig() ServerConfig {
	return ServerConfig{
		Port:            "8080",
		Host:            "localhost",
		StaticFilesPath: "../client/frontend",
		ClientLimit:     100000,
		ReadTimeout:     60,
		WriteTimeout:    60,
		IdleTimeout:     300,
	}
}
func (c *ServerConfig) Validate() error {
	if c.Port == "" {
		return ErrInvalidPort
	}
	if c.Host == "" {
		return ErrInvalidHost
	}
	if c.ClientLimit <= 0 {
		return ErrInvalidClientLimit
	}
	if c.ReadTimeout <= 0 {
		return ErrInvalidReadTimeout
	}
	if c.WriteTimeout <= 0 {
		return ErrInvalidWriteTimeout
	}
	if c.IdleTimeout <= 0 {
		return ErrInvalidIdleTimeout
	}
	return nil
}
