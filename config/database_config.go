package config

import "time"

type DatabaseConfig struct {
	Type        string `json:"type"`
	FilePath    string `json:"filePath"`
	CacheSize   int    `json:"cacheSize"`
	BoltTimeout int    `json:"boltTimeout"`
	NoSync      bool   `json:"noSync"`
}

func NewDefaultDatabaseConfig() DatabaseConfig {
	return DatabaseConfig{
		Type:        "bolt",
		FilePath:    "server/database/data/clients.db",
		CacheSize:   10000,
		BoltTimeout: 5,
		NoSync:      false,
	}
}
func (c *DatabaseConfig) Validate() error {
	if c.Type == "" {
		return ErrInvalidDatabaseType
	}
	if c.FilePath == "" {
		return ErrInvalidFilePath
	}
	if c.CacheSize <= 0 {
		return ErrInvalidCacheSize
	}
	if c.BoltTimeout <= 0 {
		return ErrInvalidBoltTimeout
	}
	return nil
}
func (c *DatabaseConfig) GetBoltTimeout() time.Duration {
	return time.Duration(c.BoltTimeout) * time.Second
}
