package config

import (
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"
)

type Configuration struct {
	Server   ServerConfig   `json:"server"`
	Database DatabaseConfig `json:"database"`
	Batch    BatchConfig    `json:"batch"`
	Advanced AdvancedConfig `json:"advanced"`
}

var (
	config     *Configuration
	configOnce sync.Once
)

func NewDefaultConfig() *Configuration {
	return &Configuration{
		Server:   NewDefaultServerConfig(),
		Database: NewDefaultDatabaseConfig(),
		Batch:    NewDefaultBatchConfig(),
		Advanced: NewDefaultAdvancedConfig(),
	}
}
func (c *Configuration) Validate() error {
	if err := c.Server.Validate(); err != nil {
		return err
	}
	if err := c.Database.Validate(); err != nil {
		return err
	}
	if err := c.Batch.Validate(); err != nil {
		return err
	}
	if err := c.Advanced.Validate(); err != nil {
		return err
	}
	return nil
}
func LoadConfig(filePath string) *Configuration {
	configOnce.Do(func() {
		config = NewDefaultConfig()
		if filePath == "" {
			return
		}
		if _, err := os.Stat(filePath); err != nil {
			log.Printf("[INFO] Config file %s doesn't exist, creating with defaults", filePath)
			if err := SaveConfig(filePath); err != nil {
				log.Printf("[WARNING] Failed to create default config file: %v", err)
			}
			return
		}
		file, err := os.Open(filePath)
		if err != nil {
			log.Printf("[WARNING] Could not open config file: %v", err)
			return
		}
		defer file.Close()
		decoder := json.NewDecoder(file)
		if err := decoder.Decode(config); err != nil {
			log.Printf("[WARNING] Could not decode config file: %v", err)
			return
		}
		if err := config.Validate(); err != nil {
			log.Printf("[WARNING] Invalid configuration: %v", err)
			config = NewDefaultConfig()
			return
		}
		log.Printf("[INFO] Configuration loaded from %s", filePath)
	})
	return config
}
func GetConfig() *Configuration {
	if config == nil {
		return LoadConfig("")
	}
	return config
}
func SaveConfig(filePath string) error {
	if config == nil {
		return ErrConfigFileWrite
	}
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(config)
}
func (c *Configuration) GetBatchFlushInterval() time.Duration {
	return time.Duration(c.Batch.FlushInterval) * time.Millisecond
}
func (c *Configuration) GetBoltTimeout() time.Duration {
	return time.Duration(c.Database.BoltTimeout) * time.Second
}
func (c *Configuration) GetCleanupInterval() time.Duration {
	return time.Duration(c.Advanced.CleanupInterval) * time.Minute
}
func (c *Configuration) GetInactivityThreshold() time.Duration {
	return time.Duration(c.Advanced.InactivityThreshold) * time.Minute
}
